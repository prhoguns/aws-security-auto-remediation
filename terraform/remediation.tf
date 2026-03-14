# ---------- The responsive control: EventBridge → Lambda → fix + SNS ----------

resource "aws_sns_topic" "alerts" {
  name = "security-auto-remediation"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

data "archive_file" "lambda" {
  type        = "zip"
  source_dir  = "${path.module}/../lambda/remediate"
  output_path = "${path.module}/.build/remediate.zip"
}

# Least privilege: exactly the calls handler.py makes, nothing else.
data "aws_iam_policy_document" "lambda" {
  statement {
    sid       = "S3Block"
    actions   = ["s3:GetBucketPublicAccessBlock", "s3:PutBucketPublicAccessBlock"]
    resources = ["arn:aws:s3:::*"]
  }
  statement {
    sid       = "SGRevoke"
    actions   = ["ec2:DescribeSecurityGroups", "ec2:RevokeSecurityGroupIngress"]
    resources = ["*"]
  }
  statement {
    sid       = "IAMDisableKeys"
    actions   = ["iam:ListAccessKeys", "iam:UpdateAccessKey"]
    resources = ["arn:aws:iam::${data.aws_caller_identity.me.account_id}:user/*"]
  }
  statement {
    sid       = "Notify"
    actions   = ["sns:Publish"]
    resources = [aws_sns_topic.alerts.arn]
  }
  statement {
    sid       = "Logs"
    actions   = ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"]
    resources = ["arn:aws:logs:${var.region}:${data.aws_caller_identity.me.account_id}:*"]
  }
}

resource "aws_iam_role" "lambda" {
  name               = "security-auto-remediation"
  assume_role_policy = jsonencode({ Version = "2012-10-17", Statement = [{ Effect = "Allow", Principal = { Service = "lambda.amazonaws.com" }, Action = "sts:AssumeRole" }] })
}

resource "aws_iam_role_policy" "lambda" {
  role   = aws_iam_role.lambda.id
  policy = data.aws_iam_policy_document.lambda.json
}

resource "aws_lambda_function" "remediate" {
  function_name    = "security-auto-remediation"
  role             = aws_iam_role.lambda.arn
  handler          = "handler.handler"
  runtime          = "python3.12"
  timeout          = 30
  filename         = data.archive_file.lambda.output_path
  source_code_hash = data.archive_file.lambda.output_base64sha256
  environment {
    variables = {
      ALERT_TOPIC_ARN = aws_sns_topic.alerts.arn
      DRY_RUN         = tostring(var.dry_run)
    }
  }
}

resource "aws_cloudwatch_log_group" "lambda" {
  name              = "/aws/lambda/${aws_lambda_function.remediate.function_name}"
  retention_in_days = 90
}

# ---------- Event sources ----------

locals {
  event_rules = {
    config-noncompliant = {
      description = "AWS Config rule evaluated NON_COMPLIANT"
      pattern = jsonencode({
        source        = ["aws.config"]
        "detail-type" = ["Config Rules Compliance Change"]
        detail        = { newEvaluationResult = { complianceType = ["NON_COMPLIANT"] } }
      })
    }
    sg-ingress-authorized = {
      description = "Security group ingress rule added (CloudTrail via EventBridge)"
      pattern = jsonencode({
        source        = ["aws.ec2"]
        "detail-type" = ["AWS API Call via CloudTrail"]
        detail        = { eventName = ["AuthorizeSecurityGroupIngress"] }
      })
    }
    guardduty-finding = {
      description = "GuardDuty finding of severity >= 4"
      pattern = jsonencode({
        source        = ["aws.guardduty"]
        "detail-type" = ["GuardDuty Finding"]
        detail        = { severity = [{ numeric = [">=", 4] }] }
      })
    }
    root-console-login = {
      description = "Root account console login"
      pattern = jsonencode({
        source        = ["aws.signin"]
        "detail-type" = ["AWS Console Sign In via CloudTrail"]
        detail        = { userIdentity = { type = ["Root"] } }
      })
    }
  }
}

resource "aws_cloudwatch_event_rule" "src" {
  for_each      = local.event_rules
  name          = "remediate-${each.key}"
  description   = each.value.description
  event_pattern = each.value.pattern
}

resource "aws_cloudwatch_event_target" "lambda" {
  for_each = aws_cloudwatch_event_rule.src
  rule     = each.value.name
  arn      = aws_lambda_function.remediate.arn
}

resource "aws_lambda_permission" "events" {
  for_each      = aws_cloudwatch_event_rule.src
  statement_id  = "AllowEventBridge-${each.key}"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.remediate.function_name
  principal     = "events.amazonaws.com"
  source_arn    = each.value.arn
}

output "alert_topic_arn" { value = aws_sns_topic.alerts.arn }
output "lambda_function" { value = aws_lambda_function.remediate.function_name }
output "cloudtrail_bucket" { value = aws_s3_bucket.trail.id }
