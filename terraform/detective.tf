# ---------- The detective controls that generate the events ----------

data "aws_caller_identity" "me" {}

resource "aws_s3_bucket" "trail" {
  bucket        = "cloudtrail-${data.aws_caller_identity.me.account_id}-${var.region}"
  force_destroy = true
}

resource "aws_s3_bucket_public_access_block" "trail" {
  bucket                  = aws_s3_bucket.trail.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

data "aws_iam_policy_document" "trail_bucket" {
  statement {
    sid       = "AWSCloudTrailAclCheck"
    actions   = ["s3:GetBucketAcl"]
    resources = [aws_s3_bucket.trail.arn]
    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }
  }
  statement {
    sid       = "AWSCloudTrailWrite"
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.trail.arn}/AWSLogs/${data.aws_caller_identity.me.account_id}/*"]
    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "s3:x-amz-acl"
      values   = ["bucket-owner-full-control"]
    }
  }
}

resource "aws_s3_bucket_policy" "trail" {
  bucket = aws_s3_bucket.trail.id
  policy = data.aws_iam_policy_document.trail_bucket.json
}

resource "aws_cloudtrail" "main" {
  name                          = "org-trail"
  s3_bucket_name                = aws_s3_bucket.trail.id
  include_global_service_events = true
  is_multi_region_trail         = true
  enable_log_file_validation    = true
  depends_on                    = [aws_s3_bucket_policy.trail]
}

resource "aws_guardduty_detector" "main" {
  enable = true
}

# AWS Config: recorder + the managed rules whose NON_COMPLIANT events the Lambda acts on
resource "aws_iam_role" "config" {
  name               = "config-recorder"
  assume_role_policy = jsonencode({ Version = "2012-10-17", Statement = [{ Effect = "Allow", Principal = { Service = "config.amazonaws.com" }, Action = "sts:AssumeRole" }] })
}

resource "aws_iam_role_policy_attachment" "config" {
  role       = aws_iam_role.config.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWS_ConfigRole"
}

resource "aws_s3_bucket" "config" {
  bucket        = "config-${data.aws_caller_identity.me.account_id}-${var.region}"
  force_destroy = true
}

resource "aws_iam_role_policy" "config_bucket" {
  role = aws_iam_role.config.id
  policy = jsonencode({
    Version = "2012-10-17", Statement = [
      { Effect = "Allow", Action = ["s3:PutObject"], Resource = "${aws_s3_bucket.config.arn}/*", Condition = { StringLike = { "s3:x-amz-acl" = "bucket-owner-full-control" } } },
      { Effect = "Allow", Action = ["s3:GetBucketAcl"], Resource = aws_s3_bucket.config.arn }
    ]
  })
}

resource "aws_config_configuration_recorder" "main" {
  name     = "default"
  role_arn = aws_iam_role.config.arn
  recording_group { all_supported = true }
}

resource "aws_config_delivery_channel" "main" {
  name           = "default"
  s3_bucket_name = aws_s3_bucket.config.id
  depends_on     = [aws_config_configuration_recorder.main]
}

resource "aws_config_configuration_recorder_status" "main" {
  name       = aws_config_configuration_recorder.main.name
  is_enabled = true
  depends_on = [aws_config_delivery_channel.main]
}

locals {
  config_rules = {
    "s3-bucket-public-read-prohibited"  = "S3_BUCKET_PUBLIC_READ_PROHIBITED"
    "s3-bucket-public-write-prohibited" = "S3_BUCKET_PUBLIC_WRITE_PROHIBITED"
    "restricted-ssh"                    = "INCOMING_SSH_DISABLED"
    "restricted-common-ports"           = "RESTRICTED_INCOMING_TRAFFIC"
    "root-account-mfa-enabled"          = "ROOT_ACCOUNT_MFA_ENABLED"
    "iam-user-mfa-enabled"              = "IAM_USER_MFA_ENABLED"
  }
}

resource "aws_config_config_rule" "managed" {
  for_each = local.config_rules
  name     = each.key
  source {
    owner             = "AWS"
    source_identifier = each.value
  }
  depends_on = [aws_config_configuration_recorder_status.main]
}
