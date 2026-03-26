"""Every remediation exercised against a mocked AWS account (moto): the fix is applied, it is idempotent, and dry-run touches nothing."""

import json
import os
import sys
from pathlib import Path

import boto3
import pytest
from moto import mock_aws

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "lambda" / "remediate"))
os.environ["AWS_DEFAULT_REGION"] = "ca-central-1"
os.environ["AWS_ACCESS_KEY_ID"] = "testing"
os.environ["AWS_SECRET_ACCESS_KEY"] = "testing"

import handler  # noqa: E402


def config_event(rule, resource, compliance="NON_COMPLIANT"):
    return {
        "source": "aws.config",
        "detail-type": "Config Rules Compliance Change",
        "detail": {
            "configRuleName": rule,
            "resourceId": resource,
            "newEvaluationResult": {"complianceType": compliance},
        },
    }


@pytest.fixture(autouse=True)
def aws():
    with mock_aws():
        handler.DRY_RUN = False
        handler.TOPIC_ARN = boto3.client("sns").create_topic(Name="alerts")["TopicArn"]
        yield


def public_access_blocked(bucket):
    cfg = boto3.client("s3").get_public_access_block(Bucket=bucket)[
        "PublicAccessBlockConfiguration"
    ]
    return all(cfg.values())


def test_public_bucket_gets_public_access_block():
    boto3.client("s3").create_bucket(
        Bucket="leaky", CreateBucketConfiguration={"LocationConstraint": "ca-central-1"}
    )
    r = handler.handler(config_event("s3-bucket-public-read-prohibited", "leaky"))
    assert r["result"] == "blocked" and public_access_blocked("leaky")
    assert (
        handler.handler(config_event("s3-bucket-public-read-prohibited", "leaky"))[
            "result"
        ]
        == "already_blocked"
    )


def test_compliant_evaluation_is_ignored():
    assert handler.handler(
        config_event("s3-bucket-public-read-prohibited", "x", "COMPLIANT")
    ) == {"skipped": "compliant"}


def make_sg(rules):
    ec2 = boto3.client("ec2")
    vpc = ec2.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]["VpcId"]
    gid = ec2.create_security_group(GroupName="web", Description="t", VpcId=vpc)[
        "GroupId"
    ]
    ec2.authorize_security_group_ingress(GroupId=gid, IpPermissions=rules)
    return ec2, gid


def test_world_open_ssh_is_revoked_but_https_kept():
    ec2, gid = make_sg(
        [
            {
                "IpProtocol": "tcp",
                "FromPort": 22,
                "ToPort": 22,
                "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
            },
            {
                "IpProtocol": "tcp",
                "FromPort": 443,
                "ToPort": 443,
                "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
            },
            {
                "IpProtocol": "tcp",
                "FromPort": 22,
                "ToPort": 22,
                "IpRanges": [{"CidrIp": "10.0.0.0/8"}],
            },
        ]
    )
    r = handler.handler(
        {
            "source": "aws.ec2",
            "detail": {
                "eventName": "AuthorizeSecurityGroupIngress",
                "requestParameters": {"groupId": gid},
            },
        }
    )
    assert r["result"] == "revoked"
    perms = ec2.describe_security_groups(GroupIds=[gid])["SecurityGroups"][0][
        "IpPermissions"
    ]
    remaining = {(p["FromPort"], r["CidrIp"]) for p in perms for r in p["IpRanges"]}
    assert remaining == {(443, "0.0.0.0/0"), (22, "10.0.0.0/8")}
    assert (
        handler.handler(config_event("restricted-ssh", gid))["result"]
        == "nothing_to_revoke"
    )


def test_all_traffic_from_anywhere_is_revoked():
    ec2, gid = make_sg([{"IpProtocol": "-1", "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}])
    assert (
        handler.handler(config_event("restricted-common-ports", gid))["result"]
        == "revoked"
    )
    assert (
        ec2.describe_security_groups(GroupIds=[gid])["SecurityGroups"][0][
            "IpPermissions"
        ]
        == []
    )


def test_guardduty_credential_compromise_disables_keys():
    iam = boto3.client("iam")
    iam.create_user(UserName="alice")
    key = iam.create_access_key(UserName="alice")["AccessKey"]["AccessKeyId"]
    ev = {
        "source": "aws.guardduty",
        "detail": {
            "type": "UnauthorizedAccess:IAMUser/MaliciousIPCaller",
            "severity": 8,
            "resource": {"accessKeyDetails": {"userName": "alice"}},
        },
    }
    assert handler.handler(ev)["result"] == "disabled"
    assert (
        iam.list_access_keys(UserName="alice")["AccessKeyMetadata"][0]["Status"]
        == "Inactive"
    )
    assert key


def test_low_severity_guardduty_is_alert_only():
    ev = {
        "source": "aws.guardduty",
        "detail": {
            "type": "Recon:EC2/PortProbeUnprotectedPort",
            "severity": 2,
            "id": "f1",
        },
    }
    assert handler.handler(ev)["action"] == "alert_only"


def test_root_login_is_never_auto_remediated():
    ev = {
        "source": "aws.signin",
        "detail": {"userIdentity": {"type": "Root"}, "sourceIPAddress": "1.2.3.4"},
    }
    r = handler.handler(ev)
    assert r["action"] == "alert_only" and r["result"] == "page on-call"


def test_dry_run_changes_nothing():
    handler.DRY_RUN = True
    boto3.client("s3").create_bucket(
        Bucket="dry", CreateBucketConfiguration={"LocationConstraint": "ca-central-1"}
    )
    r = handler.handler(config_event("s3-bucket-public-write-prohibited", "dry"))
    assert r["dry_run"] is True and r["result"] == "blocked"
    with pytest.raises(Exception):
        boto3.client("s3").get_public_access_block(Bucket="dry")


def test_every_action_is_published_to_sns(monkeypatch):
    published = []
    monkeypatch.setattr(
        handler,
        "notify",
        lambda a, r, d: published.append((a, r)) or {"action": a, "resource": r, **d},
    )
    boto3.client("s3").create_bucket(
        Bucket="bucket-one",
        CreateBucketConfiguration={"LocationConstraint": "ca-central-1"},
    )
    handler.handler(config_event("s3-bucket-public-read-prohibited", "bucket-one"))
    assert published == [("s3_public_access_block", "bucket-one")]
    assert json.dumps(published)
