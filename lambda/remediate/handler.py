"""Auto-remediation for a small set of high-confidence, low-blast-radius findings.

Invoked by EventBridge. Each rule maps an event to one remediation function. Every action is logged
as structured JSON and published to an SNS topic so a human sees what was changed and why.

Design rules:
  * Only remediate what is unambiguous. A public S3 bucket and 0.0.0.0/0 on SSH/RDP are never intended
    in this account. Anything with judgement involved (odd IAM policy, unusual API call) is alert-only.
  * Never delete. Revoke, block, disable. Everything here is reversible in one console click.
  * Idempotent. Re-running on an already-fixed resource is a no-op, not an error.
"""

from __future__ import annotations

import json
import logging
import os
from datetime import UTC, datetime

import boto3

log = logging.getLogger()
log.setLevel(logging.INFO)

TOPIC_ARN = os.getenv("ALERT_TOPIC_ARN", "")
DRY_RUN = os.getenv("DRY_RUN", "false").lower() == "true"
RISKY_PORTS = {22, 3389, 3306, 5432, 1433, 27017, 6379}
ANYWHERE = {"0.0.0.0/0", "::/0"}


def notify(action: str, resource: str, detail: dict) -> dict:
    record = {
        "time": datetime.now(UTC).isoformat(timespec="seconds"),
        "action": action,
        "resource": resource,
        "dry_run": DRY_RUN,
        **detail,
    }
    log.info(json.dumps(record))
    if TOPIC_ARN:
        boto3.client("sns").publish(
            TopicArn=TOPIC_ARN,
            Subject=f"[auto-remediation] {action}: {resource}"[:100],
            Message=json.dumps(record, indent=2),
        )
    return record


# ---------------------------------------------------------------- S3: public bucket


def remediate_public_bucket(bucket: str) -> dict:
    s3 = boto3.client("s3")
    try:
        cfg = s3.get_public_access_block(Bucket=bucket)[
            "PublicAccessBlockConfiguration"
        ]
        already = all(
            cfg.get(k)
            for k in (
                "BlockPublicAcls",
                "IgnorePublicAcls",
                "BlockPublicPolicy",
                "RestrictPublicBuckets",
            )
        )
    except s3.exceptions.ClientError:
        already = False
    if already:
        return notify("s3_public_access_block", bucket, {"result": "already_blocked"})
    if not DRY_RUN:
        s3.put_public_access_block(
            Bucket=bucket,
            PublicAccessBlockConfiguration={
                "BlockPublicAcls": True,
                "IgnorePublicAcls": True,
                "BlockPublicPolicy": True,
                "RestrictPublicBuckets": True,
            },
        )
    return notify("s3_public_access_block", bucket, {"result": "blocked"})


# ---------------------------------------------------------------- EC2: security group open to the world


def _risky(perm: dict) -> bool:
    lo, hi = perm.get("FromPort"), perm.get("ToPort")
    open_world = any(
        r.get("CidrIp") in ANYWHERE for r in perm.get("IpRanges", [])
    ) or any(r.get("CidrIpv6") in ANYWHERE for r in perm.get("Ipv6Ranges", []))
    if not open_world:
        return False
    if perm.get("IpProtocol") == "-1":
        return True
    if lo is None or hi is None:
        return False
    return any(lo <= p <= hi for p in RISKY_PORTS)


def remediate_open_security_group(group_id: str) -> dict:
    ec2 = boto3.client("ec2")
    sg = ec2.describe_security_groups(GroupIds=[group_id])["SecurityGroups"][0]
    revoke = []
    for perm in sg.get("IpPermissions", []):
        if not _risky(perm):
            continue
        trimmed = {
            k: v for k, v in perm.items() if k in ("IpProtocol", "FromPort", "ToPort")
        }
        v4 = [r for r in perm.get("IpRanges", []) if r.get("CidrIp") in ANYWHERE]
        v6 = [r for r in perm.get("Ipv6Ranges", []) if r.get("CidrIpv6") in ANYWHERE]
        if v4:
            revoke.append(
                {**trimmed, "IpRanges": [{"CidrIp": r["CidrIp"]} for r in v4]}
            )
        if v6:
            revoke.append(
                {**trimmed, "Ipv6Ranges": [{"CidrIpv6": r["CidrIpv6"]} for r in v6]}
            )
    if not revoke:
        return notify(
            "sg_revoke_world_ingress", group_id, {"result": "nothing_to_revoke"}
        )
    if not DRY_RUN:
        ec2.revoke_security_group_ingress(GroupId=group_id, IpPermissions=revoke)
    return notify(
        "sg_revoke_world_ingress", group_id, {"result": "revoked", "rules": revoke}
    )


# ---------------------------------------------------------------- IAM: access key for a user flagged by GuardDuty


def disable_user_access_keys(user: str) -> dict:
    iam = boto3.client("iam")
    keys = iam.list_access_keys(UserName=user)["AccessKeyMetadata"]
    active = [k["AccessKeyId"] for k in keys if k["Status"] == "Active"]
    if not active:
        return notify("iam_disable_access_keys", user, {"result": "no_active_keys"})
    if not DRY_RUN:
        for key_id in active:
            iam.update_access_key(UserName=user, AccessKeyId=key_id, Status="Inactive")
    return notify(
        "iam_disable_access_keys", user, {"result": "disabled", "keys": active}
    )


# ---------------------------------------------------------------- event routing


def handler(event: dict, context=None) -> dict:
    """EventBridge entry point. Understands three event shapes."""
    detail = event.get("detail", {})
    source = event.get("source")

    # 1. AWS Config rule became NON_COMPLIANT
    if (
        source == "aws.config"
        and event.get("detail-type") == "Config Rules Compliance Change"
    ):
        if (
            detail.get("newEvaluationResult", {}).get("complianceType")
            != "NON_COMPLIANT"
        ):
            return {"skipped": "compliant"}
        rule = detail.get("configRuleName", "")
        rid = detail.get("resourceId", "")
        if rule.startswith("s3-bucket-public"):
            return remediate_public_bucket(rid)
        if rule.startswith("restricted-ssh") or rule.startswith(
            "restricted-common-ports"
        ):
            return remediate_open_security_group(rid)
        return notify(
            "alert_only", rid, {"rule": rule, "result": "no remediation mapped"}
        )

    # 2. CloudTrail API call via EventBridge: someone just opened a security group
    if (
        source == "aws.ec2"
        and detail.get("eventName") == "AuthorizeSecurityGroupIngress"
    ):
        gid = detail["requestParameters"]["groupId"]
        return remediate_open_security_group(gid)

    # 3. GuardDuty finding
    if source == "aws.guardduty":
        ftype = detail.get("type", "")
        sev = float(detail.get("severity", 0))
        if ftype.startswith("UnauthorizedAccess:IAMUser") and sev >= 7:
            user = detail["resource"]["accessKeyDetails"]["userName"]
            return disable_user_access_keys(user)
        return notify(
            "alert_only",
            detail.get("id", ""),
            {"finding": ftype, "severity": sev, "result": "human review"},
        )

    # CloudTrail root login: alert only, never lock root out automatically
    if source == "aws.signin" and detail.get("userIdentity", {}).get("type") == "Root":
        return notify(
            "alert_only",
            "root",
            {
                "event": "ConsoleLogin",
                "sourceIP": detail.get("sourceIPAddress"),
                "result": "page on-call",
            },
        )

    return {"skipped": f"unhandled source {source}"}
