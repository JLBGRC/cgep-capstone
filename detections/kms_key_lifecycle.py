"""Replay helper for the KMS key-lifecycle EventBridge pattern.

Maps to HIPAA 164.312(b) / 164.308(a)(1). Keep this in lockstep with
terraform/monitoring.tf event_pattern.
"""

EVENT_NAMES = frozenset({"DisableKey", "ScheduleKeyDeletion"})


def matches(event: dict, key_arns: set[str]) -> bool:
    if event.get("source") != "aws.kms":
        return False
    if event.get("detail-type") != "AWS API Call via CloudTrail":
        return False
    detail = event.get("detail") or {}
    if detail.get("eventName") not in EVENT_NAMES:
        return False
    seen = {r.get("ARN") for r in (detail.get("resources") or []) if r.get("ARN")}
    return bool(seen & key_arns)
