"""
cloudtrail_loader.py — Parses real AWS CloudTrail JSON logs into the
pipeline's internal event format.

CloudTrail log format reference:
https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-log-file-examples.html

Field mapping:
  eventSource + eventName  → action  (e.g. "ec2:StartInstances")
  userIdentity.userName    → user_id
  sourceIPAddress          → source_ip
  userAgent                → user_agent
  eventTime                → timestamp
  eventID                  → event_id
  (no bytes field in CT)   → bytes_transferred = 0

Usage:
  events = load_cloudtrail_file("path/to/cloudtrail.json")
  events = load_cloudtrail_records(list_of_records)
"""

import json
import os
from datetime import datetime
from typing import Optional


RESOURCE_TYPE_MAP = {
    "ec2":            "EC2Instance",
    "s3":             "S3Bucket",
    "iam":            "IAMRole",
    "sts":            "STSRole",
    "lambda":         "LambdaFunction",
    "secretsmanager": "Secret",
    "ssm":            "SSMParameter",
    "cloudtrail":     "Trail",
    "guardduty":      "Detector",
    "kms":            "KMSKey",
    "rds":            "RDSInstance",
    "dynamodb":       "DynamoDBTable",
    "eks":            "EKSCluster",
    "ecs":            "ECSTask",
    "cloudformation": "CloudFormationStack",
    "athena":         "AthenaQuery",
    "glue":           "GlueTable",
    "redshift":       "RedshiftCluster",
    "codecommit":     "CodeCommitRepo",
    "cost-explorer":  "CostReport",
    "config":         "ConfigRule",
    "securityhub":    "SecurityHubFinding",
    "workdocs":       "WorkDocsFolder",
    "cognito-idp":    "CognitoUserPool",
    "quicksight":     "QuickSightDashboard",
    "budgets":        "Budget",
    "ecr":            "ECRRepository",
    "cloudwatch":     "CloudWatchMetric",
}


def _parse_hour(event_time: str) -> int:
    """Extract hour from ISO timestamp like '2023-07-19T21:17:28Z'."""
    try:
        dt = datetime.fromisoformat(event_time.replace("Z", "+00:00"))
        return dt.hour
    except Exception:
        return 12


def _infer_resource_type(event_source: str) -> str:
    """Map AWS service name to resource type."""
    svc = event_source.replace(".amazonaws.com", "").split(".")[0]
    return RESOURCE_TYPE_MAP.get(svc, "AWSResource")


def _parse_record(record: dict, user_id_override: Optional[str] = None) -> Optional[dict]:
    """
    Convert one CloudTrail record dict to pipeline event format.
    Returns None if the record is missing essential fields.
    """
    event_source = record.get("eventSource", "")
    event_name   = record.get("eventName", "")
    if not event_source or not event_name:
        return None

    # Build action string: "service:ActionName"
    svc    = event_source.replace(".amazonaws.com", "").split(".")[0]
    action = f"{svc}:{event_name}"

    # User identity
    uid_raw = record.get("userIdentity", {})
    user_id = (
        user_id_override
        or uid_raw.get("userName")
        or uid_raw.get("principalId", "unknown")
    )

    # Timestamp and hour
    event_time = record.get("eventTime", "")
    hour = _parse_hour(event_time)

    # Source IP — if console, treat as internal
    source_ip  = record.get("sourceIPAddress", "0.0.0.0")
    user_agent = record.get("userAgent", "")

    # CloudTrail does not log bytes transferred directly
    bytes_transferred = 0.0

    return {
        "event_id":          record.get("eventID", f"ct_{hash(str(record))%1000000:06d}"),
        "user_id":           user_id,
        "role":              "unknown",   # caller must set role based on user_id mapping
        "action":            action,
        "resource_type":     _infer_resource_type(event_source),
        "source_ip":         source_ip,
        "user_agent":        user_agent,
        "bytes_transferred": bytes_transferred,
        "timestamp":         event_time,
        "hour_of_day":       hour,
        "is_attack":         False,
        "attack_scenario":   None,
    }


def load_cloudtrail_records(
    records: list[dict],
    user_id_override: Optional[str] = None,
) -> list[dict]:
    """
    Parse a list of raw CloudTrail record dicts.
    Returns a list of pipeline-format event dicts.
    """
    out = []
    for r in records:
        parsed = _parse_record(r, user_id_override)
        if parsed:
            out.append(parsed)
    return out


def load_cloudtrail_file(
    path: str,
    user_id_override: Optional[str] = None,
) -> list[dict]:
    """
    Load a CloudTrail JSON file (may be {"Records":[...]} or a list).
    Handles both raw JSON and gzipped JSON (.json.gz).
    """
    if not os.path.exists(path):
        raise FileNotFoundError(f"CloudTrail file not found: {path}")

    if path.endswith(".gz"):
        import gzip
        with gzip.open(path, "rt", encoding="utf-8") as f:
            data = json.load(f)
    else:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)

    if isinstance(data, dict) and "Records" in data:
        records = data["Records"]
    elif isinstance(data, list):
        records = data
    else:
        raise ValueError("Unexpected CloudTrail JSON structure")

    return load_cloudtrail_records(records, user_id_override)


def load_cloudtrail_directory(
    directory: str,
    user_id_override: Optional[str] = None,
) -> list[dict]:
    """
    Recursively load all .json and .json.gz files from a directory.
    Useful for loading a full CloudTrail S3 export.
    """
    all_events = []
    for root, _, files in os.walk(directory):
        for fname in sorted(files):
            if fname.endswith(".json") or fname.endswith(".json.gz"):
                fpath = os.path.join(root, fname)
                try:
                    events = load_cloudtrail_file(fpath, user_id_override)
                    all_events.extend(events)
                except Exception as e:
                    print(f"  Warning: could not load {fpath}: {e}")
    return all_events
