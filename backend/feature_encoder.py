"""
feature_encoder.py — Encodes AWS CloudTrail events into 538-dim feature vectors.

Reads native CloudTrail JSON fields directly:
  eventSource + eventName  -> API action
  sourceIPAddress          -> source IP feature
  userAgent                -> call origin feature
  eventTime                -> hour-of-day sin/cos

Service name normalisation:
  CloudWatch is logged as monitoring.amazonaws.com in real CloudTrail logs.
  We normalise monitoring -> cloudwatch so real logs and ROLE_ACTIONS match.
  This ensures the velocity baseline correctly counts real cloudwatch events.
"""

import math
import numpy as np
from datetime import datetime

N_ACTIONS        = 500
N_RESOURCE_TYPES = 70

# AWS service name aliases — maps real CloudTrail eventSource to
# the canonical name used in ROLE_ACTIONS and our simulation
SERVICE_ALIASES = {
    "monitoring":          "cloudwatch",   # CloudWatch uses monitoring.amazonaws.com
    "s3control":           "s3",
    "elasticloadbalancing": "elbv2",
    "es":                  "opensearch",
    "email":               "ses",
    "streams.dynamodb":    "dynamodb",
}

RESOURCE_TYPE_MAP = {
    "ec2": "EC2Instance", "s3": "S3Bucket", "iam": "IAMRole",
    "sts": "STSRole", "lambda": "LambdaFunction",
    "secretsmanager": "Secret", "ssm": "SSMParameter",
    "cloudtrail": "Trail", "guardduty": "Detector", "kms": "KMSKey",
    "rds": "RDSInstance", "dynamodb": "DynamoDBTable",
    "eks": "EKSCluster", "ecs": "ECSTask",
    "cloudformation": "CloudFormationStack", "athena": "AthenaQuery",
    "glue": "GlueTable", "redshift": "RedshiftCluster",
    "codecommit": "CodeCommitRepo", "cost-explorer": "CostReport",
    "config": "ConfigRule", "securityhub": "SecurityHubFinding",
    "workdocs": "WorkDocsFolder", "cognito-idp": "CognitoUserPool",
    "quicksight": "QuickSightDashboard", "budgets": "Budget",
    "ecr": "ECRRepository",
    "cloudwatch": "CloudWatchMetric",   # normalised from monitoring
    "monitoring":  "CloudWatchMetric",  # also accept raw monitoring
}

HQ_IP_PREFIX = ("10.0.", "106.192.", "44.204.")


def _hash_slot(name: str, n: int) -> int:
    h = 0
    for ch in name:
        h = (h * 31 + ord(ch)) % n
    return h


def _parse_hour(event_time: str) -> int:
    try:
        return datetime.fromisoformat(event_time.replace("Z", "+00:00")).hour
    except Exception:
        return 12


# ── Field extraction helpers ──────────────────────────────────────────────────

def get_action(event: dict) -> str:
    """
    Extract API action from CloudTrail or legacy format.
    Normalises AWS service aliases so real logs match ROLE_ACTIONS.
    e.g. monitoring:ListMetrics -> cloudwatch:ListMetrics
    """
    if "eventSource" in event and "eventName" in event:
        svc = event["eventSource"].replace(".amazonaws.com", "").split(".")[0]
        svc = SERVICE_ALIASES.get(svc, svc)   # normalise aliases
        return f"{svc}:{event['eventName']}"
    return event.get("action", "")


def get_resource_type(event: dict) -> str:
    if "eventSource" in event:
        svc = event["eventSource"].replace(".amazonaws.com", "").split(".")[0]
        svc = SERVICE_ALIASES.get(svc, svc)
        return RESOURCE_TYPE_MAP.get(svc, "AWSResource")
    return event.get("resource_type", "AWSResource")


def get_source_ip(event: dict) -> str:
    return event.get("sourceIPAddress", event.get("source_ip", ""))


def get_user_agent(event: dict) -> str:
    return event.get("userAgent", event.get("user_agent", ""))


def get_hour(event: dict) -> int:
    if "eventTime" in event:
        return _parse_hour(event["eventTime"])
    return int(event.get("hour_of_day", 12))


def get_bytes(event: dict) -> float:
    return float(event.get("bytes_transferred", 0))


def get_user_id(event: dict) -> str:
    if "userIdentity" in event:
        uid = event["userIdentity"]
        return uid.get("userName") or uid.get("principalId", "unknown")
    return event.get("user_id", "unknown")


# ── Encoder ───────────────────────────────────────────────────────────────────

class FeatureEncoder:
    def __init__(self):
        self.known_actions:   set[str] = set()
        self.known_resources: set[str] = set()
        self._fitted = False

    def fit(self, events: list[dict]) -> "FeatureEncoder":
        for e in events:
            self.known_actions.add(get_action(e))
            self.known_resources.add(get_resource_type(e))
        self._fitted = True
        return self

    def encode(self, event: dict) -> np.ndarray:
        vec = np.zeros(
            N_ACTIONS + N_RESOURCE_TYPES + 1 + 1 + 1 + 2 + 1,
            dtype=np.float32
        )
        offset = 0

        # 1. Action one-hot (500-dim)
        vec[offset + _hash_slot(get_action(event), N_ACTIONS)] = 1.0
        offset += N_ACTIONS

        # 2. Resource type one-hot (70-dim)
        vec[offset + _hash_slot(get_resource_type(event), N_RESOURCE_TYPES)] = 1.0
        offset += N_RESOURCE_TYPES

        # 3. Call origin: Console=1, CLI/SDK=0
        vec[offset] = 1.0 if "console" in get_user_agent(event).lower() else 0.0
        offset += 1

        # 4. Bytes transferred (log-scaled)
        vec[offset] = math.log1p(get_bytes(event)) / 15.0
        offset += 1

        # 5. External IP flag
        vec[offset] = 0.0 if get_source_ip(event).startswith(HQ_IP_PREFIX) else 1.0
        offset += 1

        # 6. Hour of day (sin/cos encoding)
        h = get_hour(event)
        vec[offset]     = math.sin(2 * math.pi * h / 24)
        vec[offset + 1] = math.cos(2 * math.pi * h / 24)
        offset += 2

        # 7. Session age placeholder
        vec[offset] = 0.0

        return vec

    def novelty_flags(self, event: dict) -> tuple[bool, bool]:
        if not self._fitted:
            return False, False
        return (
            get_action(event)        not in self.known_actions,
            get_resource_type(event) not in self.known_resources,
        )
