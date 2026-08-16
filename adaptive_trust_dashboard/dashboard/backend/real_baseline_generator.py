"""
real_baseline_generator.py — Generates realistic CloudTrail baseline events
in authentic AWS format for each role, based on AWS CloudTrail documentation
examples (https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-log-file-examples.html)

These events are used to train the Isolation Forest on real CloudTrail
log structure rather than purely synthetic data. Attack events remain
synthetic (MITRE ATT&CK injections).

Usage:
  from real_baseline_generator import generate_real_baseline
  events = generate_real_baseline(user_id="user_001", role="developer", n_days=14)
"""

import random
import math
from datetime import datetime, timedelta

# Real CloudTrail event templates per role
# Based on AWS documentation examples and real API call patterns

ROLE_TEMPLATES = {
    "developer": [
        {"eventSource": "codecommit.amazonaws.com", "eventName": "GitPull",          "userAgent": "git/2.39.0",                     "sourceIPAddress": "10.0.1.{}", "readOnly": True},
        {"eventSource": "codecommit.amazonaws.com", "eventName": "GitPush",          "userAgent": "git/2.39.0",                     "sourceIPAddress": "10.0.1.{}", "readOnly": False},
        {"eventSource": "s3.amazonaws.com",         "eventName": "GetObject",        "userAgent": "aws-cli/2.13.5 Python/3.11.4",   "sourceIPAddress": "10.0.1.{}", "readOnly": True},
        {"eventSource": "ec2.amazonaws.com",        "eventName": "DescribeInstances","userAgent": "aws-cli/2.13.5 Python/3.11.4",   "sourceIPAddress": "10.0.1.{}", "readOnly": True},
        {"eventSource": "lambda.amazonaws.com",     "eventName": "InvokeFunction",   "userAgent": "aws-sdk-java/1.12.261",           "sourceIPAddress": "10.0.2.{}", "readOnly": False},
        {"eventSource": "cloudwatch.amazonaws.com", "eventName": "GetMetricData",    "userAgent": "aws-cli/2.13.5 Python/3.11.4",   "sourceIPAddress": "10.0.1.{}", "readOnly": True},
        {"eventSource": "ecr.amazonaws.com",        "eventName": "GetAuthorizationToken","userAgent": "docker/24.0.5",              "sourceIPAddress": "10.0.1.{}", "readOnly": True},
        {"eventSource": "ssm.amazonaws.com",        "eventName": "GetParameter",     "userAgent": "aws-sdk-python/1.28.0",          "sourceIPAddress": "10.0.1.{}", "readOnly": True},
    ],
    "data_analyst": [
        {"eventSource": "s3.amazonaws.com",         "eventName": "GetObject",        "userAgent": "aws-cli/2.13.5 Python/3.11.4",   "sourceIPAddress": "10.0.3.{}", "readOnly": True},
        {"eventSource": "s3.amazonaws.com",         "eventName": "PutObject",        "userAgent": "aws-cli/2.13.5 Python/3.11.4",   "sourceIPAddress": "10.0.3.{}", "readOnly": False},
        {"eventSource": "athena.amazonaws.com",     "eventName": "StartQueryExecution","userAgent": "aws-sdk-python/1.28.0",        "sourceIPAddress": "10.0.3.{}", "readOnly": False},
        {"eventSource": "glue.amazonaws.com",       "eventName": "GetTable",         "userAgent": "aws-sdk-python/1.28.0",          "sourceIPAddress": "10.0.3.{}", "readOnly": True},
        {"eventSource": "redshift.amazonaws.com",   "eventName": "DescribeClusters", "userAgent": "aws-cli/2.13.5 Python/3.11.4",   "sourceIPAddress": "10.0.3.{}", "readOnly": True},
        {"eventSource": "cloudwatch.amazonaws.com", "eventName": "GetMetricData",    "userAgent": "aws-cli/2.13.5 Python/3.11.4",   "sourceIPAddress": "10.0.3.{}", "readOnly": True},
    ],
    "security_admin": [
        {"eventSource": "iam.amazonaws.com",        "eventName": "ListUsers",        "userAgent": "aws-cli/2.13.5 Python/3.11.4",   "sourceIPAddress": "10.0.4.{}", "readOnly": True},
        {"eventSource": "iam.amazonaws.com",        "eventName": "GetPolicy",        "userAgent": "aws-cli/2.13.5 Python/3.11.4",   "sourceIPAddress": "10.0.4.{}", "readOnly": True},
        {"eventSource": "cloudtrail.amazonaws.com", "eventName": "LookupEvents",     "userAgent": "aws-cli/2.13.5 Python/3.11.4",   "sourceIPAddress": "10.0.4.{}", "readOnly": True},
        {"eventSource": "guardduty.amazonaws.com",  "eventName": "ListFindings",     "userAgent": "aws-cli/2.13.5 Python/3.11.4",   "sourceIPAddress": "10.0.4.{}", "readOnly": True},
        {"eventSource": "securityhub.amazonaws.com","eventName": "GetFindings",      "userAgent": "aws-cli/2.13.5 Python/3.11.4",   "sourceIPAddress": "10.0.4.{}", "readOnly": True},
        {"eventSource": "config.amazonaws.com",     "eventName": "GetComplianceSummaryByConfigRule","userAgent": "aws-cli/2.13.5",  "sourceIPAddress": "10.0.4.{}", "readOnly": True},
        {"eventSource": "sts.amazonaws.com",        "eventName": "GetCallerIdentity","userAgent": "aws-cli/2.13.5 Python/3.11.4",   "sourceIPAddress": "10.0.4.{}", "readOnly": True},
    ],
    "devops": [
        {"eventSource": "ec2.amazonaws.com",        "eventName": "DescribeInstances","userAgent": "aws-cli/2.13.5 Python/3.11.4",   "sourceIPAddress": "10.0.5.{}", "readOnly": True},
        {"eventSource": "ec2.amazonaws.com",        "eventName": "StartInstances",   "userAgent": "aws-cli/2.13.5 Python/3.11.4",   "sourceIPAddress": "10.0.5.{}", "readOnly": False},
        {"eventSource": "ec2.amazonaws.com",        "eventName": "StopInstances",    "userAgent": "aws-cli/2.13.5 Python/3.11.4",   "sourceIPAddress": "10.0.5.{}", "readOnly": False},
        {"eventSource": "ecs.amazonaws.com",        "eventName": "ListTasks",        "userAgent": "aws-sdk-go/1.44.298",            "sourceIPAddress": "10.0.5.{}", "readOnly": True},
        {"eventSource": "eks.amazonaws.com",        "eventName": "DescribeCluster",  "userAgent": "kubectl/v1.27.0",                "sourceIPAddress": "10.0.5.{}", "readOnly": True},
        {"eventSource": "cloudformation.amazonaws.com","eventName": "DescribeStacks","userAgent": "aws-cli/2.13.5 Python/3.11.4",   "sourceIPAddress": "10.0.5.{}", "readOnly": True},
        {"eventSource": "ssm.amazonaws.com",        "eventName": "GetParameter",     "userAgent": "aws-sdk-python/1.28.0",          "sourceIPAddress": "10.0.5.{}", "readOnly": True},
        {"eventSource": "secretsmanager.amazonaws.com","eventName": "GetSecretValue","userAgent": "aws-sdk-python/1.28.0",          "sourceIPAddress": "10.0.5.{}", "readOnly": True},
    ],
    "finance": [
        {"eventSource": "s3.amazonaws.com",         "eventName": "GetObject",        "userAgent": "aws-cli/2.13.5 Python/3.11.4",   "sourceIPAddress": "10.0.6.{}", "readOnly": True},
        {"eventSource": "quicksight.amazonaws.com", "eventName": "DescribeDashboard","userAgent": "Mozilla/5.0 (Windows NT 10.0)",  "sourceIPAddress": "10.0.6.{}", "readOnly": True},
        {"eventSource": "cost-explorer.amazonaws.com","eventName": "GetCostAndUsage","userAgent": "aws-cli/2.13.5 Python/3.11.4",   "sourceIPAddress": "10.0.6.{}", "readOnly": True},
        {"eventSource": "budgets.amazonaws.com",    "eventName": "DescribeBudgets",  "userAgent": "aws-cli/2.13.5 Python/3.11.4",   "sourceIPAddress": "10.0.6.{}", "readOnly": True},
        {"eventSource": "cloudtrail.amazonaws.com", "eventName": "LookupEvents",     "userAgent": "aws-cli/2.13.5 Python/3.11.4",   "sourceIPAddress": "10.0.6.{}", "readOnly": True},
    ],
    "hr": [
        {"eventSource": "s3.amazonaws.com",         "eventName": "GetObject",        "userAgent": "aws-cli/2.13.5 Python/3.11.4",   "sourceIPAddress": "10.0.7.{}", "readOnly": True},
        {"eventSource": "workdocs.amazonaws.com",   "eventName": "DescribeUsers",    "userAgent": "Mozilla/5.0 (Windows NT 10.0)",  "sourceIPAddress": "10.0.7.{}", "readOnly": True},
        {"eventSource": "cognito-idp.amazonaws.com","eventName": "AdminGetUser",     "userAgent": "aws-cli/2.13.5 Python/3.11.4",   "sourceIPAddress": "10.0.7.{}", "readOnly": True},
        {"eventSource": "iam.amazonaws.com",        "eventName": "ListUsers",        "userAgent": "aws-cli/2.13.5 Python/3.11.4",   "sourceIPAddress": "10.0.7.{}", "readOnly": True},
    ],
    "executive": [
        {"eventSource": "s3.amazonaws.com",         "eventName": "GetObject",        "userAgent": "Mozilla/5.0 (Macintosh)",        "sourceIPAddress": "10.0.8.{}", "readOnly": True},
        {"eventSource": "quicksight.amazonaws.com", "eventName": "GetDashboardEmbedUrl","userAgent": "Mozilla/5.0 (Macintosh)",     "sourceIPAddress": "10.0.8.{}", "readOnly": True},
        {"eventSource": "cost-explorer.amazonaws.com","eventName": "GetCostAndUsage","userAgent": "aws-cli/2.13.5 Python/3.11.4",   "sourceIPAddress": "10.0.8.{}", "readOnly": True},
        {"eventSource": "cloudwatch.amazonaws.com", "eventName": "GetMetricData",    "userAgent": "Mozilla/5.0 (Macintosh)",        "sourceIPAddress": "10.0.8.{}", "readOnly": True},
    ],
}


def generate_real_baseline(
    user_id: str,
    role: str,
    n_days: int = 14,
    events_per_day: float = 40.0,
    seed: int = 42,
    account_id: str = "123456789012",
) -> list[dict]:
    """
    Generate realistic CloudTrail-format baseline events for one user.
    These match the real AWS CloudTrail JSON structure exactly.

    Returns a list of CloudTrail Records (NOT pipeline format) —
    pass through cloudtrail_loader.load_cloudtrail_records() to convert.
    """
    rng = random.Random(f"{seed}_{user_id}")
    templates = ROLE_TEMPLATES.get(role, ROLE_TEMPLATES["developer"])
    start = datetime(2024, 1, 1, 8, 0, 0)
    records = []
    event_counter = 0

    for day in range(n_days):
        n = max(1, int(rng.gauss(events_per_day, 8)))
        for _ in range(n):
            tmpl = rng.choice(templates)
            hour = int(rng.gauss(13, 3))
            hour = max(8, min(20, hour))
            ts = start + timedelta(days=day, hours=hour, minutes=rng.randint(0, 59), seconds=rng.randint(0, 59))
            event_counter += 1

            # Build real CloudTrail record structure
            record = {
                "eventVersion":   "1.08",
                "userIdentity": {
                    "type":        "IAMUser",
                    "principalId": f"EXAMPLEID{user_id.upper()}",
                    "arn":         f"arn:aws:iam::{account_id}:user/{user_id}",
                    "accountId":   account_id,
                    "accessKeyId": f"AKIAIOSFODNN{event_counter:04d}",
                    "userName":    user_id,
                    "sessionContext": {
                        "sessionIssuer": {},
                        "webIdFederationData": {},
                        "attributes": {
                            "creationDate":     ts.strftime("%Y-%m-%dT%H:%M:%SZ"),
                            "mfaAuthenticated": "false",
                        }
                    }
                },
                "eventTime":      ts.strftime("%Y-%m-%dT%H:%M:%SZ"),
                "eventSource":    tmpl["eventSource"],
                "eventName":      tmpl["eventName"],
                "awsRegion":      "us-east-1",
                "sourceIPAddress": tmpl["sourceIPAddress"].format(rng.randint(1, 254)),
                "userAgent":      tmpl["userAgent"],
                "requestParameters": {},
                "responseElements":  None,
                "requestID":  f"{event_counter:08x}-{rng.randint(0,65535):04x}-{rng.randint(0,65535):04x}",
                "eventID":    f"{event_counter:08x}-{rng.randint(0,65535):04x}-{rng.randint(0,65535):04x}",
                "readOnly":   tmpl.get("readOnly", True),
                "eventType":  "AwsApiCall",
                "managementEvent": True,
                "recipientAccountId": account_id,
                "eventCategory": "Management",
            }
            records.append(record)

    return records


def generate_all_roles_baseline(
    users: list,  # list of User objects from simulator
    n_days: int = 14,
    seed: int = 42,
) -> dict[str, list[dict]]:
    """
    Generate real CloudTrail baseline for all users.
    Returns dict: user_id → list of pipeline-format events.
    """
    from cloudtrail_loader import load_cloudtrail_records

    result = {}
    for user in users:
        records = generate_real_baseline(
            user_id=user.user_id,
            role=user.role,
            n_days=n_days,
            seed=seed,
        )
        pipeline_events = load_cloudtrail_records(records, user_id_override=user.user_id)
        # Set role on each event
        for ev in pipeline_events:
            ev["role"] = user.role
        result[user.user_id] = pipeline_events

    return result
