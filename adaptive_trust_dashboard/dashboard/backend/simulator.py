"""
simulator.py — Synthetic CloudTrail event generator.

All events generated in authentic AWS CloudTrail JSON format.
ROLE_ACTIONS aligned with actual commands run daily via IAM users
to ensure synthetic simulation matches real log baseline distribution.

Attack scenarios use actions genuinely outside role vocabulary
to ensure novelty override fires correctly for detection.
"""

import random
import math
from datetime import datetime, timedelta
from dataclasses import dataclass, field
from typing import Optional
import numpy as np

ROLES = [
    "developer", "data_analyst", "security_admin",
    "devops", "finance", "hr", "executive"
]

# Role user agents matching actual AWS client versions
ROLE_USER_AGENTS = {
    "developer": [
        "aws-cli/2.13.5 Python/3.11.4 Linux/5.15.0 botocore/2.13.5",
        "aws-sdk-java/1.12.261 Linux/5.15.0 OpenJDK_64-Bit_Server_VM/17.0.4",
        "Boto3/1.34.0 Python/3.11.4 Linux/5.15.0 Botocore/1.34.0",
    ],
    "data_analyst": [
        "aws-cli/2.13.5 Python/3.11.4 Linux/5.15.0 botocore/2.13.5",
        "aws-sdk-python/1.28.0 Python/3.11.4 Linux/5.15.0",
        "Boto3/1.34.0 Python/3.11.4 Linux/5.15.0 Botocore/1.34.0",
    ],
    "security_admin": [
        "aws-cli/2.13.5 Python/3.11.4 Linux/5.15.0 botocore/2.13.5",
        "Boto3/1.34.0 Python/3.11.4 Linux/5.15.0 Botocore/1.34.0",
        "aws-cli/2.15.0 Python/3.11.4 Linux/5.15.0 botocore/2.15.0",
    ],
    "devops": [
        "aws-cli/2.13.5 Python/3.11.4 Linux/5.15.0 botocore/2.13.5",
        "aws-sdk-go/1.44.298 go/go1.20.4 linux/amd64",
        "Boto3/1.34.0 Python/3.11.4 Linux/5.15.0 Botocore/1.34.0",
    ],
    "finance": [
        "aws-cli/2.13.5 Python/3.11.4 Windows/10 botocore/2.13.5",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "Boto3/1.34.0 Python/3.11.4 Windows/10 Botocore/1.34.0",
    ],
    "hr": [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "aws-cli/2.13.5 Python/3.11.4 Windows/10 botocore/2.13.5",
        "Mozilla/5.0 (Windows NT 11.0; Win64; x64) AppleWebKit/537.36",
    ],
    "executive": [
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
        "aws-cli/2.13.5 Python/3.11.4 Darwin/22.6.0 botocore/2.13.5",
        "Mozilla/5.0 (iPhone; CPU iPhone OS 16_6 like Mac OS X) AppleWebKit/605.1.15",
    ],
}

# ROLE_ACTIONS aligned with actual commands run via IAM users in real logs
# This ensures synthetic simulation matches real baseline distribution
ROLE_ACTIONS = {
    "developer": [
        "ec2:DescribeInstances",
        "ec2:DescribeSecurityGroups",
        "ec2:DescribeVpcs",
        "ec2:DescribeSubnets",
        "ec2:DescribeKeyPairs",
        "ec2:DescribeRegions",
        "lambda:ListFunctions",
        "cloudwatch:ListMetrics",
        "cloudwatch:DescribeAlarms",
        "ssm:DescribeParameters",
    ],
    "data_analyst": [
        "s3:ListBuckets",
        "athena:ListQueryExecutions",
        "athena:ListWorkGroups",
        "glue:GetDatabases",
        "glue:ListJobs",
        "cloudwatch:ListMetrics",
        "cloudwatch:DescribeAlarms",
        "redshift:DescribeClusters",
    ],
    "security_admin": [
        "iam:ListUsers",
        "iam:ListRoles",
        "iam:ListPolicies",
        "iam:GetAccountSummary",
        "iam:ListGroups",
        "cloudtrail:DescribeTrails",
        "cloudtrail:ListTrails",
        "guardduty:ListDetectors",
        "cloudwatch:ListMetrics",
        "sts:GetCallerIdentity",
    ],
    "devops": [
        "ec2:DescribeInstances",
        "ec2:DescribeSecurityGroups",
        "ec2:DescribeVpcs",
        "cloudformation:ListStacks",
        "cloudformation:DescribeStacks",
        "ssm:DescribeParameters",
        "ssm:ListDocuments",
        "cloudwatch:ListMetrics",
        "cloudwatch:DescribeAlarms",
        "s3:ListBuckets",
    ],
    "finance": [
        "s3:ListBuckets",
        "budgets:DescribeBudgets",
        "cloudwatch:ListMetrics",
        "cloudwatch:DescribeAlarms",
        "cloudwatch:ListDashboards",
        "ec2:DescribeInstances",
        "ec2:DescribeRegions",
        "sts:GetCallerIdentity",
    ],
    "hr": [
        "s3:ListBuckets",
        "iam:ListUsers",
        "iam:ListGroups",
        "iam:GetAccountSummary",
        "iam:ListRoles",
        "cloudwatch:ListMetrics",
        "cloudwatch:DescribeAlarms",
        "sts:GetCallerIdentity",
    ],
    "executive": [
        "s3:ListBuckets",
        "cloudwatch:ListMetrics",
        "cloudwatch:DescribeAlarms",
        "cloudwatch:ListDashboards",
        "ec2:DescribeInstances",
        "ec2:DescribeRegions",
        "budgets:DescribeBudgets",
        "sts:GetCallerIdentity",
    ],
}

# Attack scenarios use actions outside normal role vocabulary
# ensuring novelty override fires for detection
MITRE_SCENARIOS = {
    "privilege_escalation":  {"action": "iam:PassRole",                  "tactic": "T1068", "events": 308},
    "data_exfiltration":     {"action": "s3:GetObject",                  "tactic": "T1048", "events": 2145},
    "defense_evasion":       {"action": "cloudtrail:StopLogging",        "tactic": "T1036", "events": 411},
    "persistence":           {"action": "iam:AddUserToGroup",            "tactic": "T1098", "events": 198},
    "discovery":             {"action": "ec2:DescribeInstances",         "tactic": "T1087", "events": 1132},
    "collection":            {"action": "ssm:GetParameters",             "tactic": "T1119", "events": 267},
    "credential_access":     {"action": "secretsmanager:GetSecretValue", "tactic": "T1606", "events": 156},
    "lateral_movement":      {"action": "sts:AssumeRole",                "tactic": "T1530", "events": 487},
}

ACCOUNT_ID = "123456789012"
AWS_REGION  = "us-east-1"


def _make_request_id(rng: random.Random, counter: int) -> str:
    return (f"{counter:08x}-{rng.randint(0,0xffff):04x}-"
            f"{rng.randint(0,0xffff):04x}-{rng.randint(0,0xffff):04x}-"
            f"{rng.randint(0,0xffffffffffff):012x}")


def _make_access_key(rng: random.Random) -> str:
    chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    suffix = "".join(rng.choice(chars) for _ in range(16))
    return f"AKIA{suffix}"


@dataclass
class User:
    user_id: str
    role: str
    normal_actions: list
    work_hours: tuple = (9, 18)
    mean_events_per_day: float = 40.0
    attack_scenario: Optional[str] = None
    attack_start_day: Optional[int] = None
    attack_duration_days: int = 3
    access_key_id: str = ""
    principal_id: str = ""


@dataclass
class CloudTrailEvent:
    event_id: str
    user_id: str
    role: str
    action: str
    resource_type: str
    source_ip: str
    user_agent: str
    bytes_transferred: float
    timestamp: datetime
    is_attack: bool = False
    attack_scenario: Optional[str] = None
    access_key_id: str = ""
    principal_id: str = ""
    request_id: str = ""

    def to_cloudtrail_dict(self) -> dict:
        svc_parts = self.action.split(":")
        svc  = svc_parts[0] if len(svc_parts) > 1 else "unknown"
        name = svc_parts[1] if len(svc_parts) > 1 else self.action
        write_kw = ["Put","Create","Start","Stop","Delete","Add","Invoke",
                    "Assume","Update","Modify","Attach","Detach","Enable",
                    "Disable","Push","Terminate","Run","Launch","Send","Pass"]
        read_only = not any(w in name for w in write_kw)
        return {
            "eventVersion": "1.08",
            "userIdentity": {
                "type":        "IAMUser",
                "principalId": self.principal_id,
                "arn":         f"arn:aws:iam::{ACCOUNT_ID}:user/{self.user_id}",
                "accountId":   ACCOUNT_ID,
                "accessKeyId": self.access_key_id,
                "userName":    self.user_id,
                "sessionContext": {
                    "sessionIssuer": {},
                    "webIdFederationData": {},
                    "attributes": {
                        "creationDate":     self.timestamp.strftime("%Y-%m-%dT%H:%M:%SZ"),
                        "mfaAuthenticated": "false",
                    }
                }
            },
            "eventTime":      self.timestamp.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "eventSource":    f"{svc}.amazonaws.com",
            "eventName":      name,
            "awsRegion":      AWS_REGION,
            "sourceIPAddress": self.source_ip,
            "userAgent":      self.user_agent,
            "requestParameters":  {},
            "responseElements":   None,
            "requestID":      self.request_id,
            "eventID":        self.event_id,
            "readOnly":       read_only,
            "eventType":      "AwsApiCall",
            "managementEvent": True,
            "recipientAccountId": ACCOUNT_ID,
            "eventCategory":  "Management",
            "is_attack":       self.is_attack,
            "attack_scenario": self.attack_scenario,
            "role":            self.role,
        }

    def to_dict(self) -> dict:
        return {
            "event_id":          self.event_id,
            "user_id":           self.user_id,
            "role":              self.role,
            "action":            self.action,
            "resource_type":     self.resource_type,
            "source_ip":         self.source_ip,
            "user_agent":        self.user_agent,
            "bytes_transferred": self.bytes_transferred,
            "timestamp":         self.timestamp.isoformat(),
            "is_attack":         self.is_attack,
            "attack_scenario":   self.attack_scenario,
            "hour_of_day":       self.timestamp.hour,
        }


class CloudTrailSimulator:
    def __init__(self, n_users: int = 20, seed: int = 42):
        self.rng      = random.Random(seed)
        self.np_rng   = np.random.default_rng(seed)
        self.users    = self._create_users(n_users)
        self._event_counter = 0
        self._office_ips = [
            f"10.0.{self.rng.randint(1,10)}.{self.rng.randint(1,254)}"
            for _ in range(30)
        ]
        self._external_ips = [
            f"203.0.{self.rng.randint(100,200)}.{self.rng.randint(1,254)}"
            for _ in range(5)
        ]
        self._attack_assignment: dict[str, str] = {}
        self._assign_attacks()

    def _create_users(self, n: int) -> list[User]:
        users = []
        # Guarantee at least 1 user per role first
        guaranteed = list(ROLES)
        self.rng.shuffle(guaranteed)
        assigned_roles = guaranteed[:min(n, len(guaranteed))]
        # Fill remaining slots with weighted random
        remaining = n - len(assigned_roles)
        weights = [20, 15, 8, 12, 10, 10, 5]
        for _ in range(remaining):
            role = self.rng.choices(ROLES, weights=weights, k=1)[0]
            assigned_roles.append(role)
        self.rng.shuffle(assigned_roles)

        for i, role in enumerate(assigned_roles):
            uid = f"user_{i:03d}"
            access_key = _make_access_key(self.rng)
            principal  = f"AIDA{''.join(self.rng.choice('ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789') for _ in range(16))}"
            work_start = self.rng.randint(8, 10)
            users.append(User(
                user_id=uid,
                role=role,
                normal_actions=ROLE_ACTIONS[role].copy(),
                work_hours=(work_start, work_start + 9),
                mean_events_per_day=self.rng.gauss(40, 8),
                access_key_id=access_key,
                principal_id=principal,
            ))
        return users

    def _assign_attacks(self):
        scenario_names = list(MITRE_SCENARIOS.keys())
        n_victims = min(len(scenario_names), len(self.users))
        step = max(1, len(self.users) // n_victims)
        for i, scenario in enumerate(scenario_names[:n_victims]):
            victim = self.users[min(i * step, len(self.users) - 1)]
            victim.attack_scenario      = scenario
            victim.attack_start_day     = self.rng.randint(5, 20)
            victim.attack_duration_days = self.rng.randint(2, 5)
            self._attack_assignment[victim.user_id] = scenario

    def _make_event_id(self) -> str:
        self._event_counter += 1
        return _make_request_id(self.rng, self._event_counter)

    def _normal_event(self, user: User, ts: datetime) -> CloudTrailEvent:
        action     = self.rng.choice(user.normal_actions)
        user_agent = self.rng.choice(ROLE_USER_AGENTS.get(user.role, ["aws-cli/2.13.5"]))
        req_id     = _make_request_id(self.rng, self._event_counter + 10000)
        return CloudTrailEvent(
            event_id=self._make_event_id(),
            user_id=user.user_id,
            role=user.role,
            action=action,
            resource_type=self._infer_resource(action),
            source_ip=self.rng.choice(self._office_ips),
            user_agent=user_agent,
            bytes_transferred=float(self.np_rng.exponential(500)),
            timestamp=ts,
            is_attack=False,
            access_key_id=user.access_key_id,
            principal_id=user.principal_id,
            request_id=req_id,
        )

    def _attack_event(self, user: User, ts: datetime) -> CloudTrailEvent:
        scenario   = MITRE_SCENARIOS[user.attack_scenario]
        req_id     = _make_request_id(self.rng, self._event_counter + 90000)
        return CloudTrailEvent(
            event_id=self._make_event_id(),
            user_id=user.user_id,
            role=user.role,
            action=scenario["action"],
            resource_type=self._infer_resource(scenario["action"]),
            source_ip=self.rng.choice(self._external_ips),
            user_agent="curl/7.81.0",
            bytes_transferred=float(
                self.np_rng.exponential(50_000)
                if "exfil" in user.attack_scenario
                else self.np_rng.exponential(200)
            ),
            timestamp=ts,
            is_attack=True,
            attack_scenario=user.attack_scenario,
            access_key_id=user.access_key_id,
            principal_id=user.principal_id,
            request_id=req_id,
        )

    @staticmethod
    def _infer_resource(action: str) -> str:
        svc = action.split(":")[0] if ":" in action else "unknown"
        return {
            "s3": "S3Bucket", "iam": "IAMRole", "ec2": "EC2Instance",
            "lambda": "LambdaFunction", "sts": "STSRole",
            "secretsmanager": "Secret", "ssm": "SSMParameter",
            "cloudtrail": "Trail", "guardduty": "Detector",
            "eks": "EKSCluster", "ecs": "ECSTask",
            "cloudformation": "CloudFormationStack",
            "athena": "AthenaQuery", "glue": "GlueTable",
            "redshift": "RedshiftCluster", "budgets": "Budget",
            "cloudwatch": "CloudWatchMetric",
        }.get(svc, "AWSResource")

    def generate_baseline(self, user: User, days: int = 14) -> list[CloudTrailEvent]:
        events = []
        start  = datetime(2024, 1, 1, 0, 0, 0)
        for day in range(days):
            n = max(1, int(self.np_rng.poisson(user.mean_events_per_day)))
            for _ in range(n):
                hour = max(0, min(23, int(self.rng.gauss(
                    (user.work_hours[0] + user.work_hours[1]) / 2, 2
                ))))
                ts = start + timedelta(days=day, hours=hour, minutes=self.rng.randint(0,59))
                events.append(self._normal_event(user, ts))
        return events

    def generate_full_trace(self, days: int = 30) -> list[CloudTrailEvent]:
        all_events = []
        start      = datetime(2024, 1, 15, 0, 0, 0)
        for user in self.users:
            for day in range(days):
                is_in_attack = (
                    user.attack_scenario is not None
                    and user.attack_start_day is not None
                    and user.attack_start_day <= day < user.attack_start_day + user.attack_duration_days
                )
                n = max(1, int(self.np_rng.poisson(user.mean_events_per_day)))
                for _ in range(n):
                    hour = max(0, min(23, int(self.rng.gauss(
                        (user.work_hours[0] + user.work_hours[1]) / 2, 2
                    ))))
                    ts = start + timedelta(
                        days=day, hours=hour, minutes=self.rng.randint(0,59)
                    )
                    if is_in_attack and self.rng.random() < 0.25:
                        all_events.append(self._attack_event(user, ts))
                    else:
                        all_events.append(self._normal_event(user, ts))

        all_events.sort(key=lambda e: e.timestamp)
        return all_events
