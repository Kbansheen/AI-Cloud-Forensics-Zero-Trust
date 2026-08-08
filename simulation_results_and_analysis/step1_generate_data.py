"""
STEP 1 - Realistic CloudTrail Data Generator
=============================================
KEY FIX: Each user has a FIXED behavioral profile (role-based).
Real users are highly repetitive:
  - 2-3 primary APIs used 85% of the time
  - Fixed IP subnet (same location every day)
  - Tight byte ranges per API type
  - Strict business hours (95%+ within work window)
This gives Isolation Forest a clean baseline to learn,
producing near-zero scores for normal events and high
scores for attack events — matching the paper's real data.

Run: python step1_generate_data.py
"""

import numpy as np
import pandas as pd
from datetime import datetime, timedelta
import random

random.seed(42)
np.random.seed(42)

# ── Simulation parameters ─────────────────────────────────────────────────────
N_HUMAN_USERS    = 40
N_SERVICE_ROLES  = 10
N_USERS          = 50
N_ATTACK_USERS   = 8
SIM_DAYS         = 90
START_DATE       = datetime(2024, 1, 1)

# ── Role-based behavioral profiles (realistic repetitive behavior) ─────────────
# Each user is assigned ONE role. They use ONLY those APIs, at THOSE hours,
# with THOSE byte ranges. This is exactly how real AWS users behave.
ROLE_PROFILES = [
    {
        "role":      "DevOps Engineer",
        "primary":   ["ec2:DescribeInstances", "cloudwatch:GetMetricData", "s3:GetObject"],
        "secondary": ["sts:GetCallerIdentity", "lambda:InvokeFunction"],
        "rare":      ["iam:GetUser"],
        "hour_mean": 13, "hour_std": 1.5,   # very tight hours
        "bytes_mean": 500,  "bytes_std": 80,
        "geo_mean":  35,    "geo_std": 5,    # always from same location
        "events_per_day": 35,
    },
    {
        "role":      "Data Engineer",
        "primary":   ["s3:GetObject", "s3:PutObject", "s3:ListBucket"],
        "secondary": ["kms:Decrypt", "rds:DescribeDBInstances"],
        "rare":      ["sts:GetCallerIdentity"],
        "hour_mean": 14, "hour_std": 1.5,
        "bytes_mean": 2200, "bytes_std": 200,
        "geo_mean":  42,    "geo_std": 4,
        "events_per_day": 40,
    },
    {
        "role":      "IAM Administrator",
        "primary":   ["iam:GetUser", "iam:ListUsers", "iam:GetRole"],
        "secondary": ["sts:GetCallerIdentity", "iam:ListRoles"],
        "rare":      ["kms:Decrypt"],
        "hour_mean": 11, "hour_std": 1.5,
        "bytes_mean": 180,  "bytes_std": 30,
        "geo_mean":  28,    "geo_std": 4,
        "events_per_day": 25,
    },
    {
        "role":      "App Developer",
        "primary":   ["lambda:InvokeFunction", "s3:GetObject", "rds:DescribeDBInstances"],
        "secondary": ["cloudwatch:GetMetricData", "sts:GetCallerIdentity"],
        "rare":      ["s3:PutObject"],
        "hour_mean": 13, "hour_std": 2.0,
        "bytes_mean": 950,  "bytes_std": 100,
        "geo_mean":  38,    "geo_std": 5,
        "events_per_day": 30,
    },
    {
        "role":      "Security Analyst",
        "primary":   ["cloudwatch:GetMetricData", "sts:GetCallerIdentity", "kms:Decrypt"],
        "secondary": ["iam:GetUser", "s3:GetObject"],
        "rare":      ["ec2:DescribeInstances"],
        "hour_mean": 12, "hour_std": 2.0,
        "bytes_mean": 280,  "bytes_std": 40,
        "geo_mean":  31,    "geo_std": 4,
        "events_per_day": 28,
    },
    {
        "role":      "Service Role (Lambda)",
        "primary":   ["s3:GetObject", "s3:PutObject", "kms:Decrypt"],
        "secondary": ["sts:GetCallerIdentity"],
        "rare":      ["cloudwatch:GetMetricData"],
        "hour_mean": 12, "hour_std": 6.0,   # service roles run any time
        "bytes_mean": 1500, "bytes_std": 150,
        "geo_mean":  20,    "geo_std": 2,
        "events_per_day": 45,
    },
    {
        "role":      "Service Role (EC2)",
        "primary":   ["ec2:DescribeInstances", "sts:GetCallerIdentity", "cloudwatch:GetMetricData"],
        "secondary": ["s3:GetObject"],
        "rare":      ["kms:Decrypt"],
        "hour_mean": 12, "hour_std": 6.0,
        "bytes_mean": 400,  "bytes_std": 60,
        "geo_mean":  18,    "geo_std": 2,
        "events_per_day": 50,
    },
]

# ── 8 MITRE ATT&CK Attack Scenarios (Table 4 of paper) ───────────────────────
ATTACK_SCENARIOS = [
    {"tactic": "Priv. Esc. T1068",        "action": "iam:PassRole",                  "start_day": 20, "duration": 20},
    {"tactic": "Exfil. T1048",            "action": "s3:GetObject_exfil",            "start_day": 20, "duration": 20},
    {"tactic": "Def. Evasion T1036",      "action": "console_login_tor",             "start_day": 22, "duration": 20},
    {"tactic": "Persistence T1098",       "action": "iam:AddUserToGroup",            "start_day": 22, "duration": 20},
    {"tactic": "Discovery T1087",         "action": "ec2:DescribeInstances_mass",    "start_day": 24, "duration": 20},
    {"tactic": "Collection T1119",        "action": "ssm:GetParameters",             "start_day": 24, "duration": 20},
    {"tactic": "Cred. Access T1606",      "action": "secretsmanager:GetSecretValue", "start_day": 26, "duration": 20},
    {"tactic": "Lateral Mvmt T1530",      "action": "sts:AssumeRole_lateral",        "start_day": 26, "duration": 20},
]

RESOURCE_TYPES = [
    "arn:aws:s3:::bucket-", "arn:aws:ec2:::instance/i-",
    "arn:aws:iam:::user/",  "arn:aws:lambda:::function:",
    "arn:aws:kms:::key/",   "arn:aws:rds:::db:",
]

def make_benign_event(uid, profile, ts):
    """
    Generate ONE realistic benign event for this user.
    Critically: API, bytes, geo all follow tight per-user distributions.
    """
    # API call: 85% primary, 12% secondary, 3% rare
    r = random.random()
    if r < 0.85:
        action = random.choice(profile["primary"])
    elif r < 0.97:
        action = random.choice(profile["secondary"])
    else:
        action = random.choice(profile["rare"])

    # Bytes: tight normal distribution around user's baseline
    # (same user doing same operation = very similar byte count)
    bytes_out = max(50, np.random.normal(profile["bytes_mean"], profile["bytes_std"]))

    # Geo: user always comes from same location (± small variation)
    geo_dist = max(0, np.random.normal(profile["geo_mean"], profile["geo_std"]))

    # Session age: consistent with user's work pattern
    session_age = max(0, np.random.normal(3600, 300))

    # Call origin: consistent for this role
    call_origin = "Console" if uid < N_HUMAN_USERS and random.random() > 0.4 else "Key"

    resource = random.choice(RESOURCE_TYPES) + f"res{random.randint(1, 10)}"
    # Very rare errors (2%) — consistent with normal operations
    error = "" if random.random() > 0.02 else "AccessDenied"

    return {
        "user_id":          f"user_{uid:03d}",
        "role":             profile["role"],
        "is_service_role":  uid >= N_HUMAN_USERS,
        "timestamp":        ts,
        "event_name":       action,
        "resource_arn":     resource,
        "call_origin":      call_origin,
        "bytes_out":        round(bytes_out, 2),
        "geo_dist_km":      round(geo_dist, 2),
        "hour_of_day":      ts.hour,
        "session_age_s":    round(session_age, 2),
        "error_code":       error,
        "is_malicious":     False,
        "is_malicious_user":False,
        "attack_tactic":    "",
    }

def make_attack_event(uid, scenario, ts):
    """
    Generate ONE attack event — clearly outside baseline:
    - Foreign API not in user's profile
    - Massive bytes (data exfiltration)
    - Foreign IP (thousands of km away)
    - Any hour (attackers don't follow business hours)
    """
    return {
        "user_id":          f"user_{uid:03d}",
        "role":             "ATTACKER",
        "is_service_role":  False,
        "timestamp":        ts,
        "event_name":       scenario["action"],
        "resource_arn":     "arn:aws:s3:::bucket-exfil",
        "call_origin":      "Key",
        "bytes_out":        round(max(0, np.random.lognormal(14, 0.4)), 2),
        "geo_dist_km":      round(np.random.uniform(4000, 9000), 2),
        "hour_of_day":      ts.hour,
        "session_age_s":    round(np.random.exponential(300), 2),
        "error_code":       "",
        "is_malicious":     True,
        "is_malicious_user":True,
        "attack_tactic":    scenario["tactic"],
    }

def generate():
    print("=" * 60)
    print("STEP 1: Generating Realistic CloudTrail Dataset")
    print("        (Role-based behavioral profiles)")
    print("=" * 60)

    # Assign roles and attack scenarios
    attack_ids = set(range(N_ATTACK_USERS))
    user_profiles = {}
    user_attacks  = {}
    for uid in range(N_USERS):
        user_profiles[uid] = ROLE_PROFILES[uid % len(ROLE_PROFILES)]
        if uid in attack_ids:
            user_attacks[uid] = ATTACK_SCENARIOS[uid]

    all_rows = []

    for uid in range(N_USERS):
        profile  = user_profiles[uid]
        scenario = user_attacks.get(uid)
        is_att   = uid in attack_ids

        for day in range(SIM_DAYS):
            dt = START_DATE + timedelta(days=day)

            # ── Benign events ─────────────────────────────────────────────────
            n_events = max(5, int(np.random.normal(
                profile["events_per_day"], profile["events_per_day"] * 0.05
            )))
            for _ in range(n_events):
                # Tight hours: 95% within work window
                h = int(np.clip(
                    np.random.normal(profile["hour_mean"], profile["hour_std"]),
                    0, 23
                ))
                ts = dt.replace(
                    hour=h,
                    minute=random.randint(0, 59),
                    second=random.randint(0, 59)
                )
                row = make_benign_event(uid, profile, ts)
                row["is_malicious_user"] = is_att
                all_rows.append(row)

            # ── Attack events (only during attack window) ─────────────────────
            if scenario:
                start = scenario["start_day"]
                end   = start + scenario["duration"]
                if start <= day <= end:
                    n_att = random.randint(20, 40)
                    for _ in range(n_att):
                        h  = random.randint(0, 23)
                        ts = dt.replace(
                            hour=h,
                            minute=random.randint(0, 59),
                            second=random.randint(0, 59)
                        )
                        all_rows.append(make_attack_event(uid, scenario, ts))

    df = pd.DataFrame(all_rows).sort_values("timestamp").reset_index(drop=True)
    df.to_csv("cloudtrail_logs.csv", index=False)

    print(f"\n  Total events        : {len(df):,}")
    print(f"  Benign events       : {(~df['is_malicious']).sum():,}")
    print(f"  Malicious events    : {df['is_malicious'].sum():,}")
    print(f"  Users               : {df['user_id'].nunique()}")
    print(f"  Attack users        : {len(attack_ids)}")
    print(f"  Duration            : {SIM_DAYS} days")
    print()
    print("  User behavioral profiles:")
    print(f"  {'User':<12} {'Role':<25} {'Primary APIs'}")
    for uid in range(min(8, N_USERS)):
        p = user_profiles[uid]
        tag = " [ATTACKER]" if uid in attack_ids else ""
        print(f"  user_{uid:03d}    {p['role']:<25} {p['primary'][0]}, {p['primary'][1]}{tag}")
    print()
    print("  Attack scenarios injected:")
    for sc in ATTACK_SCENARIOS:
        print(f"    Day {sc['start_day']:>2}-{sc['start_day']+sc['duration']:<3} | "
              f"{sc['tactic']:<30} | {sc['action']}")
    print()

    # Show how tight benign behavior is now
    u0 = df[(df['user_id']=='user_008') & (~df['is_malicious'])]
    print(f"  Benign user_008 API distribution (should be very concentrated):")
    for api, cnt in u0['event_name'].value_counts().head(5).items():
        pct = cnt / len(u0) * 100
        print(f"    {api:<40} {pct:.1f}%")
    print()
    print(f"  Benign bytes_out std : {u0['bytes_out'].std():.1f}  "
          f"(paper real data: very tight, ~50-200)")
    print(f"  Benign geo_dist std  : {u0['geo_dist_km'].std():.1f} km  "
          f"(paper real data: near-zero)")
    print()
    print("  STEP 1 COMPLETE. Run step2_extract_features.py next.")
    return df

if __name__ == "__main__":
    df = generate()
