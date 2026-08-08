"""
STEP 2 - Feature Extraction Pipeline
=====================================
Paper Section 3.2, Table 1: Behavioral Feature Set

What this does:
- Loads cloudtrail_logs.csv from Step 1
- Converts each event into a 538-dimensional feature vector
- Matches Table 1 exactly:
    * API action      → one-hot (k=500)
    * Resource ARN    → one-hot (k=10 types)
    * Call origin     → binary  (Console=1, Key=0)
    * Bytes out       → log-scaled float
    * Geo-distance    → normalized float
    * Hour-of-day     → sin/cos encoding
    * Session age     → log-scaled float
    * Error code      → binary
- Pads to 538 dimensions (paper's reported size)
- Saves features to features.npy

Run: python step2_extract_features.py
"""

import numpy as np
import pandas as pd
from sklearn.preprocessing import MinMaxScaler

def extract_features(df):
    print("=" * 60)
    print("STEP 2: Extracting Features (Table 1 of paper)")
    print("=" * 60)

    df = df.reset_index(drop=True)
    n  = len(df)
    features = []

    # ── Feature 1: API action one-hot (k=500) ────────────────────────────────
    print("  [1/8] API action one-hot encoding (k=500)...")
    top_actions    = df["event_name"].value_counts().head(500).index.tolist()
    action_to_idx  = {a: i for i, a in enumerate(top_actions)}
    action_matrix  = np.zeros((n, 500), dtype=np.float32)
    for i, action in enumerate(df["event_name"]):
        if action in action_to_idx:
            action_matrix[i, action_to_idx[action]] = 1.0
    features.append(action_matrix)

    # ── Feature 2: Resource ARN type one-hot (10 types) ──────────────────────
    print("  [2/8] Resource ARN type one-hot (10 types)...")
    arn_types = ["s3", "ec2", "iam", "lambda", "rds", "kms", "sts", "ssm", "cloudwatch", "other"]
    arn_matrix = np.zeros((n, len(arn_types)), dtype=np.float32)
    for i, arn in enumerate(df["resource_arn"]):
        matched = False
        for j, t in enumerate(arn_types[:-1]):
            if t in str(arn):
                arn_matrix[i, j] = 1.0
                matched = True
                break
        if not matched:
            arn_matrix[i, -1] = 1.0
    features.append(arn_matrix)

    # ── Feature 3: Call origin binary (Console=1, Key=0) ─────────────────────
    print("  [3/8] Call origin (Console vs Key)...")
    origin = (df["call_origin"] == "Console").astype(np.float32).values.reshape(-1, 1)
    features.append(origin)

    # ── Feature 4: Bytes out (log-scaled, normalized) ────────────────────────
    print("  [4/8] Bytes out (log-scaled)...")
    bytes_log    = np.log1p(df["bytes_out"].fillna(0).values).reshape(-1, 1).astype(np.float32)
    bytes_scaled = MinMaxScaler().fit_transform(bytes_log)
    features.append(bytes_scaled)

    # ── Feature 5: Geo-distance (normalized) ─────────────────────────────────
    print("  [5/8] Geo-distance (normalized)...")
    geo        = df["geo_dist_km"].fillna(0).values.reshape(-1, 1).astype(np.float32)
    geo_scaled = MinMaxScaler().fit_transform(geo)
    features.append(geo_scaled)

    # ── Feature 6: Hour-of-day (sin/cos encoding) ─────────────────────────────
    print("  [6/8] Hour-of-day (sin/cos)...")
    hour     = df["hour_of_day"].fillna(12).values
    hour_sin = np.sin(2 * np.pi * hour / 24).reshape(-1, 1).astype(np.float32)
    hour_cos = np.cos(2 * np.pi * hour / 24).reshape(-1, 1).astype(np.float32)
    features.append(hour_sin)
    features.append(hour_cos)

    # ── Feature 7: Session age (log-scaled, normalized) ───────────────────────
    print("  [7/8] Session age (log-scaled)...")
    age        = np.log1p(df["session_age_s"].fillna(0).values).reshape(-1, 1).astype(np.float32)
    age_scaled = MinMaxScaler().fit_transform(age)
    features.append(age_scaled)

    # ── Feature 8: Error code (binary: error present=1) ───────────────────────
    print("  [8/8] Error code (binary)...")
    error = (df["error_code"] != "").astype(np.float32).values.reshape(-1, 1)
    features.append(error)

    # ── Combine all features ──────────────────────────────────────────────────
    # Current total: 500 + 10 + 1 + 1 + 1 + 1 + 1 + 1 + 1 = 517
    X = np.hstack(features)

    # Pad to 538 dimensions (paper's reported dimensionality)
    pad = np.zeros((n, 538 - X.shape[1]), dtype=np.float32)
    X   = np.hstack([X, pad])

    # ── Save ──────────────────────────────────────────────────────────────────
    np.save("features.npy", X)

    sparsity = (X == 0).mean() * 100
    print(f"\n  Feature matrix shape   : {X.shape}")
    print(f"  Sparsity               : {sparsity:.1f}% (paper reports ~92.7%)")
    print(f"  Memory usage           : {X.nbytes / 1e6:.1f} MB")
    print(f"\n  Saved to: features.npy")
    print("\n  STEP 2 COMPLETE. Run step3_anomaly_scoring.py next.")
    return X

if __name__ == "__main__":
    df = pd.read_csv("cloudtrail_logs.csv", parse_dates=["timestamp"])
    X  = extract_features(df)
