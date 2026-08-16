"""
anomaly_scorer.py — Isolation Forest + Velocity Detection.

Two complementary anomaly signals:

1. Isolation Forest (pattern-based)
   Detects actions that look unusual compared to the user's baseline
   distribution. Catches cross-role actions, unusual IPs, unusual timing.
   Fails for in-vocabulary attacks at normal frequency.

2. Velocity detection (frequency-based)
   Detects actions that occur at abnormally high frequency compared to
   the user's baseline rate. Catches volumetric attacks like data
   exfiltration (s3:GetObject at 10x normal) and discovery sweeps
   (ec2:DescribeInstances at 10x normal) even when IF scores them low.

Final score = max(IF_score, velocity_score)
This ensures either signal can trigger detection independently.
"""

import numpy as np
from sklearn.ensemble import IsolationForest
from typing import Optional
from feature_encoder import FeatureEncoder, get_action, get_source_ip
from simulator import ROLE_ACTIONS

NORMAL_SCORE_CAP    = 0.20   # max score for IF within baseline distribution
VELOCITY_WINDOW     = 100    # rolling window size (events)
VELOCITY_THRESHOLD  = 4.0    # trigger if action count > threshold x baseline


class AnomalyScorer:
    def __init__(self, contamination: float = 0.05, n_estimators: int = 100, seed: int = 42):
        self._contamination = contamination
        self._n_estimators  = n_estimators
        self._seed          = seed
        self._encoder       = FeatureEncoder()
        self._forest: Optional[IsolationForest] = None
        self._p5:   float = 0.0
        self._p95:  float = 1.0
        self._fitted = False

        # Velocity detection baseline:
        # action → expected count per VELOCITY_WINDOW events
        self._action_expected: dict[str, float] = {}

    def fit(self, baseline_events: list[dict], role: str = None) -> "AnomalyScorer":
        if not baseline_events:
            return self

        self._encoder.fit(baseline_events)

        # Expand vocabulary with full role action list
        if role and role in ROLE_ACTIONS:
            for action in ROLE_ACTIONS[role]:
                self._encoder.known_actions.add(action)

        # Add common resource types
        self._encoder.known_resources.update({
            "S3Bucket", "IAMRole", "EC2Instance", "LambdaFunction", "STSRole",
            "Secret", "SSMParameter", "Trail", "Detector", "AWSResource",
            "RDSInstance", "EKSCluster", "ECSTask", "DynamoDBTable",
        })

        # ── Isolation Forest ─────────────────────────────────────────────────
        X = np.array([self._encoder.encode(e) for e in baseline_events])
        self._forest = IsolationForest(
            n_estimators=self._n_estimators,
            contamination=self._contamination,
            random_state=self._seed,
        )
        self._forest.fit(X)

        raw = -self._forest.score_samples(X)
        self._p5  = float(np.percentile(raw, 5))
        self._p95 = float(np.percentile(raw, 95))
        if self._p95 <= self._p5:
            self._p95 = self._p5 + 1e-6

        # ── Velocity baseline ─────────────────────────────────────────────────
        # Count how often each action appears in baseline
        # Scale to expected count per VELOCITY_WINDOW events
        from collections import Counter
        action_counts = Counter(get_action(e) for e in baseline_events)
        n = len(baseline_events)
        for action, count in action_counts.items():
            # Expected occurrences in a window of VELOCITY_WINDOW events
            self._action_expected[action] = (count / n) * VELOCITY_WINDOW

        self._fitted = True
        return self

    def score(self, event: dict, recent_action_count: int = 0) -> float:
        if not self._fitted:
            return 0.0

        # ── Signal 1: Novelty override ────────────────────────────────────────
        action_novel, _ = self._encoder.novelty_flags(event)
        if action_novel:
            return 1.0

        # ── Signal 2: Isolation Forest score ─────────────────────────────────
        vec = self._encoder.encode(event).reshape(1, -1)
        raw = float(-self._forest.score_samples(vec)[0])
        t   = (raw - self._p5) / (self._p95 - self._p5)

        if t <= 1.0:
            if_score = float(np.clip(t * NORMAL_SCORE_CAP, 0.0, 1.0))
        else:
            excess   = t - 1.0
            if_score = float(np.clip(
                NORMAL_SCORE_CAP + (1.0 - NORMAL_SCORE_CAP) * min(1.0, excess),
                0.0, 1.0
            ))

        # ── Signal 3: Velocity detection ─────────────────────────────────────
        velocity_score = 0.0
        if recent_action_count > 0:
            action   = get_action(event)
            expected = self._action_expected.get(action, 1.0)
            expected = max(3.0, expected)  # minimum baseline — avoid false triggers on rare actions
            ratio    = recent_action_count / expected
            if ratio > VELOCITY_THRESHOLD:
                # Smoothly scale: 2.5x→0.40, 5x→0.70, 10x→1.0
                velocity_score = min(1.0, (ratio - VELOCITY_THRESHOLD) / (10.0 - VELOCITY_THRESHOLD))
                velocity_score = float(np.clip(velocity_score * 0.9 + 0.30, 0.0, 1.0))

        # Final score: take maximum of both signals
        return float(max(if_score, velocity_score))

    def top_features(self, event: dict, top_k: int = 3,
                     recent_action_count: int = 0) -> list[str]:
        if not self._fitted:
            return []
        action  = get_action(event)
        src_ip  = get_source_ip(event)
        score   = self.score(event, recent_action_count)
        reasons = []
        action_novel, _ = self._encoder.novelty_flags(event)

        if action_novel:
            reasons.append(f"Novel API action: {action} (outside role vocabulary)")

        # Velocity reason
        if recent_action_count > 0:
            expected = self._action_expected.get(action, 1.0)
            if expected > 0 and recent_action_count / expected > VELOCITY_THRESHOLD:
                reasons.append(
                    f"High frequency: {action} called {recent_action_count}x "
                    f"(baseline: {expected:.1f}x per {VELOCITY_WINDOW} events)"
                )

        if src_ip and not src_ip.startswith("10.0."):
            reasons.append(f"External source IP: {src_ip}")
        if event.get("bytes_transferred", 0) > 10_000:
            reasons.append(f"High data transfer: {event['bytes_transferred']:.0f} bytes")
        if score > 0.50:
            reasons.append(f"Isolation Forest path depth anomaly (score={score:.2f})")

        return reasons[:top_k]
