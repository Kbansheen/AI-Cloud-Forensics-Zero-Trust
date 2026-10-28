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
VELOCITY_THRESHOLD  = 2.0    # trigger if action count > threshold x baseline
VELOCITY_PERCENTILE = 95     # percentile of historical per-window burst size used as baseline


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
        # Calibrate each action's "expected" per-VELOCITY_WINDOW count from the
        # LARGEST burst already seen for that action in clean baseline data
        # (95th percentile across overlapping rolling windows) — not a flat
        # per-event average. A flat average badly under-represents legitimate
        # bursty work (e.g. a devops user making 15-20 CloudFormation calls in
        # one troubleshooting session, then nothing for hours): averaged over
        # the full 14-day baseline that burst looks artificially rare, so any
        # future, equally-normal burst of similar size trips the velocity
        # alarm. Calibrating against the user's own historical burst sizes
        # fixes that without losing the ability to catch genuinely abnormal
        # spikes well beyond anything seen during clean behaviour.
        from collections import Counter
        action_sequence = [get_action(e) for e in baseline_events]
        n = len(action_sequence)
        window_counts: dict[str, list[int]] = {}
        stride = max(1, VELOCITY_WINDOW // 4)  # overlapping windows, 25% stride
        for start in range(0, max(1, n - VELOCITY_WINDOW + 1), stride):
            window = action_sequence[start:start + VELOCITY_WINDOW]
            for action, c in Counter(window).items():
                window_counts.setdefault(action, []).append(c)
        # Cover the tail end too, in case n < VELOCITY_WINDOW or doesn't divide evenly
        if n > 0:
            for action, c in Counter(action_sequence[max(0, n - VELOCITY_WINDOW):]).items():
                window_counts.setdefault(action, []).append(c)

        for action, counts_list in window_counts.items():
            self._action_expected[action] = float(np.percentile(counts_list, VELOCITY_PERCENTILE))

        self._fitted = True
        return self

    def _velocity_score(self, event: dict, recent_action_count: int) -> float:
        """Frequency signal, shared by score() and score_batch() so the two
        paths can never drift apart."""
        if recent_action_count <= 0:
            return 0.0
        action   = get_action(event)
        expected = self._action_expected.get(action, 1.0)
        expected = max(3.0, expected)  # minimum baseline — avoid false triggers on rare actions
        ratio    = recent_action_count / expected
        if ratio <= VELOCITY_THRESHOLD:
            return 0.0
        # Smoothly scale: 2.5x→0.40, 5x→0.70, 10x→1.0
        velocity_score = min(1.0, (ratio - VELOCITY_THRESHOLD) / (10.0 - VELOCITY_THRESHOLD))
        return float(np.clip(velocity_score * 0.9 + 0.30, 0.0, 1.0))

    @staticmethod
    def _raw_to_if_score(raw: np.ndarray, p5: float, p95: float) -> np.ndarray:
        """Map raw -score_samples output to the calibrated [0,1] IF score.
        Vectorised equivalent of the scalar maths in score()."""
        t = (raw - p5) / (p95 - p5)
        return np.where(
            t <= 1.0,
            np.clip(t * NORMAL_SCORE_CAP, 0.0, 1.0),
            np.clip(NORMAL_SCORE_CAP + (1.0 - NORMAL_SCORE_CAP) * np.minimum(1.0, t - 1.0), 0.0, 1.0),
        )

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
        if_score = float(self._raw_to_if_score(np.array([raw]), self._p5, self._p95)[0])

        # ── Signal 3: Velocity detection ─────────────────────────────────────
        velocity_score = self._velocity_score(event, recent_action_count)

        # Final score: take maximum of both signals
        return float(max(if_score, velocity_score))

    def score_batch(self, events: list[dict], recent_action_counts: list[int] = None) -> list[float]:
        """
        Vectorised equivalent of calling score() once per event.

        IsolationForest.score_samples() carries a large fixed per-call
        overhead (joblib dispatch + validation + per-tree traversal setup),
        roughly 4 ms PER EVENT when called one row at a time. Handing the
        whole batch to score_samples() in a single call amortises that
        overhead across every event and is ~200x faster for identical
        results (verified row-for-row against score()).

        Novelty-override events still short-circuit to 1.0 and never touch
        the forest, exactly as in score().
        """
        n = len(events)
        if not self._fitted:
            return [0.0] * n
        rc = recent_action_counts if recent_action_counts is not None else [0] * n

        out: list[float] = [0.0] * n
        forest_idx: list[int] = []
        forest_events: list[dict] = []

        for i, event in enumerate(events):
            action_novel, _ = self._encoder.novelty_flags(event)
            if action_novel:
                out[i] = 1.0
            else:
                forest_idx.append(i)
                forest_events.append(event)

        if forest_events:
            X   = np.array([self._encoder.encode(e) for e in forest_events])
            raw = -self._forest.score_samples(X)
            if_scores = self._raw_to_if_score(raw, self._p5, self._p95)
            for k, i in enumerate(forest_idx):
                out[i] = float(max(if_scores[k], self._velocity_score(events[i], rc[i])))

        return out

    def top_features(self, event: dict, top_k: int = 3,
                     recent_action_count: int = 0,
                     score: Optional[float] = None) -> list[str]:
        """
        score: pass the already-computed anomaly score to avoid re-scoring the
        event.  Previously this method called self.score() internally, so every
        event was scored TWICE in the live dashboard path (once by the caller,
        once here) — doubling scoring cost for no benefit.
        """
        if not self._fitted:
            return []
        action  = get_action(event)
        src_ip  = get_source_ip(event)
        if score is None:
            score = self.score(event, recent_action_count)
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
