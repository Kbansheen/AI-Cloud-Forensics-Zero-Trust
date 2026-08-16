"""
trust_engine.py — Unified trust engine for Papers 1 + 2.

Paper 1: bounded decay-recovery update rule, graded enforcement zones.
Paper 2: UCB adaptive λ/ρ per user, velocity-based anomaly detection.

Velocity detection: tracks per-user action frequency in a rolling
100-event window using O(1) dictionary lookups. Catches volumetric
attacks like data exfiltration that IF misses due to in-vocabulary actions.
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional
from collections import deque
import numpy as np

from adaptive_params import UCBParamLearner, compute_reward
from adversary import PacingAdversary, AdversaryConfig
from feature_encoder import get_user_id, get_action, get_source_ip


ZONE_COLOURS = {
    "normal_access": "#10b981",
    "step_up_mfa":   "#f59e0b",
    "read_only":     "#f97316",
    "quarantine":    "#ef4444",
}


def enforcement_zone(trust: float) -> str:
    if trust >= 0.80: return "normal_access"
    if trust >= 0.60: return "step_up_mfa"
    if trust >= 0.40: return "read_only"
    return "quarantine"


@dataclass
class TrustState:
    user_id: str
    role: str
    trust: float = 0.85
    decay_lambda:   float = 0.15
    recovery_rho:   float = 0.05
    event_count:    int   = 0
    quarantine_count: int = 0
    last_action:    str   = ""
    last_score:     float = 0.0
    zone:           str   = "normal_access"
    history:        list  = field(default_factory=list)
    volatility_window: deque = field(default_factory=lambda: deque(maxlen=500))
    recent_actions:   deque = field(default_factory=lambda: deque(maxlen=100))
    action_counts:    dict  = field(default_factory=dict)
    last_updated:   Optional[datetime] = None

    def update(self, anomaly_score: float, event_idx: int, action: str = "") -> str:
        s   = float(np.clip(anomaly_score, 0.0, 1.0))
        t   = float(self.trust)
        lam = self.decay_lambda
        rho = self.recovery_rho

        t_new = float(np.clip(t - lam * s + rho * (1 - s) * (1 - t), 0.0, 1.0))
        self.trust       = t_new
        self.last_score  = s
        self.last_action = action
        self.event_count += 1
        self.last_updated = datetime.utcnow()
        new_zone = enforcement_zone(t_new)
        if new_zone == "quarantine":
            self.quarantine_count += 1
        self.zone = new_zone
        self.volatility_window.append(t_new)

        if self.event_count % 5 == 0 or s > 0.5:
            self.history.append({
                "idx": event_idx, "trust": round(t_new, 4),
                "score": round(s, 4), "zone": new_zone,
                "action": action,
                "lambda_": round(lam, 3), "rho": round(rho, 3),
            })
        if len(self.history) > 600:
            self.history = self.history[-600:]
        return new_zone

    @property
    def volatility(self) -> float:
        if len(self.volatility_window) < 2:
            return 0.0
        return float(np.std(list(self.volatility_window)))

    def to_dict(self) -> dict:
        return {
            "user_id":         self.user_id,
            "role":            self.role,
            "trust":           round(self.trust, 4),
            "zone":            self.zone,
            "zone_colour":     ZONE_COLOURS[self.zone],
            "event_count":     self.event_count,
            "quarantine_count": self.quarantine_count,
            "last_action":     self.last_action,
            "last_score":      round(self.last_score, 4),
            "volatility":      round(self.volatility, 4),
            "lambda_":         round(self.decay_lambda, 3),
            "rho":             round(self.recovery_rho, 3),
            "last_updated":    self.last_updated.isoformat() if self.last_updated else None,
        }


class TrustEngineManager:
    def __init__(self, use_adaptive_ucb: bool = True):
        self._states:       dict[str, TrustState]      = {}
        self._ucb_learners: dict[str, UCBParamLearner] = {}
        self._use_adaptive_ucb = use_adaptive_ucb
        self._adversary: Optional[PacingAdversary]     = None
        self._alerts: list[dict] = []

    def set_adaptive_mode(self, enabled: bool):
        self._use_adaptive_ucb = enabled

    def enable_adversary(self, cfg: Optional[AdversaryConfig] = None):
        self._adversary = PacingAdversary(cfg or AdversaryConfig())

    def disable_adversary(self):
        self._adversary = None

    @property
    def adversary_enabled(self) -> bool:
        return self._adversary is not None

    def register_user(self, user_id: str, role: str):
        if user_id not in self._states:
            self._states[user_id] = TrustState(user_id=user_id, role=role)
        if user_id not in self._ucb_learners:
            self._ucb_learners[user_id] = UCBParamLearner(seed=42)

    def get_action_velocity(self, user_id: str, action: str) -> int:
        """O(1) lookup of action count in user's recent 100-event window."""
        state = self._states.get(user_id)
        if not state:
            return 0
        return state.action_counts.get(action, 0)

    def process_event(
        self,
        event: dict,
        anomaly_score: float,
        event_idx: int,
        reasons: list[str] = None,
    ) -> dict:
        uid = get_user_id(event)
        if uid not in self._states:
            self.register_user(uid, event.get("role", "unknown"))

        is_attack = event.get("is_attack", False)

        adversary_active = False
        if self._adversary and is_attack:
            current_trust = self._states[uid].trust
            if not self._adversary.should_attack(uid, current_trust):
                is_attack = False
            else:
                adversary_active = True
                anomaly_score = min(anomaly_score, self._adversary.attack_anomaly_score())

        state = self._states[uid]

        # Update rolling action window with O(1) counter
        current_action = get_action(event)
        if len(state.recent_actions) == state.recent_actions.maxlen:
            oldest = state.recent_actions[0]
            state.action_counts[oldest] = state.action_counts.get(oldest, 1) - 1
            if state.action_counts[oldest] <= 0:
                del state.action_counts[oldest]
        state.recent_actions.append(current_action)
        state.action_counts[current_action] = state.action_counts.get(current_action, 0) + 1

        if self._use_adaptive_ucb:
            lam, rho = self._ucb_learners[uid].select()
            state.decay_lambda = lam
            state.recovery_rho = rho
        else:
            lam, rho = 0.15, 0.05
            state.decay_lambda = lam
            state.recovery_rho = rho

        old_zone = state.zone
        new_zone = state.update(anomaly_score, event_idx, current_action)

        if self._use_adaptive_ucb:
            reward = compute_reward(is_attack, new_zone)
            self._ucb_learners[uid].update(reward, event_idx)

        result = {
            "user_id":       uid,
            "event_id":      event.get("eventID", event.get("event_id", "")),
            "action":        current_action,
            "anomaly_score": round(anomaly_score, 4),
            "trust":         round(state.trust, 4),
            "zone":          new_zone,
            "zone_colour":   ZONE_COLOURS[new_zone],
            "zone_changed":  new_zone != old_zone,
            "reasons":       reasons or [],
            "timestamp":     event.get("eventTime", event.get("timestamp", "")),
            "lambda_":       round(lam, 3),
            "rho":           round(rho, 3),
            "is_attack":     is_attack,
            "adversary_active": adversary_active,
        }

        if new_zone in ("quarantine", "read_only") and old_zone not in ("quarantine", "read_only"):
            alert = {
                "alert_id":     f"alert_{len(self._alerts):04d}",
                "user_id":      uid,
                "role":         event.get("role", "unknown"),
                "zone":         new_zone,
                "trust":        round(state.trust, 4),
                "action":       current_action,
                "anomaly_score": round(anomaly_score, 4),
                "reasons":      reasons or [],
                "timestamp":    event.get("eventTime", event.get("timestamp", "")),
                "event_idx":    event_idx,
                "is_attack":    is_attack,
                "lambda_":      round(lam, 3),
                "rho":          round(rho, 3),
            }
            self._alerts.append(alert)
            if len(self._alerts) > 200:
                self._alerts = self._alerts[-200:]

        return result

    def get_user_state(self, uid: str) -> Optional[dict]:
        s = self._states.get(uid)
        return s.to_dict() if s else None

    def get_all_states(self) -> list[dict]:
        return [s.to_dict() for s in self._states.values()]

    def get_alerts(self, limit: int = 50) -> list[dict]:
        return list(reversed(self._alerts[-limit:]))

    def get_ucb_state(self, uid: str) -> Optional[dict]:
        learner = self._ucb_learners.get(uid)
        if not learner:
            return None
        return {
            "best_arm":  learner.best_arm(),
            "arm_table": learner.arm_table(),
            "history":   learner.param_history(100),
        }

    def get_all_ucb_summary(self) -> list[dict]:
        out = []
        for uid, learner in self._ucb_learners.items():
            state = self._states.get(uid)
            best  = learner.best_arm()
            out.append({
                "user_id":        uid,
                "role":           state.role if state else "unknown",
                "current_lambda": round(state.decay_lambda if state else 0.15, 3),
                "current_rho":    round(state.recovery_rho if state else 0.05, 3),
                "best_lambda":    best["lambda_"],
                "best_rho":       best["rho"],
                "mean_reward":    best["mean_reward"],
            })
        return out

    def compute_metrics(self, labelled_events: list) -> dict:
        if not labelled_events:
            return {}
        scores = [s for _, s, _ in labelled_events]
        labels = [int(a) for _, _, a in labelled_events]
        if sum(labels) == 0:
            return {"auc": 0.5, "precision": 0.0, "fpr": 0.0}
        pos = [scores[i] for i, l in enumerate(labels) if l == 1]
        neg = [scores[i] for i, l in enumerate(labels) if l == 0]
        auc = sum(p > n for p in pos for n in neg) / max(1, len(pos) * len(neg))
        threshold = 0.60
        tp = sum(1 for s, l in zip(scores, labels) if s >= threshold and l == 1)
        fp = sum(1 for s, l in zip(scores, labels) if s >= threshold and l == 0)
        tn = sum(1 for s, l in zip(scores, labels) if s < threshold and l == 0)
        return {
            "auc":       round(auc, 4),
            "precision": round(tp / max(1, tp + fp), 4),
            "fpr":       round(fp / max(1, fp + tn), 4),
        }
