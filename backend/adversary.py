"""
adversary.py — Paper 2: Pacing Adversary Model

An adversary who:
  1. Knows the trust engine's λ and ρ (or estimates them from observed score changes)
  2. Computes the minimum clean-event interval needed between attacks to keep trust
     above the quarantine threshold (T=0.40) plus a safety margin
  3. Operates in "stealthy mode" — chooses action scores below 1.0 to avoid
     triggering the novel-action override while still causing drift

Formal evasion strategy:
  After an attack with anomaly score s, trust drops by:
    ΔT_attack ≈ λ·s  (decay term dominates)
  Each clean event recovers approximately:
    ΔT_recover ≈ ρ·(1−s_clean)·(1−T)  where s_clean ≈ 0
  So safe interval n ≈ (T_target − T_after_attack) / (ρ·(1−T_after_attack))

Paper 2 Table A shows this adversary reduces static-system detection by ~40%.
Paper 2 Table C shows adaptive UCB closes this gap.
"""

import math
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class AdversaryConfig:
    known_lambda: float = 0.15          # λ the adversary knows
    known_rho: float   = 0.05          # ρ the adversary knows
    quarantine_threshold: float = 0.40  # adversary avoids dropping below this
    safety_margin: float = 0.07         # extra buffer (avoids MFA too)
    attack_score: float = 0.55          # stealthy: below novel-action threshold
    enable_stealthy: bool = True         # True = use attack_score; False = full score=1.0


class PacingAdversary:
    """
    Models a knowledge-aware insider who paces malicious actions to evade the
    static trust engine.  For each user independently, tracks:
      - events since last attack
      - current estimated trust (updated from observed enforcement actions)

    Usage:
      adv = PacingAdversary(cfg)
      for event in timeline:
          should_attack = adv.should_attack(user_id, current_trust, event)
          if should_attack:
              event['is_attack'] = True   # override event type
    """

    def __init__(self, cfg: Optional[AdversaryConfig] = None):
        self.cfg = cfg or AdversaryConfig()
        # Per-user state
        self._events_since_attack: dict[str, int]   = {}
        self._last_trust_observed: dict[str, float] = {}
        self._total_attacks:       dict[str, int]   = {}
        self._evaded_events:       dict[str, int]   = {}

    # ------------------------------------------------------------------
    def should_attack(self, user_id: str, current_trust: float) -> bool:
        """
        Return True if the adversary judges it safe to launch an attack event
        for this user right now.
        """
        since = self._events_since_attack.get(user_id, 9999)
        self._events_since_attack[user_id] = since + 1
        self._last_trust_observed[user_id] = current_trust

        safe_n = self._safe_interval(current_trust)
        if since >= safe_n:
            # Reset counter; record attack
            self._events_since_attack[user_id] = 0
            self._total_attacks[user_id] = self._total_attacks.get(user_id, 0) + 1
            return True
        return False

    # ------------------------------------------------------------------
    def _safe_interval(self, current_trust: float) -> int:
        """
        Minimum clean events needed after one attack to recover above threshold.
        Uses the linearised Eq.(1) approximation.
        """
        lam = self.cfg.known_lambda
        rho = self.cfg.known_rho
        s   = self.cfg.attack_score
        target = self.cfg.quarantine_threshold + self.cfg.safety_margin

        # Trust immediately after attack
        t_after = current_trust - lam * s + rho * (1 - s) * (1 - current_trust)
        t_after = max(0.0, min(1.0, t_after))

        if t_after >= target:
            return 1   # already above threshold; can attack again almost immediately

        # Recovery per benign event (s_clean ≈ 0)
        # ΔT ≈ ρ·(1−T_current_at_step)
        # Iteratively compute (more accurate than linear approximation)
        t = t_after
        n = 0
        while t < target and n < 500:
            t += rho * (1 - 0.05) * (1 - t)   # assume s_clean = 0.05 (not perfect)
            n += 1
        return max(1, n)

    # ------------------------------------------------------------------
    def attack_anomaly_score(self) -> float:
        """Score to use when injecting an attack event."""
        if self.cfg.enable_stealthy:
            return self.cfg.attack_score   # below novel-action threshold
        return 1.0

    # ------------------------------------------------------------------
    def stats(self, user_id: str) -> dict:
        return {
            "user_id": user_id,
            "total_attacks": self._total_attacks.get(user_id, 0),
            "events_since_last_attack": self._events_since_attack.get(user_id, 0),
            "last_trust": round(self._last_trust_observed.get(user_id, 1.0), 4),
        }

    def all_stats(self) -> list[dict]:
        return [self.stats(uid) for uid in self._total_attacks]
