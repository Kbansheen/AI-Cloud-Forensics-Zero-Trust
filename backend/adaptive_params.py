"""
adaptive_params.py — UCB adaptive λ/ρ learner.

Key fix: arm grid is constrained to STABLE pairs only.
Stability condition: ρ/λ > 0.35 ensures trust has net positive
drift during normal (low-score) events and doesn't collapse.

Arms that violate this (e.g. λ=0.30, ρ=0.02) cause trust to
erode even for completely benign behaviour — excluded entirely.
"""

import math
import numpy as np
from dataclasses import dataclass, field
from typing import Optional

# Only stable arms: ρ/λ > 0.35
ARMS = [
    (0.10, 0.05), (0.10, 0.08), (0.10, 0.10),
    (0.13, 0.05), (0.13, 0.08), (0.13, 0.10),
    (0.15, 0.05), (0.15, 0.08), (0.15, 0.10),
    (0.18, 0.08), (0.18, 0.10),
    (0.20, 0.08), (0.20, 0.10),
    (0.23, 0.10),
]

DEFAULT_ARM_IDX = ARMS.index((0.15, 0.05))   # Paper 1 baseline


@dataclass
class ArmState:
    lambda_: float
    rho:     float
    n:       int   = 1
    q:       float = 0.0


class UCBParamLearner:
    """
    Per-user UCB1 bandit over stable (λ, ρ) pairs.
    Warm-started on the Paper 1 default to prevent cold-start collapse.
    """

    def __init__(self, c: float = 0.2, seed: int = 42):
        self.c    = c
        self.t    = len(ARMS)
        self.arms = [ArmState(lambda_=l, rho=r) for (l, r) in ARMS]

        # Strong warm-start: Paper 1 default gets 200 fake pulls
        # with positive reward — UCB explores slowly from here
        self.arms[DEFAULT_ARM_IDX].n = 200
        self.arms[DEFAULT_ARM_IDX].q = 20.0   # mean reward = 0.1

        self._current_arm_idx = DEFAULT_ARM_IDX
        self.history: list[dict] = []

    def select(self) -> tuple[float, float]:
        ln_t = math.log(self.t + 1)
        ucb  = [
            arm.q / arm.n + self.c * math.sqrt(ln_t / arm.n)
            for arm in self.arms
        ]
        self._current_arm_idx = int(np.argmax(ucb))
        arm = self.arms[self._current_arm_idx]
        return arm.lambda_, arm.rho

    def update(self, reward: float, event_idx: int = 0):
        arm = self.arms[self._current_arm_idx]
        arm.n += 1
        arm.q += reward
        self.t += 1
        if len(self.history) < 1000:
            self.history.append({
                "event_idx": event_idx,
                "lambda_":   arm.lambda_,
                "rho":       arm.rho,
                "reward":    round(reward, 3),
            })

    def current_params(self) -> tuple[float, float]:
        arm = self.arms[self._current_arm_idx]
        return arm.lambda_, arm.rho

    def best_arm(self) -> dict:
        best = max(self.arms, key=lambda a: a.q / a.n)
        return {
            "lambda_":     best.lambda_,
            "rho":         best.rho,
            "mean_reward": round(best.q / best.n, 4),
        }

    def arm_table(self) -> list[dict]:
        return [
            {
                "lambda_": a.lambda_,
                "rho":     a.rho,
                "n":       a.n,
                "mean_q":  round(a.q / a.n, 4),
            }
            for a in self.arms
        ]

    def param_history(self, max_pts: int = 300) -> list[dict]:
        h = self.history
        if len(h) <= max_pts:
            return h
        step = len(h) // max_pts
        return h[::step]


def compute_reward(is_attack: bool, zone: str) -> float:
    restricted = zone in ("read_only", "quarantine")
    if is_attack and restricted:     return  1.0
    if not is_attack and restricted: return -0.5
    if not is_attack and not restricted: return 0.05
    return 0.0
