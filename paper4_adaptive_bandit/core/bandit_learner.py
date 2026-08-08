"""
Paper 4: UCB1 Adaptive Parameter Learner
========================================
Implements Section 4 of Paper 4:
- 14 stability-constrained (lambda, rho) arms satisfying rho/lambda > 0.35
- Warm-started arm 7 (baseline: lambda=0.15, rho=0.05) with N=200, Q=20.0
- Asymmetric reward signals (Table 2):
  * True Positive  (Attack, zone in {read_only, quarantine})       -> +1.0
  * False Positive (Benign, zone in {read_only, quarantine})       -> -0.5
  * True Negative  (Benign, zone == normal_access)                 -> +0.05
  * False Negative (Attack, zone == normal_access)                 -> 0.0
- UCB1 Selection Rule:
  a*(t) = argmax { Q_i / N_i + c * sqrt(ln(t) / N_i) } with c = 0.20
"""

import numpy as np

# 14 Stable Arms Grid (Table 1)
STABLE_ARMS = {
    1:  {"lambda": 0.10, "rho": 0.05, "ratio": 0.50},
    2:  {"lambda": 0.10, "rho": 0.08, "ratio": 0.80},
    3:  {"lambda": 0.10, "rho": 0.10, "ratio": 1.00},
    4:  {"lambda": 0.13, "rho": 0.05, "ratio": 0.38},
    5:  {"lambda": 0.13, "rho": 0.08, "ratio": 0.62},
    6:  {"lambda": 0.13, "rho": 0.10, "ratio": 0.77},
    7:  {"lambda": 0.15, "rho": 0.05, "ratio": 0.33},  # baseline arm
    8:  {"lambda": 0.15, "rho": 0.08, "ratio": 0.53},
    9:  {"lambda": 0.15, "rho": 0.10, "ratio": 0.67},
    10: {"lambda": 0.18, "rho": 0.08, "ratio": 0.44},
    11: {"lambda": 0.18, "rho": 0.10, "ratio": 0.56},
    12: {"lambda": 0.20, "rho": 0.08, "ratio": 0.40},
    13: {"lambda": 0.20, "rho": 0.10, "ratio": 0.50},
    14: {"lambda": 0.23, "rho": 0.10, "ratio": 0.43},
}

EXPLORATION_CONSTANT = 0.20


class UCBBanditLearner:
    def __init__(self):
        # Initialize bandit structures for 14 arms
        self.arms = list(STABLE_ARMS.keys())
        self.K = len(self.arms)
        
        # Warm start according to Section 4.3
        self.N = np.ones(self.K, dtype=np.float32)  # pulls count (warm started to 1)
        self.Q = np.zeros(self.K, dtype=np.float32) # cumulative rewards (warm started to 0)
        
        # Arm 7 is the index 6 (0-based) for (lambda=0.15, rho=0.05)
        # N_7 = 200, Q_7 = 20.0
        self.N[6] = 200.0
        self.Q[6] = 20.0
        
        self.t = float(np.sum(self.N))  # total rounds

    def select_arm(self):
        """Selects arm using UCB1 selection rule (Equation 3)."""
        mean_rewards = self.Q / self.N
        exploration_bonus = EXPLORATION_CONSTANT * np.sqrt(np.log(self.t) / self.N)
        ucb_values = mean_rewards + exploration_bonus
        
        # Return 1-based arm ID
        selected_idx = np.argmax(ucb_values)
        return self.arms[selected_idx]

    def get_reward(self, is_malicious, action):
        """Computes asymmetric reward signals (Table 2)."""
        # Graded zones map to groups
        is_restricted = action in ["READ_ONLY", "QUARANTINE", "STEP_UP_MFA"]
        
        if is_malicious:
            if is_restricted:
                return 1.0   # True Positive
            else:
                return 0.0   # False Negative
        else:
            if is_restricted:
                return -0.5  # False Positive
            else:
                return 0.05  # True Negative (reward normal access on benign)

    def update(self, arm_id, is_malicious, action):
        """Updates the selected arm with reward outcome."""
        reward = self.get_reward(is_malicious, action)
        idx = arm_id - 1  # Map 1-based ID to 0-based index
        
        self.N[idx] += 1.0
        self.Q[idx] += reward
        self.t += 1.0


if __name__ == "__main__":
    # Quick sanity check
    bandit = UCBBanditLearner()
    print("Initial pulls N:", bandit.N)
    print("Initial Q:", bandit.Q)
    
    # Try selecting an arm
    arm = bandit.select_arm()
    print(f"Initially selected arm: {arm} (Expected baseline-aligned arm 7 or close)")
    
    # Update with a True Positive on arm 7
    bandit.update(7, is_malicious=True, action="QUARANTINE")
    print("Pulls N after TP update on arm 7:", bandit.N)
    print("Q after TP update on arm 7:", bandit.Q)
