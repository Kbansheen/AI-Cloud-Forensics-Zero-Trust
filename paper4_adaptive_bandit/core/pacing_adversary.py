"""
Paper 4: Pacing Adversary Simulator
===================================
Implements Section 3.2 of Paper 4:
- Formulates how an informed insider exploits fixed lambda & rho parameters.
- Target threshold T* = 0.40 + delta (safety margin delta = 0.07, so T* = 0.47)
- Computes minimum safe interval n* before next attack:
  T' = clamp(0,1)[ T - lambda*sa + rho*(1-sa)*(1-T) ]
  n* = ceil( (T* - T') / (rho * (1 - T')) )
- Attack is spaced at exactly n* clean events apart, keeping the trust score
  above the quarantine threshold (T >= 0.40) to evade detection.
"""

import numpy as np


class PacingAdversary:
    def __init__(self, lam=0.15, rho=0.05, delta=0.07, s_a=0.55):
        self.lam = lam
        self.rho = rho
        self.delta = delta
        self.s_a = s_a
        self.T_star = 0.40 + delta  # Target threshold (safety margin)

    def calculate_pacing_interval(self, current_trust):
        """
        Equation (2) — Calculates the minimum number of benign events n* 
        required before executing the next attack event.
        """
        # Calculate T' (estimated trust score immediately after the malicious action)
        T_prime = current_trust - self.lam * self.s_a + self.rho * (1.0 - self.s_a) * (1.0 - current_trust)
        T_prime = np.clip(T_prime, 0.0, 1.0)
        
        if T_prime >= self.T_star:
            # If trust score doesn't even drop below target safety margin, no waiting is needed
            return 0
            
        if T_prime >= 1.0:
            return 0

        # Calculate recovery multiplier per benign event: rho * (1 - T')
        recovery_per_event = self.rho * (1.0 - T_prime)
        
        if recovery_per_event <= 0:
            return 1000  # avoid division by zero (extreme boundary)

        # Compute n* (Equation 2)
        n_star = np.ceil((self.T_star - T_prime) / recovery_per_event)
        return int(max(0, n_star))


if __name__ == "__main__":
    # Test with paper defaults
    adv = PacingAdversary(lam=0.15, rho=0.05)
    
    print("=" * 60)
    print("Paper 4: Pacing Adversary Calculation Test")
    print("=" * 60)
    
    # Test lower values of trust to show where pacing kicks in
    for T in [0.90, 0.70, 0.52, 0.50, 0.48]:
        interval = adv.calculate_pacing_interval(T)
        T_prime = T - adv.lam * adv.s_a + adv.rho * (1.0 - adv.s_a) * (1.0 - T)
        print(f"  Current Trust T = {T:.2f} | Post-Attack T' = {T_prime:.4f} | Minimum Safe Benign Interval n* = {interval} events")
        
    print("\n  Interpretation:")
    print("  Knowing that lambda=0.15 and rho=0.05, a pacing adversary whose trust has already")
    print("  declined (e.g., to T=0.50 due to minor baseline anomalies) calculates that a new attack")
    print("  will drop their trust to T'=0.4288 (dangerously close to the T<0.40 quarantine zone).")
    print(f"  Therefore, they must wait at least {adv.calculate_pacing_interval(0.50)} benign events before their next attack")
    print("  to safely recover and remain undetected.")
    print("=" * 60)
