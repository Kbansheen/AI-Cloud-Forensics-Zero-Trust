# AI-Cloud-Forensics-Zero-Trust

[![IEEE Xplore](https://img.shields.io/badge/IEEE-Xplore-blue.svg)](https://doi.org/10.1109/ISCS69371.2025.11386291)
[![Python 3.8+](https://img.shields.io/badge/python-3.8%2B-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

Code and simulation datasets for a continuous trust re-evaluation and adaptive parameter learning system in cloud Zero Trust environments. 

This repository implements the behavioral drift modeling and decay-recovery trust update rules described in our research series (including our published ISCS 2025 review on cloud forensics and our submitted ISAC 2026 work).

---

## 📚 Publications & Research Arc

This codebase links together the following three research papers:

### 1. Foundational Review (Paper 2 — Published)
* **Title**: *Integrating Artificial Intelligence and Zero Trust Principles in Cloud Forensics and Incident Response: A Comprehensive Review*
* **Venue**: Proceedings of ISCS 2025 (The NorthCap University, IEEE Delhi Section), **IEEE Xplore**
* **DOI**: [10.1109/ISCS69371.2025.11386291](https://doi.org/10.1109/ISCS69371.2025.11386291)
* **Finding**: Identified the main research gap—traditional cloud authentication is static (one-time checks at login), leaving systems vulnerable to credentialed insider threats who drift slowly away from normal behavior.

### 2. Continuous Behavioral Trust Modeling (Paper 3 — Under Review)
* **Title**: *Continuous Trust Re-Evaluation Using Behavioral Drift Modelling in Zero Trust Cloud Environments*
* **Venue**: Submitted to ISAC 2026
* **Co-Author**: Sumit Kumar (The NorthCap University)
* **Contribution**: Implements a bounded, per-event recursive trust update rule to replace static sessions. An unsupervised Isolation Forest scores incoming logs to drive trust decay and recovery, triggering graded enforcement (MFA, Read-Only, or Quarantine) based on the current score.

### 3. Adaptive Bandit Parameter Learning (Paper 4 — In Preparation)
* **Title**: *Adaptive Trust Parameter Learning Against Evasive Insider Threats in Zero Trust Cloud Environments*
* **Venue**: In preparation
* **Co-Author**: Sumit Kumar (The NorthCap University)
* **Contribution**: Models a "pacing adversary" that spaces attacks to exploit fixed trust parameters and delay detection. Implements a per-user **UCB1 multi-armed bandit** over a 14-arm stable parameter grid to adaptively optimize decay/recovery rates based solely on enforcement outcomes.

---

## 📐 System Flow

```
                  +----------------------------------------+
                  |  AWS CloudTrail Logs (Control-Plane)   |
                  +----------------------------------------+
                                       |
                                       v
                  +----------------------------------------+
                  |  Sparse Vectorizer (538 Dimensions)    |
                  +----------------------------------------+
                                       |
                                       v
                  +----------------------------------------+
                  |  Unsupervised Isolation Forest Scorer  |
                  +----------------------------------------+
                                       |
                                       v  Anomaly Score su(t)
                  +----------------------------------------+
                  |  Continuous Trust Engine (Eq. 1)       | <----+
                  |  Tracks and Clamps trust score Tu(t)   |      |
                  +----------------------------------------+      | Adaptive Parameter
                                       |                          | Updates (λ, ρ)
                                       v  Trust Score Tu(t)       |
                  +----------------------------------------+      |
                  |  Graded Enforcement Engine            |      |
                  |  (Normal / MFA / Read-Only / Quarantine)|      |
                  +----------------------------------------+      |
                                       |                          |
                                       v  Enforcement Outcome     |
                  +----------------------------------------+      |
                  |  UCB1 Bandit Parameter Learner         | -----+
                  |  (Stability-Constrained 14-Arm Grid)   |
                  +----------------------------------------+
```

---

## 🔬 Key Formulations

### 1. Continuous Trust Update Rule (Paper 3)
For user $u$ at event step $t$, the trust score $T_u(t) \in [0, 1]$ is recursively updated as:

$$T_u(t+1) = \text{clamp}_{[0, 1]} \left[ T_u(t) - \lambda s_u(t) + \rho (1 - s_u(t)) (1 - T_u(t)) \right]$$

* **Defaults**: Decay coefficient $\lambda = 0.15$; recovery coefficient $\rho = 0.05$.

### 2. 538-Dimensional Feature Pipeline
We convert raw JSON CloudTrail logs into sparse vectors across seven main families:
* **API Action**: One-hot encoded ($k=500$)
* **Resource ARN Category**: One-hot encoded ($k=10$ types)
* **Call Origin**: Binary {Console vs. Access Key}
* **Bytes Out**: Log-scaled float
* **Geodesic Distance**: Normalized float
* **Hour-of-day**: Sine/Cosine transformation
* **Session Age**: Log-scaled float

### 3. Graded Enforcement Tiers
* **$T_u \ge 0.80$**: Normal Access
* **$0.60 \le T_u < 0.80$**: Step-up MFA
* **$0.40 \le T_u < 0.60$**: Read-Only Privilege
* **$T_u < 0.40$**: Session Quarantine & admin alert

---

## 🚀 The 5-Step Replication Pipeline

The codebase is organized as a step-by-step pipeline to replicate our Paper 3 experiments:

1. **`step1_generate_data.py`**  
   Generates a 90-day simulation of **165,345 events** for 50 role-based synthetic users, injecting **8 MITRE ATT&CK insider scenarios** (exfiltration, privilege escalation, defense evasion, etc.).
2. **`step2_extract_features.py`**  
   Processes logs to build the 538-dimensional sparse feature vectors and saves them to `features.npy`.
3. **`step3_anomaly_scoring.py`**  
   Trains an unsupervised Isolation Forest on a 14-day user baseline and applies per-user Z-score calibration to save the calibrated scores to `anomaly_scores.npy`.
4. **`step4_trust_engine.py`**  
   Runs the continuous decay-recovery updates (Eq. 1) against the static baseline. Saves output simulation files.
5. **`step5_results.py`**  
   Computes session-level AUC (via bootstrap), precision, false positive rates, and plots the final figures.

---

## 📊 Evaluation Results (Paper 3 Replication)

Running the 5-step pipeline end-to-end reproduces our experimental results:

* **Session-Level AUC**: Static ZT = $0.65 \pm 0.04$ | Continuous ZT = $0.83 \pm 0.03$ (Continuous wins)
* **Mean Time-to-Detect (MTTD)**: Halved from **11.4 hours** (Static ZT) to **5.7 hours** (Continuous ZT).
* **False Positive Rate (FPR)**: Slashed from $0.48$ to $0.28$.
* **Precision**: Improved from $0.06$ to $0.12$.

### Parameter Ablation Table
| Variant | $\lambda$ (Decay) | $\rho$ (Recovery) | Session AUC | Precision | FPR |
| :--- | :---: | :---: | :---: | :---: | :---: |
| **Default (Ours)** | **0.15** | **0.05** | **0.83 ± 0.03** | **0.12** | **0.28** |
| No-recovery | 0.15 | 0.00 | 0.52 ± 0.00 | 0.05 | 0.95 |
| Aggressive | 0.25 | 0.10 | 0.80 ± 0.03 | 0.10 | 0.34 |

---

## 🎨 Generated Figures

Running `step5_results.py` generates the following high-resolution figures at the root of the project:

1. **`fig_main_results.png`**: ROC curves, trust trajectories for compromised users, and volatility boxplots.
2. **`fig_trust_distribution.png`**: Trust score densities comparing benign vs. malicious events.
3. **`fig_mttd.png`**: Detection latencies across all 8 MITRE ATT&CK scenarios.

---

## 🛠️ Setup & Execution

### 1. Requirements
Ensure you have Python 3.8+ installed:
```bash
pip install -r requirements.txt
```

### 2. Run Pipeline
```bash
python step1_generate_data.py
python step2_extract_features.py
python step3_anomaly_scoring.py
python step4_trust_engine.py
python step5_results.py
```

---

## 📝 Citations

If you build upon this work, please cite our papers:

```bibtex
@inproceedings{kaur2025integrating,
  title={Integrating Artificial Intelligence and Zero Trust Principles in Cloud Forensics and Incident Response: A Comprehensive Review},
  author={Kaur, Bansheen and Gupta, Swati},
  booktitle={Proceedings of ISCS 2025},
  publisher={IEEE},
  doi={10.1109/ISCS69371.2025.11386291},
  year={2025}
}

@article{kaur2026continuous,
  title={Continuous Trust Re-Evaluation Using Behavioral Drift Modelling in Zero Trust Cloud Environments},
  author={Kaur, Bansheen and Kumar, Sumit},
  journal={Submitted to ISAC 2026 (Under Review)},
  year={2026}
}
```

---

## 🛡️ License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for more details.
