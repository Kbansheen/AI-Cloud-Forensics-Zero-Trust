<div align="center">

# Active Zero Trust Cloud Forensics & Continuous Trust Evaluation

### AI-Driven Behavioral Drift Modeling, Real-Time Trust Re-Evaluation, and Adaptive Parameter Tuning over Cloud Control-Plane Audits

Behavioral Analytics · Continuous Re-Authentication · Multi-Armed Bandits · Incident Response

[![IEEE Xplore](https://img.shields.io/badge/IEEE-Xplore-blue.svg)](https://doi.org/10.1109/ISCS69371.2025.11386291)
[![Python 3.8+](https://img.shields.io/badge/python-3.8%2B-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

</div>

---

## 📌 Research Context & Journey

This repository houses the complete, unified research codebase and implementation files for my graduate dissertation. It represents a progressive research journey—from identifying critical authentication gaps in modern digital forensics, to designing mathematically bounded continuous trust scoring models, and finally to engineering active reinforcement-learning defenses against evasive adversaries.

Rather than treating cloud security as a set of disconnected tools, this repository unites three distinct phases of scientific inquiry into a single, cohesive framework:

<div align="center">

| Phase | Research Focus | Practical Contribution |
|:---|:---|:---|
| **Phase 1: Conceptual Blueprint** | Foundational review of AI and Zero Trust integration in cloud forensics. | Identified the "static trust" gap and mapped out the initial AIZT-CFIR design. |
| **Phase 2: Mathematical Engine** | Continuous trust re-evaluation via event-driven decay-recovery modeling. | Code for a reproducible 90-day simulation of 165k events with unsupervised scoring. |
| **Phase 3: Active Defense** | Mitigating evasive pacing threats using reinforcement learning parameter tuning. | Ongoing full-stack monitoring dashboard with a per-user UCB1 bandit. |

</div>

---

## 🕵️‍♂️ The Core Problem: Static Trust in Cloud Environments

Modern cloud control planes authorize credentials at the moment of login. Once authenticated, the session is treated as statically trusted for hours, leaving a dangerous vulnerability: **the credentialed insider**. 

Whether an identity is a legitimate compromised user or a rogue service role, an attacker inside the control plane can slowly and deliberately drift away from normal behavior—exfiltrating data or escalating privileges—while staying completely below traditional rate-limiting or spike-based detection thresholds. 

### Identifying the Gaps
Our foundational review of cloud forensics (published in **IEEE ISCS 2025**) established that existing frameworks are highly reactive and fail to maintain forensic integrity in transient, multi-tenant cloud planes. This literature review proposed the conceptual **AI-driven Zero Trust Cloud Forensics and Incident Response (AIZT-CFIR)** framework, establishing that real-time, continuous re-verification is the only mathematically sound way to secure cloud environments against behavioral drift.

### Our Proposed Solution
To bridge this gap, we operationalized the AIZT-CFIR framework. Every cloud control-plane event dynamically updates a bounded, scalar trust score $T_u \in [0, 1]$. If a user's behavior looks suspicious, their trust score decays proportionally to the anomaly severity, triggering **graded enforcement actions** (such as step-up MFA, read-only session restrictions, or total account quarantine) in real time.

---

## 📐 System Architecture & Methodology

The continuous trust pipeline operates as an automated, closed-loop feedback system:

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

### 1. High-Dimensional Feature Engineering
To identify behavioral deviations, raw JSON CloudTrail logs are transformed into sparse, 538-dimensional vectors across seven main feature families:
* **API Action**: One-hot encoded ($k=500$) for command semantics.
* **Resource ARN Category**: One-hot encoded ($k=10$) for service context.
* **Call Origin**: Binary {Console vs. Access Key} to separate humans from automated code.
* **Bytes Out**: Log-scaled float capturing exfiltration volumes.
* **Geodesic Distance**: Normalized float representing travel improbability.
* **Hour-of-day**: Sine/Cosine transformation for circadian offsets.
* **Session Age**: Log-scaled float to detect credential reuse.

### 2. Unsupervised Anomaly Scoring: The Latency vs. Interpretability Trade-Off
We benchmarked three candidate detectors on an identical validation dataset: an **Isolation Forest**, a **Local Outlier Factor (LOF)**, and a **3-Layer Autoencoder**. 

Although the Autoencoder achieved the highest raw validation AUC (0.94 vs 0.92 for the Isolation Forest), **the Isolation Forest was selected for deployment** due to two critical operational requirements:
1. **Latency**: The Isolation Forest delivers a median per-event inference latency of just **2.7 ms** (well below our 5 ms real-time enforcement constraint), compared to the Autoencoder's 16 ms.
2. **Interpretability**: The Isolation Forest's path-length calculations allow a security analyst to easily extract and interpret the shortest isolation paths, providing immediate context (e.g., that an alert was triggered by an unusual `iam:PassRole` API call).

### 3. Mathematically Bounded Trust Updates
For any user $u$ at event step $t$, the continuous trust score $T_u(t) \in [0, 1]$ is recursively updated using a bounded decay-recovery rule:

$$T_u(t+1) = \text{clamp}_{[0, 1]} \left[ T_u(t) - \lambda s_u(t) + \rho (1 - s_u(t)) (1 - T_u(t)) \right]$$

* **Parameters**: Baseline decay rate $\lambda = 0.15$; baseline recovery rate $\rho = 0.05$.
* **Properties**: Since $\lambda, \rho > 0$ and $\lambda + \rho < 1$, the trust score is mathematically guaranteed to stay stable and bounded in $[0, 1]$ at all times. 
* **The Decay-Recovery Dynamic**: A single anomalous event immediately decays trust. In contrast, normal behavior recovers trust, but it does so **deliberately more slowly**, ensuring that the system's memory of suspicious actions persists through "cover" behavior.

### 4. Graded Enforcement Policy Mapping
Instead of binary block/allow decisions, the scalar trust score drives real-time, risk-adaptive session constraints:
* **$T_u \ge 0.80$**: **Normal Access** (Benign activity is tightly concentrated here).
* **$0.60 \le T_u < 0.80$**: **Step-up MFA** (Triggers additional multi-factor challenges for minor anomalies).
* **$0.40 \le T_u < 0.60$**: **Read-Only Privilege** (Strips permission to write or modify cloud resources).
* **$T_u < 0.40$**: **Session Quarantine** (Revokes active credentials immediately and alerts SOC analysts).

---

## 📂 Repository Directory Structure

The codebase is organized into clean, logical research and engineering boundaries:

```directory
AI-Cloud-Forensics-Zero-Trust/
├── .gitignore                      # Excludes large generated datasets from GitHub
├── LICENSE                         # Official MIT License
├── README.md                       # Master documentation (you are reading this)
├── requirements.txt                # Unified python libraries
│
├── simulation_results_and_analysis/ # 📊 THE OFFLINE SIMULATION SUITE
│   ├── step1_generate_data.py      # Role-based CloudTrail log generator
│   ├── step2_extract_features.py   # 538-dimensional sparse vectorizer
│   ├── step3_anomaly_scoring.py    # Unsupervised Isolation Forest training & calibration
│   ├── step4_trust_engine.py       # Bounded decay-recovery update loop & metrics
│   ├── step5_results.py            # Generates comparative tables & exports paper plots
│   ├── view_npy.ipynb               # Human-friendly notebook to load and inspect arrays
│   ├── fig_main_results.png        # Exported ROC, trajectory, and volatility plots
│   ├── fig_mttd.png                # Exported MTTD scenario bar chart
│   ├── fig_trust_distribution.png  # Exported benign vs malicious density histogram
│   └── results_summary.txt          # Humanized analysis of experimental outcomes
│
└── adaptive_trust_dashboard/        # ⚡ ACTIVE FULL-STACK ENGINEERING DASHBOARD PROJECT
    ├── README.md                    # Dedicated dashboard guide
    ├── core/
    │   ├── bandit_learner.py       # Multi-armed UCB1 bandit parameter tuner
    │   └── pacing_adversary.py     # Simulation logic for the evasive adversary
    └── dashboard/
        ├── backend/                # FastAPI backend & WebSocket server
        └── frontend/               # Interactive React / Streamlit UI
```

---

## 📊 Empirical Results & Performance (Simulation Phase)

The pipeline under **`simulation_results_and_analysis/`** replicates the core continuous trust experiments over a 90-day simulation of **165,345 events**, 50 role-based synthetic users, and **8 injected MITRE ATT&CK insider threat scenarios**.

Running this pipeline produces the following comparative metrics against an otherwise identical static-trust baseline:

* **Session-Level Detection AUC**: Lifted from **$0.65 \pm 0.04$** (Static ZT) to **$0.83 \pm 0.03$** (Continuous ZT).
* **Mean Time-to-Detect (MTTD)**: Slashed by **50%** from **11.4 hours** down to **5.7 hours** (and up to a 99% reduction in high-volume Data Exfiltration).
* **False Positive Rate (FPR)**: Slashed by nearly half, dropping from **$0.48 \rightarrow 0.28$**, preventing unnecessary lockouts.
* **Precision**: Doubled from **$0.06 \rightarrow 0.12$** under severe class imbalance.

### Parameter Ablation Study (Generated by Step 5)
| Variant | $\lambda$ (Decay) | $\rho$ (Recovery) | Session AUC | Precision | FPR |
| :--- | :---: | :---: | :---: | :---: | :---: |
| **Default (Ours)** | **0.15** | **0.05** | **0.83 ± 0.03** | **0.12** | **0.28** |
| No-recovery | 0.15 | 0.00 | 0.52 ± 0.00 | 0.05 | 0.95 |
| Aggressive | 0.25 | 0.10 | 0.80 ± 0.03 | 0.10 | 0.34 |

### Automatically Generated Research Figures
Running `python simulation_results_and_analysis/step5_results.py` automatically plots and exports the following figures:

1. **`fig_main_results.png`**: ROC curves, trust trajectories during active attacks, and volatility boxplots showing that malicious users exhibit significantly higher trust volatility ($V_u$).
2. **`fig_trust_distribution.png`**: Dense histogram showing clear separation—benign events concentrate heavily above $T_u = 0.80$, while malicious events are successfully forced into the restricted and quarantine zones.
3. **`fig_mttd.png`**: Detection latency comparison across all 8 MITRE ATT&CK scenarios (Privilege Escalation, Lateral Movement, Collection, etc.).

---

## ⚡ Current Work: Adaptive Parameters & Visual Dashboard

While our simulation results proved the mathematical feasibility of continuous trust evaluation, they also exposed a critical operational vulnerability: **fixed parameters are exploitable**. 

### 1. The Pacing Adversary
An informed adversary who knows the decay ($\lambda = 0.15$) and recovery ($\rho = 0.05$) rates can calculate the optimal spacing of their attacks. By inserting a specific number of benign events between malicious steps, they can let their trust score recover, successfully delaying quarantine by up to **29 hours**.

### 2. Reinforcement Learning via Multi-Armed Bandits
To counter this pacing threat, our ongoing work implements a per-user **Upper Confidence Bound (UCB1) Multi-Armed Bandit** over a 14-arm stability-constrained parameter grid. 
* By evaluating the outcomes of previous enforcement actions (rewarding successful detections and penalizing false alarms), the bandit adaptively optimizes the decay and recovery rates ($\lambda, \rho$) per user.
* Against the pacing adversary, this adaptive learning **recovers detection speeds to under 2 hours** and slashes the False Positive Rate by **50.2%** ($110.85 \rightarrow 55.19$ per 10k events).

### 3. The Full-Stack Monitoring UI
To make this deployable in a real-world Security Operations Center (SOC), we are actively building a full-stack, real-time visualization dashboard:
* **FastAPI Backend**: Connects to the core models via REST and WebSockets to stream active user trajectories.
* **React/Streamlit Frontend**: Displays live visual trajectory charts, the bandit parameter grid's convergence, and controls to trigger live MITRE ATT&CK simulations in real time.

---

## 🛠️ Setup & Execution

To replicate the continuous trust simulation on your own computer:

### 1. Install Dependencies
```bash
pip install -r requirements.txt
```

### 2. Run the Simulation Pipeline End-to-End
```bash
python simulation_results_and_analysis/step1_generate_data.py
python simulation_results_and_analysis/step2_extract_features.py
python simulation_results_and_analysis/step3_anomaly_scoring.py
python simulation_results_and_analysis/step4_trust_engine.py
python simulation_results_and_analysis/step5_results.py
```
*(Once completed, the final metrics will print in your terminal, and the three high-resolution `.png` figures and humanized `results_summary.txt` will be exported straight to your `simulation_results_and_analysis/` folder!)*

---

## 📝 Citations & Publications

If you use this codebase or refer to our work, please cite our papers:

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
