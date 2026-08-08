# Paper 4: Adaptive Trust Parameter Learning & Visualization Dashboard (WIP)

This directory houses the ongoing, active research and implementation files for the fourth paper in our Zero Trust series:
> **Title**: *Adaptive Trust Parameter Learning Against Evasive Insider Threats in Zero Trust Cloud Environments*  
> **Authors**: Bansheen Kaur and Sumit Kumar (The NorthCap University)

---

## 🌟 Research Focus

While Paper 3 validated a robust continuous trust model using a fixed decay rate ($\lambda = 0.15$) and recovery rate ($\rho = 0.05$), **Paper 4** introduces a dynamic defense against a **pacing adversary**—an attacker who deliberately slows their malicious activity to exploit fixed parameters and delay detection.

### Core Enhancements:
1. **Pacing Adversary Modeling**: Formalizes how sophisticated threats delay detection up to **29.11 hours** under static parameters.
2. **Multi-Armed Bandit Optimization**: Implements a per-user **UCB1 bandit** over a stability-constrained 14-arm parameter grid to dynamically adjust $\lambda$ and $\rho$ in real time based purely on enforcement feedback.
3. **Full-Stack Security Dashboard**: A real-time trust monitoring UI that lets administrators visualize active user trajectories, monitor bandit parameter convergence, and trigger live MITRE ATT&CK insider simulations.

---

## 📂 Subdirectory Organization

We have separated our mathematical models and full-stack dashboard into clean boundaries:

```directory
paper4_adaptive_bandit/
├── README.md                           # This document (WIP Guide)
├── core/                               # MATHEMATICAL & ALGORITHMIC MODELS
│   ├── bandit_learner.py               # UCB1 multi-armed bandit parameter tuner
│   └── pacing_adversary.py             # Simulation logic for the evasive attacker
│
└── dashboard/                          # FULL-STACK VISUALIZATION TOOL
    ├── backend/                        # FastAPI REST/WebSocket Server
    │   └── main.py                     # API entry point & simulated SOAR hooks
    └── frontend/                       # Interactive Frontend UI (React / Streamlit)
        └── src/                        # UI charts, bandit grids, and controllers
```

---

## 🚀 Status: Work in Progress

This portion of the codebase is actively under development. The current focus is integrating the working **FastAPI backend** with the **React/Streamlit frontend charts** to visualize the UCB1 grid convergence in real time.
