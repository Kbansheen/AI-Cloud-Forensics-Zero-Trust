# Adaptive Trust Parameter Learning & Real-Time Visualization Dashboard (WIP)

This directory houses the ongoing, active implementation files for the practical full-stack extension of our Zero Trust continuous trust framework:
> **Project Focus**: *Adaptive Trust Parameter Learning & Real-Time Monitoring in Cloud Zero Trust Environments*

---

## 🌟 Project Focus

While our simulation results validated a robust continuous trust model using fixed decay and recovery rates, **this project** introduces a dynamic defense against a **pacing adversary**—an attacker who deliberately slows their malicious activity to exploit fixed parameters and delay detection.

### Core Engineering Enhancements:
1. **Pacing Adversary Modeling**: Formalizes how sophisticated threats delay detection up to **29.11 hours** under static parameters.
2. **Multi-Armed Bandit Optimization**: Implements a per-user **UCB1 bandit** over a stability-constrained 14-arm parameter grid to dynamically adjust decay and recovery rates in real time based purely on enforcement feedback.
3. **Full-Stack Security Dashboard**: A real-time trust monitoring UI that lets administrators visualize active user trajectories, monitor bandit parameter convergence, and trigger live MITRE ATT&CK insider simulations.

---

## 📂 Directory Organization

We have separated our mathematical models and full-stack dashboard into clean boundaries:

```directory
adaptive_trust_dashboard/
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
