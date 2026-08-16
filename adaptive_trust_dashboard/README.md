# Adaptive Trust Parameter Learning & Real-Time Visualization Dashboard (WIP)

This directory houses the ongoing, active implementation files for the practical full-stack extension of our Zero Trust continuous trust framework:
> **Project Focus**: *Adaptive Trust Parameter Learning & Real-Time Monitoring in Cloud Zero Trust Environments*

---

## 🌟 Project Focus

While our simulation results validated a robust continuous trust model using fixed decay and recovery rates, **this project** introduces a dynamic defense against a **pacing adversary**—an attacker who deliberately slows their malicious activity to exploit fixed parameters and delay detection.

### Core Engineering Enhancements:
1. **Pacing Adversary Modeling (`adversary.py`)**: Formalizes how sophisticated threats delay detection up to **29.11 hours** under static parameters.
2. **Multi-Armed Bandit Optimization (`adaptive_params.py`)**: Implements a per-user **UCB1 bandit** over a stability-constrained 14-arm parameter grid to dynamically adjust decay and recovery rates in real time based purely on enforcement feedback.
3. **Full-Stack Security Dashboard (`main.py`)**: A real-time trust monitoring UI that lets administrators visualize active user trajectories, monitor bandit parameter convergence, and trigger live MITRE ATT&CK insider simulations.

---

## 📂 Directory Organization

We have separated our mathematical models and full-stack dashboard into clean boundaries:

```directory
adaptive_trust_dashboard/
├── README.md                           # This document (WIP Guide)
└── dashboard/
    ├── backend/                        # Python/FastAPI Backend & Simulation
    │   ├── real_logs/                  # Raw AWS CloudTrail JSON samples
    │   ├── main.py                     # FastAPI web server entry point
    │   ├── simulator.py                # Main simulation engine
    │   ├── trust_engine.py             # Continuous decay-recovery scoring
    │   ├── adaptive_params.py          # UCB1 multi-armed bandit tuning
    │   ├── adversary.py                # Pacing adversary simulation logic
    │   ├── anomaly_scorer.py           # Isolation Forest scoring
    │   ├── feature_encoder.py          # 538-dimensional feature encoder
    │   ├── cloudtrail_loader.py        # CloudTrail log parser & loader
    │   ├── comparison.py               # Benchmark comparison logic
    │   ├── real_baseline_generator.py  # User profile baseline generator
    │   ├── Dockerfile                  # Container build config
    │   ├── requirements.txt            # Python backend dependencies
    │   ├── status.json                 # Dashboard cache status
    │   └── log_generation_commands.txt # Execution command log
    │
    └── frontend/                       # Interactive React Frontend UI
        ├── src/                        # React components (charts, grids, simulations)
        │   ├── App.jsx                 # UI entrance
        │   ├── main.jsx                # Render entrance
        │   └── components/             # Visual widgets
        ├── Dockerfile                  # Frontend container build config
        ├── nginx.conf                  # Nginx web server routing config
        ├── package.json                # Frontend package manifest
        └── vite.config.js              # Vite bundler configurations
```

---

## 🚀 Status: Work in Progress

This portion of the codebase is actively under development. The current focus is integrating the working **FastAPI backend** with the **React frontend charts** to visualize the UCB1 grid convergence in real time.
