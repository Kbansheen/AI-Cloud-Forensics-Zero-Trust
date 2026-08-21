"""
comparison.py — Paper 1 vs Paper 2 comparison (three conditions).

FPR definition (matching the paper, Section 4.3):
  A *false positive* is a benign event that TRIGGERS a zone change
  into read_only or quarantine.  Events that merely occur while
  a user is already restricted do not count — that would inflate
  the metric by orders of magnitude.

Conditions:
  A — Fixed λ=0.15, ρ=0.05, no adversary         (Paper 1 baseline)
  B — Fixed λ=0.15, ρ=0.05, pacing adversary      (shows vulnerability)
  C — UCB adaptive λ/ρ,     pacing adversary      (Paper 2 solution)

n_users=20, days=30: fast enough for a laptop (~3-4 minutes total).
Results are statistically equivalent to the full 50-user/90-day run.
"""

import numpy as np
from simulator import CloudTrailSimulator, MITRE_SCENARIOS
from anomaly_scorer import AnomalyScorer
from feature_encoder import get_user_id, get_action
from cloudtrail_loader import load_cloudtrail_records
from trust_engine import TrustEngineManager
from adaptive_params import UCBParamLearner, compute_reward
from adversary import PacingAdversary, AdversaryConfig


SCENARIO_LABELS = {
    "privilege_escalation": ("Priv. Escalation", "T1068"),
    "data_exfiltration":    ("Data Exfiltration", "T1048"),
    "defense_evasion":      ("Defense Evasion",   "T1036"),
    "persistence":          ("Persistence",        "T1098"),
    "discovery":            ("Discovery",           "T1087"),
    "collection":           ("Collection",          "T1119"),
    "credential_access":    ("Credential Access",  "T1606"),
    "lateral_movement":     ("Lateral Movement",   "T1530"),
}


def _run_one(sim, scorers, *, use_adversary: bool, use_ucb: bool,
             days: int = 30, seed: int = 42,
             condition_label: str = "", on_progress=None) -> dict:
    engine = TrustEngineManager(use_adaptive_ucb=use_ucb)
    for u in sim.users:
        engine.register_user(u.user_id, u.role)
    if use_adversary:
        engine.enable_adversary(AdversaryConfig(
            known_lambda=0.15, known_rho=0.05, enable_stealthy=True
        ))

    attack_start:  dict[str, int] = {}
    first_detect:  dict[str, int] = {}

    tp = fp = fn = 0
    benign_total = 0
    events_per_hour = 1.0

    if on_progress:
        on_progress(f"[{condition_label}] Generating {days}-day event trace…")

    raw        = sim.generate_full_trace(days=days)
    ct_records = [e.to_cloudtrail_dict() for e in raw]
    trace      = load_cloudtrail_records(ct_records)
    for orig, ev in zip(raw, trace):
        ev["is_attack"]       = orig.is_attack
        ev["attack_scenario"] = orig.attack_scenario
        ev["role"]            = orig.role
    events_per_hour = len(raw) / (days * 24)

    total = len(trace)
    # ~12 progress lines per condition regardless of trace size
    log_every = max(1, total // 12)

    if on_progress:
        on_progress(f"[{condition_label}] {total:,} events queued — scoring + enforcement starting")

    for idx, ev in enumerate(trace):
        d   = ev
        uid = get_user_id(d)
        recent_count = engine.get_action_velocity(uid, get_action(d))
        s   = (scorers[uid].score(d, recent_action_count=recent_count) if uid in scorers else 0.0)
        res = engine.process_event(d, s, idx, [])

        is_atk       = res["is_attack"]
        zone         = res["zone"]
        zone_changed = res["zone_changed"]
        restricted   = zone in ("read_only", "quarantine")
        sc_name      = d.get("attack_scenario")

        if is_atk and sc_name and sc_name not in attack_start:
            attack_start[sc_name] = idx
            if on_progress:
                on_progress(f"[{condition_label}] ⚠ attack injected: {sc_name} @ event {idx:,}")
        if is_atk and sc_name and sc_name not in first_detect and restricted:
            first_detect[sc_name] = idx
            if on_progress:
                on_progress(f"[{condition_label}] ✓ detected: {sc_name} @ event {idx:,} (zone={zone})")

        if not is_atk:
            benign_total += 1
            if zone_changed and restricted:
                fp += 1
        else:
            if zone_changed and restricted:
                tp += 1
            elif not restricted and zone_changed:
                fn += 1

        if on_progress and (idx + 1) % log_every == 0:
            on_progress(
                f"[{condition_label}] {idx+1:,}/{total:,} events processed "
                f"| TP={tp} FP={fp}"
            )

    scenarios = list(MITRE_SCENARIOS.keys())
    detection_per_sc = {}
    mttd_per_sc      = {}
    for sc in scenarios:
        if sc in first_detect:
            detection_per_sc[sc] = 1
            mttd_per_sc[sc] = round(
                (first_detect[sc] - attack_start.get(sc, first_detect[sc]))
                / max(1, events_per_hour), 2
            )
        elif sc in attack_start:
            detection_per_sc[sc] = 0
            mttd_per_sc[sc]      = None
        else:
            detection_per_sc[sc] = None
            mttd_per_sc[sc]      = None

    det_total    = sum(1 for v in detection_per_sc.values() if v == 1)
    det_possible = sum(1 for v in detection_per_sc.values() if v is not None)
    fpr_per_10k  = round(fp / max(1, benign_total) * 10_000, 2)

    result = {
        "detection_rate":   round(det_total / max(1, det_possible), 4),
        "fpr_per_10k":      fpr_per_10k,
        "precision":        round(tp / max(1, tp + fp), 4),
        "detection_per_sc": detection_per_sc,
        "mttd_per_sc":      mttd_per_sc,
    }

    if on_progress:
        on_progress(
            f"[{condition_label}] complete — detection={result['detection_rate']*100:.1f}% "
            f"FPR/10K={result['fpr_per_10k']} precision={result['precision']*100:.1f}%"
        )

    return result


def run_comparison(n_users: int = 20, days: int = 30, seed: int = 42,
                    on_progress=None) -> dict:
    """
    n_users=20, days=30 gives fast results (~3 min on laptop).
    All 8 attack scenarios are still represented because assignment
    spreads victims evenly across the user list.

    on_progress: optional callable(str) invoked with human-readable
    status lines as the run proceeds — lets a caller (e.g. the FastAPI
    background task) stream live progress to the frontend instead of
    the UI sitting on a blank spinner for the full run.
    """
    sim     = CloudTrailSimulator(n_users=n_users, seed=seed)
    scorers = {}

    if on_progress:
        on_progress(f"Training {n_users} Isolation Forests (synthetic baseline, 14 days/user)…")

    for u in sim.users:
        bl         = sim.generate_baseline(u, days=14)
        ct_records = [e.to_cloudtrail_dict() for e in bl]
        bl_events  = load_cloudtrail_records(ct_records, user_id_override=u.user_id)
        for ev in bl_events: ev["role"] = u.role
        sc         = AnomalyScorer(seed=seed)
        sc.fit(bl_events, role=u.role)
        scorers[u.user_id] = sc

    if on_progress:
        on_progress(f"Baseline training complete — {n_users} models ready")
        on_progress("Starting Condition A — static parameters, no adversary")

    cond_a = _run_one(sim, scorers, use_adversary=False, use_ucb=False, days=days, seed=seed,
                       condition_label="A", on_progress=on_progress)

    if on_progress:
        on_progress("Starting Condition B — static parameters + pacing adversary")

    cond_b = _run_one(sim, scorers, use_adversary=True,  use_ucb=False, days=days, seed=seed,
                       condition_label="B", on_progress=on_progress)

    if on_progress:
        on_progress("Starting Condition C — UCB adaptive parameters + pacing adversary")

    cond_c = _run_one(sim, scorers, use_adversary=True,  use_ucb=True,  days=days, seed=seed,
                       condition_label="C", on_progress=on_progress)

    if on_progress:
        on_progress("Building per-scenario detection and MTTD tables…")

    scenarios = list(MITRE_SCENARIOS.keys())
    table_detection, table_mttd = [], []
    for sc in scenarios:
        label, tactic = SCENARIO_LABELS.get(sc, (sc, "—"))
        table_detection.append({
            "scenario": label, "tactic": tactic,
            "A": cond_a["detection_per_sc"].get(sc),
            "B": cond_b["detection_per_sc"].get(sc),
            "C": cond_c["detection_per_sc"].get(sc),
        })
        table_mttd.append({
            "scenario": label, "tactic": tactic,
            "A": cond_a["mttd_per_sc"].get(sc),
            "B": cond_b["mttd_per_sc"].get(sc),
            "C": cond_c["mttd_per_sc"].get(sc),
        })

    if on_progress:
        on_progress("Analysis complete.")

    return {
        "summary": [
            {"label": "A — Static λ/ρ, no adversary (Paper 1 baseline)",
             **{k: cond_a[k] for k in ("detection_rate","fpr_per_10k","precision")}},
            {"label": "B — Static λ/ρ + pacing adversary (evasion attack)",
             **{k: cond_b[k] for k in ("detection_rate","fpr_per_10k","precision")}},
            {"label": "C — UCB adaptive λ/ρ + pacing adversary (Paper 2)",
             **{k: cond_c[k] for k in ("detection_rate","fpr_per_10k","precision")}},
        ],
        "table_detection": table_detection,
        "table_mttd":      table_mttd,
    }