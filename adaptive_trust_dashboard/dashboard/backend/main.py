"""
main.py — Unified ZT Trust Engine backend.
One system. UCB adaptive parameters always active.
Adversary mode toggleable. Comparison on demand.

Real AWS CloudTrail Integration:
  - 7 IAM users (developer, data-analyst, security-admin, devops,
    finance, hr, executive) generated real logs from a live AWS account
  - Per-role baseline: each simulated user trains on real logs from
    the matching IAM user role
  - Fallback to synthetic if real logs not available for a role
"""

import asyncio
import os
import time
from contextlib import asynccontextmanager
from datetime import datetime
from typing import Optional

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from simulator import CloudTrailSimulator, MITRE_SCENARIOS
from feature_encoder import FeatureEncoder, get_user_id, get_action
from anomaly_scorer import AnomalyScorer
from trust_engine import TrustEngineManager
from adversary import AdversaryConfig
from comparison import run_comparison
from cloudtrail_loader import load_cloudtrail_directory, load_cloudtrail_records


# ── Role to IAM username mapping ──────────────────────────────────────────────
# Maps simulation role names to real IAM usernames in CloudTrail logs

ROLE_TO_IAM = {
    "developer":      "developer",
    "data_analyst":   "data-analyst",
    "security_admin": "security-admin",
    "devops":         "devops",
    "finance":        "finance",
    "hr":             "hr",
    "executive":      "executive",
}


# ── Global state ──────────────────────────────────────────────────────────────

class AppState:
    def __init__(self):
        self.sim: Optional[CloudTrailSimulator] = None
        self.scorers:         dict[str, AnomalyScorer] = {}
        self.engine           = TrustEngineManager(use_adaptive_ucb=True)
        self.all_events:      list[dict] = []
        self.processed_idx:   int  = 0
        self.is_initialised:  bool = False
        self.is_running:      bool = False
        self.ws_clients:      list[WebSocket] = []
        self.metrics:         dict = {}
        self.labelled_events: list = []
        self.scenario_start:  dict = {}
        self.scenario_detect: dict = {}
        self.comparison_results: Optional[dict] = None
        self.comparison_running: bool = False
        self.real_log_count:  int  = 0

state = AppState()


@asynccontextmanager
async def lifespan(app: FastAPI):
    yield


app = FastAPI(title="ZT Trust Engine — Unified", lifespan=lifespan)
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])


# ── Helpers ───────────────────────────────────────────────────────────────────

def _is_valid_real_event(ev: dict) -> bool:
    """Filter to keep only genuine IAM user events."""
    uid    = ev.get("user_id", "")
    action = ev.get("action", "")
    source = ev.get("source_ip", "")

    if not uid or not action:
        return False
    if source.endswith(".amazonaws.com"):
        return False
    if uid.isdigit() and len(uid) == 12:
        return False
    if ":" in uid:
        return False
    if uid == "unknown":
        return False

    skip_prefixes = [
        "billingconsole:", "mapcredits:", "payments:", "tax:",
        "uxc:", "notifications:", "freetier:", "bcm-",
        "cost-optimization-hub:", "resource-explorer-2:",
    ]
    if any(action.startswith(s) for s in skip_prefixes):
        return False

    return True


def _load_real_logs_per_role(real_logs_path: str) -> dict[str, list[dict]]:
    """
    Load real CloudTrail logs and group by IAM username.
    Returns dict: role_name → list of events for that role.
    """
    all_events  = load_cloudtrail_directory(real_logs_path)
    valid_events = [e for e in all_events if _is_valid_real_event(e)]

    # Group by IAM username
    by_iam_user: dict[str, list[dict]] = {}
    for ev in valid_events:
        uid = ev.get("user_id", "")
        if uid not in by_iam_user:
            by_iam_user[uid] = []
        by_iam_user[uid].append(ev)

    # Map IAM username back to simulation role name
    by_role: dict[str, list[dict]] = {}
    for role, iam_user in ROLE_TO_IAM.items():
        if iam_user in by_iam_user:
            by_role[role] = by_iam_user[iam_user]
            print(f"[REAL LOGS] {role:15s} → IAM user '{iam_user}': "
                  f"{len(by_role[role])} events")
        else:
            print(f"[REAL LOGS] {role:15s} → no real logs found, will use synthetic")

    return by_role


# ── WebSocket broadcast ───────────────────────────────────────────────────────

async def broadcast(payload: dict):
    dead = []
    for ws in state.ws_clients:
        try:
            await ws.send_json(payload)
        except Exception:
            dead.append(ws)
    for ws in dead:
        if ws in state.ws_clients:
            state.ws_clients.remove(ws)


# ── Request schemas ───────────────────────────────────────────────────────────

class StepRequest(BaseModel):
    n_events: int = 100

class AttackRequest(BaseModel):
    scenario: str

class ModeRequest(BaseModel):
    adaptive_ucb: bool = True
    adversary:    bool = False


# ── Status ────────────────────────────────────────────────────────────────────

@app.get("/api/status")
def status():
    return {
        "is_initialised":     state.is_initialised,
        "is_running":         state.is_running,
        "total_events":       len(state.all_events),
        "processed_events":   state.processed_idx,
        "progress_pct":       round(100 * state.processed_idx / max(1, len(state.all_events)), 1),
        "adaptive_ucb":       state.engine._use_adaptive_ucb,
        "adversary_enabled":  state.engine.adversary_enabled,
        "comparison_ready":   state.comparison_results is not None,
        "comparison_running": state.comparison_running,
        "real_log_count":     state.real_log_count,
        "timestamp":          datetime.utcnow().isoformat(),
    }


# ── Initialisation ────────────────────────────────────────────────────────────

@app.post("/api/simulation/init")
async def init_simulation():
    if state.is_running:
        raise HTTPException(400, "Simulation already running — stop it first")

    state.processed_idx        = 0
    state.labelled_events      = []
    state.scenario_start       = {}
    state.scenario_detect      = {}
    state.scorers              = {}
    state.metrics              = {}
    state.real_log_count       = 0
    state.real_events_per_role = {}
    state.engine               = TrustEngineManager(use_adaptive_ucb=True)
    state.sim                  = CloudTrailSimulator(n_users=20, seed=42)

    for user in state.sim.users:
        state.engine.register_user(user.user_id, user.role)

    # ── Load real AWS CloudTrail logs per role ────────────────────────────
    # Real logs from 7 IAM users (developer, data-analyst, security-admin,
    # devops, finance, hr, executive) provide genuine AWS activity patterns.
    # Combined with synthetic events for full role coverage.
    # Laptop IP (106.192.x.x) and CloudShell IP (44.204.x.x) treated as
    # trusted internal IPs to prevent feature mismatch with simulation.
    real_by_role = {}
    real_logs_path = os.path.join(os.path.dirname(__file__), "real_logs")
    if os.path.exists(real_logs_path):
        print(f"[REAL LOGS] Loading from real_logs/...")
        real_by_role = _load_real_logs_per_role(real_logs_path)
        total_real   = sum(len(v) for v in real_by_role.values())
        state.real_log_count = total_real
        print(f"[REAL LOGS] {total_real} valid events across {len(real_by_role)} roles")
    else:
        print("[REAL LOGS] No real_logs/ folder — using synthetic baseline only")

    # ── Train per-user Isolation Forests (hybrid baseline) ────────────────
    print(f"[INIT] Training {len(state.sim.users)} Isolation Forests...")
    for user in state.sim.users:
        synthetic_bl     = state.sim.generate_baseline(user, days=14)
        synthetic_events = [e.to_cloudtrail_dict() for e in synthetic_bl]
        role_real_events = real_by_role.get(user.role, [])
        if role_real_events:
            combined = role_real_events + synthetic_events
            print(f"[BASELINE] {user.user_id} ({user.role}): "
                  f"{len(role_real_events)} real + {len(synthetic_events)} synthetic")
        else:
            combined = synthetic_events
        scorer = AnomalyScorer(seed=42)
        scorer.fit(combined, role=user.role)
        state.scorers[user.user_id] = scorer

    # ── Generate 30-day trace in real CloudTrail format ───────────────────
    raw              = state.sim.generate_full_trace(days=30)
    state.all_events = [e.to_cloudtrail_dict() for e in raw]

    for user in state.sim.users:
        if user.attack_scenario and user.attack_start_day is not None:
            state.scenario_start[user.attack_scenario] = user.attack_start_day * 24

    state.is_initialised = True
    print(f"[INIT] Ready: {len(state.sim.users)} users, "
          f"{len(state.all_events)} events, "
          f"{len(state.scenario_start)} scenarios, "
          f"{state.real_log_count} real log events used in baseline")

    return {
        "ok":                  True,
        "users":               len(state.sim.users),
        "events":              len(state.all_events),
        "scenarios":           list(state.scenario_start.keys()),
        "real_log_count":      state.real_log_count,
        "baseline_source":     "hybrid_per_role" if real_by_role else "synthetic_only",
    }


# ── Step ──────────────────────────────────────────────────────────────────────

@app.post("/api/simulation/step")
async def step_simulation(req: StepRequest):
    if not state.is_initialised:
        raise HTTPException(400, "Not initialised")

    results = []
    end = min(state.processed_idx + req.n_events, len(state.all_events))

    for i in range(state.processed_idx, end):
        ev      = state.all_events[i]
        uid            = get_user_id(ev)
        recent_count   = state.engine.get_action_velocity(uid, get_action(ev))
        s              = state.scorers[uid].score(ev, recent_action_count=recent_count) if uid in state.scorers else 0.0
        reasons        = state.scorers[uid].top_features(ev, recent_action_count=recent_count) if uid in state.scorers else []
        result  = state.engine.process_event(ev, s, i, reasons)
        state.labelled_events.append((ev, s, ev.get("is_attack", False)))
        sc = ev.get("attack_scenario")
        if sc and result["zone"] in ("read_only", "quarantine") and sc not in state.scenario_detect:
            state.scenario_detect[sc] = i
        results.append(result)

    state.processed_idx = end
    _refresh_metrics()

    await broadcast({
        "type":           "step",
        "processed":      state.processed_idx,
        "total":          len(state.all_events),
        "alerts":         state.engine.get_alerts(5),
        "users_snapshot": state.engine.get_all_states(),
        "metrics":        state.metrics,
    })
    return {
        "events_processed": len(results),
        "total_processed":  state.processed_idx,
        "results":          results[-10:],
    }


@app.post("/api/simulation/run")
async def run_simulation(background_tasks: BackgroundTasks):
    if not state.is_initialised:
        raise HTTPException(400, "Not initialised")
    if state.is_running:
        raise HTTPException(400, "Already running")
    background_tasks.add_task(_run_full_bg)
    return {"ok": True}


async def _run_full_bg():
    state.is_running = True
    batch = 1000
    while state.processed_idx < len(state.all_events):
        end = min(state.processed_idx + batch, len(state.all_events))
        for i in range(state.processed_idx, end):
            ev      = state.all_events[i]
            uid          = get_user_id(ev)
            recent_count = state.engine.get_action_velocity(uid, get_action(ev))
            s            = state.scorers[uid].score(ev, recent_action_count=recent_count) if uid in state.scorers else 0.0
            reasons      = state.scorers[uid].top_features(ev, recent_action_count=recent_count) if uid in state.scorers else []
            result  = state.engine.process_event(ev, s, i, reasons)
            state.labelled_events.append((ev, s, ev.get("is_attack", False)))
            sc = ev.get("attack_scenario")
            if sc and result["zone"] in ("read_only", "quarantine") and sc not in state.scenario_detect:
                state.scenario_detect[sc] = i

        state.processed_idx = end
        _refresh_metrics()
        print(f"Processed {state.processed_idx}/{len(state.all_events)} | "
              f"Alerts: {len(state.engine.get_alerts(200))} | "
              f"AUC: {state.metrics.get('auc', '—')}")
        await broadcast({
            "type":           "progress",
            "processed":      state.processed_idx,
            "total":          len(state.all_events),
            "users_snapshot": state.engine.get_all_states(),
            "alerts":         state.engine.get_alerts(5),
            "metrics":        state.metrics,
        })
        await asyncio.sleep(0.001)

    state.is_running = False
    await broadcast({"type": "done", "metrics": state.metrics})


# ── Mode control ──────────────────────────────────────────────────────────────

@app.post("/api/mode")
async def set_mode(req: ModeRequest):
    state.engine.set_adaptive_mode(req.adaptive_ucb)
    if req.adversary:
        state.engine.enable_adversary()
    else:
        state.engine.disable_adversary()
    await broadcast({"type": "mode_change",
                     "adaptive_ucb": req.adaptive_ucb,
                     "adversary": req.adversary})
    return {"ok": True, "adaptive_ucb": req.adaptive_ucb, "adversary": req.adversary}


# ── User queries ──────────────────────────────────────────────────────────────

@app.get("/api/users")
def get_users():
    return state.engine.get_all_states()


@app.get("/api/users/{uid}")
def get_user(uid: str):
    s = state.engine.get_user_state(uid)
    if not s:
        raise HTTPException(404, f"User {uid} not found")
    ts = state.engine._states.get(uid)
    s["history"] = ts.history if ts else []
    s["ucb"]     = state.engine.get_ucb_state(uid)
    return s


@app.get("/api/alerts")
def get_alerts(limit: int = 50):
    return state.engine.get_alerts(limit)


@app.get("/api/metrics")
def get_metrics():
    _refresh_metrics()
    return state.metrics


@app.get("/api/ucb-summary")
def ucb_summary():
    return state.engine.get_all_ucb_summary()


# ── Real log info ─────────────────────────────────────────────────────────────

@app.get("/api/real-logs/info")
def real_logs_info():
    real_logs_path = os.path.join(os.path.dirname(__file__), "real_logs")
    if not os.path.exists(real_logs_path):
        return {"available": False, "event_count": 0, "file_count": 0}
    files = sorted([f for f in os.listdir(real_logs_path)
                    if f.endswith(".json.gz") or f.endswith(".json")])
    return {
        "available":            True,
        "event_count":          state.real_log_count,
        "file_count":           len(files),
        "iam_user_mapping":     ROLE_TO_IAM,
    }


# ── Attack injection ──────────────────────────────────────────────────────────

@app.post("/api/attack/{uid}")
async def inject_attack(uid: str, req: AttackRequest):
    if not state.is_initialised:
        raise HTTPException(400, "Not initialised")
    if req.scenario not in MITRE_SCENARIOS:
        raise HTTPException(400, f"Unknown scenario. Valid: {list(MITRE_SCENARIOS)}")

    cfg   = MITRE_SCENARIOS[req.scenario]
    role  = (state.engine.get_user_state(uid) or {}).get("role", "unknown")
    parts = cfg["action"].split(":")
    svc   = parts[0] if len(parts) > 1 else "unknown"
    name  = parts[1] if len(parts) > 1 else cfg["action"]

    ct_record = {
        "eventVersion":  "1.08",
        "userIdentity":  {"type": "IAMUser", "userName": uid, "accountId": "123456789012"},
        "eventTime":     datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
        "eventSource":   f"{svc}.amazonaws.com",
        "eventName":     name,
        "awsRegion":     "us-east-1",
        "sourceIPAddress": "203.0.113.42",
        "userAgent":     "curl/7.81.0",
        "eventID":       f"manual_{int(time.time())}",
        "readOnly":      False,
        "eventType":     "AwsApiCall",
        "is_attack":     True,
        "attack_scenario": req.scenario,
        "role":          role,
    }
    parsed = load_cloudtrail_records([ct_record], user_id_override=uid)
    ev = parsed[0] if parsed else {}
    ev["is_attack"]       = True
    ev["attack_scenario"] = req.scenario
    ev["role"]            = role

    scorer  = state.scorers.get(uid)
    s       = scorer.score(ev) if scorer else 1.0
    reasons = scorer.top_features(ev) if scorer else [f"Manual: {req.scenario}"]
    result  = state.engine.process_event(ev, s, state.processed_idx, reasons)
    _refresh_metrics()
    await broadcast({"type": "attack", "result": result})
    return result


# ── Comparison ────────────────────────────────────────────────────────────────

@app.post("/api/comparison/run")
async def run_comparison_api(background_tasks: BackgroundTasks):
    if state.comparison_running:
        raise HTTPException(400, "Comparison already running")
    state.comparison_running = True
    background_tasks.add_task(_comparison_bg)
    return {"ok": True, "message": "Running 3-condition comparison — watch /ws"}


async def _comparison_bg():
    try:
        loop   = asyncio.get_event_loop()
        result = await loop.run_in_executor(
            None, lambda: run_comparison(n_users=20, days=30, seed=42)
        )
        state.comparison_results = result
        await broadcast({"type": "comparison_done", "summary": result["summary"]})
    finally:
        state.comparison_running = False


@app.get("/api/comparison/results")
def get_comparison():
    if not state.comparison_results:
        raise HTTPException(404, "No comparison results yet")
    return state.comparison_results


# ── WebSocket ─────────────────────────────────────────────────────────────────

@app.websocket("/ws")
async def ws_endpoint(ws: WebSocket):
    await ws.accept()
    state.ws_clients.append(ws)
    try:
        await ws.send_json({
            "type":           "init",
            "is_initialised": state.is_initialised,
            "users":          state.engine.get_all_states(),
            "alerts":         state.engine.get_alerts(20),
            "metrics":        state.metrics,
        })
        while True:
            await ws.receive_text()
    except WebSocketDisconnect:
        pass
    finally:
        if ws in state.ws_clients:
            state.ws_clients.remove(ws)


# ── Internal ──────────────────────────────────────────────────────────────────

def _refresh_metrics():
    if not state.labelled_events:
        return
    base = state.engine.compute_metrics(state.labelled_events)
    state.metrics = {
        **base,
        "total_events":       state.processed_idx,
        "total_alerts":       len(state.engine.get_alerts(200)),
        "scenarios_detected": len(state.scenario_detect),
        "scenarios_total":    len(state.scenario_start),
        "adaptive_ucb":       state.engine._use_adaptive_ucb,
        "adversary_enabled":  state.engine.adversary_enabled,
        "real_log_count":     state.real_log_count,
    }
