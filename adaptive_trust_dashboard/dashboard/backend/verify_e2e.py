"""End-to-end verification of the shipped dashboard path (50 users / 90 days).

Run from dashboard/backend:  python3 verify_e2e.py
Prints the headline numbers plus the alert-quality breakdown, so a change to
the alerting rule or the zone boundary can be checked in one command.
"""
import sys, os, collections, statistics as stx
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import trust_engine as TE
import main
from fastapi.testclient import TestClient

c = TestClient(main.app)
assert c.post("/api/simulation/init").status_code == 200
assert c.post("/api/simulation/run").status_code == 200

al = c.get("/api/alerts?limit=5000").json()
alerts = al["alerts"] if isinstance(al, dict) else al
met = c.get("/api/metrics").json()
users = c.get("/api/users").json()

att = [a for a in alerts if a.get("is_attack")]
ben = [a for a in alerts if not a.get("is_attack")]
print("\n================ e2e verification ================")
print("alerts      : %d  (attack %d / benign %d)" % (len(alerts), len(att), len(ben)))
print("benign share: %.1f%%" % (100 * len(ben) / max(1, len(alerts))))
print("worst user  : %d alerts" % max((collections.Counter(a["user_id"] for a in alerts).values()), default=0))
print("unique ids  : %s" % (len({a["alert_id"] for a in alerts}) == len(alerts)))
print("scenarios   : %d/%d" % (met["scenarios_detected"], met["scenarios_total"]))
print("AUC/FPR/prec: %s / %s / %s" % (met["auc"], met["fpr"], met["precision"]))
print("zones       : %s" % dict(collections.Counter(u["zone"] for u in users)))
print("alert zones : %s" % dict(collections.Counter(a["zone"] for a in alerts)))
print("transitions : %s" % dict(collections.Counter(
    "%s->%s" % (a.get("zone_from"), a.get("zone_to")) for a in alerts)))
print("zone_from on every alert: %s" % all(a.get("zone_from") for a in alerts))
print("attack alerts (user, ts, trust, score):")
for a in att:
    print("   %-10s %s  T=%.3f score=%.3f persisted=%s %s" % (
        a["user_id"], a["timestamp"], a["trust"], a["anomaly_score"],
        a.get("persisted"), a["action"]))
if ben:
    print("benign persisted-events histogram: %s" %
          dict(sorted(collections.Counter(a.get("persisted") for a in ben).items())))
print("=================================================")
