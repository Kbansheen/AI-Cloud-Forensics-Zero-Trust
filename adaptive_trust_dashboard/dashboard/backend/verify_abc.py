"""One-seed A/B/C check at 50 users / 90 days. Must be unchanged by alerting work."""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from comparison import run_comparison
r = run_comparison(n_users=50, days=90, seed=42)
for row in r["summary"]:
    print("%-55s det=%.3f FPR/10K=%6.2f prec=%.3f AUC=%.4f" % (
        row["label"][:55], row["detection_rate"], row["fpr_per_10k"],
        row["precision"], row["auc"]))
