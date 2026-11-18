# paper_scale — raw results behind Paper 2

All runs are **50 identities / 90 days**, produced by
`run_paper_scale.py` (which calls `comparison.run_comparison`).

Every number quoted in the dissertation comes from these files. The
**restriction boundary (`trust_engine.ZONE_READ_ONLY`) is 0.55** unless the
filename says otherwise — FPR and detection rate both move with that boundary,
so a figure without a boundary is meaningless.

| File | What it is | Boundary |
|---|---|---|
| `seeds_50_90_thr55.json` | **Current.** 9 seeds, mean ± SD table plus every per-seed row. This is the file to quote. | 0.55 |
| `comp_50_90_seed42.json` | Single seed-42 run, full A/B/C summary + MTTD table + per-scenario detection. Matches what the dashboard displays. | 0.55 |
| `tbl_6.json`, `tbl_8.json` | Per-condition pair tables used to build the manuscript tables. | 0.55 |
| `SUPERSEDED_thr060_seeds_50_90.json` | Historical. Boundary 0.60. FPR ≈ 91–115 per 10k. **Do not quote.** | 0.60 |
| `SUPERSEDED_thr050_seeds_50_90.json` | Historical. Boundary 0.50. Kept only as the threshold-ablation evidence. | 0.50 |

## Why the superseded files are kept

They are the measured evidence for the threshold ablation
(`THRESHOLD_TEST_RESULTS.md`). Deleting them would remove the justification for
choosing 0.55, but quoting them as current results would overstate the false
positive rate by roughly a factor of two.

## Reproducing

From `adaptive_trust_dashboard/dashboard/backend`:

```
python ../../../../run_paper_scale.py --json out.json      # 9 seeds, ~60 s each
python ../../../../run_paper_scale.py --seeds 42 --json one.json
```

Seed 42 is the seed the live dashboard uses, so it is the one to compare
against anything on screen.
