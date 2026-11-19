"""Milestone 4 - final integrated demo, the same steps as Part B / Section 7 of the notebook.

Runs the whole system on the built-in simulated AWS account (no AWS account or credentials needed):
  1. one assess() call: authentication -> collector -> rules -> scoring -> compliance -> storage -> reports
  2. the data-flow table (what every layer received and produced)
  3. result, top findings and accuracy against the planted answer key
  4. a second scan after the cloud changes, to show drift (resolved / new findings)
Reports are written to the  reports/  folder (report.html, report.json, report.csv).
"""
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
os.chdir(HERE)
sys.path.insert(0, os.path.join(HERE, "src"))

import boto3  # noqa: E402

from cra.auth import ScanSession  # noqa: E402
from cra.config import load_config  # noqa: E402
from cra.evaluation import score_against_truth  # noqa: E402
from cra.pipeline import assess  # noqa: E402
from cra.simulation import REGIONS, SIM_NOW, SIM_TODAY, build_account, fake_aws  # noqa: E402
from cra.storage import Store  # noqa: E402


def line(title):
    print("\n" + "=" * 78 + "\n" + title + "\n" + "=" * 78)


def main():
    cfg = load_config("config")
    if os.path.exists("history.db"):
        os.remove("history.db")
    store = Store("sqlite:///history.db")

    with fake_aws():
        truth = build_account(boto3)

        line("SCAN 1 - the whole system in ONE call: assess()")
        r1, drift1, stages = assess(ScanSession(regions=REGIONS), cfg, store, "reports", "baseline", SIM_NOW, SIM_TODAY)
        print("DATA FLOW (every hand-off recorded):")
        for s in stages:
            print(f"  {s.layer:28s} in={s.items_in!s:>4}  out={s.items_out!s:>4}  {s.detail}")
        print(f"\nRESULT: posture {r1.posture}/100 | active findings {len(r1.active)} | suppressed {len(r1.suppressed)}"
              f" | checks run {r1.evaluation.checks_run}")
        print("Read-only proof:", r1.proof)
        print("\nTop 5 findings:")
        for f in sorted(r1.active, key=lambda f: -f.score)[:5]:
            print(f"  {f.score:>4} {f.severity:8s} {f.rule_id:8s} {(f.resource_name or f.resource_id)[:24]:24s}"
                  f" exposure={f.exposure_level} blast=x{f.blast}")
        m = score_against_truth(r1, truth)
        print(f"\nAccuracy vs the planted answer key: TP={m.tp} FP={m.fp} FN={m.fn}"
              f"  precision={m.precision:.2f} recall={m.recall:.2f}")

        line("The cloud changes: one problem fixed, one new risky bucket created")
        s3 = boto3.client("s3")
        s3.put_bucket_versioning(Bucket="team-notes", VersioningConfiguration={"Status": "Enabled"})
        s3.create_bucket(Bucket="new-risky-bucket")
        s3.put_bucket_acl(Bucket="new-risky-bucket", ACL="public-read")
        print("  fixed : versioning turned ON for team-notes")
        print("  new   : bucket new-risky-bucket made public-read")

        line("SCAN 2 - drift compared with scan 1 (storage layer)")
        r2, drift2, _ = assess(ScanSession(regions=REGIONS), cfg, store, "reports", "after-change", SIM_NOW, SIM_TODAY)
        print("  resolved  :", [f.fingerprint for f in drift2["resolved"]])
        print("  new       :", [f.fingerprint for f in drift2["new"]])
        print("  still open:", len(drift2["persisting"]))
        print(f"  posture   : {r1.posture} -> {r2.posture}")

    line("Scan history saved in history.db")
    for row in store.history():
        print(" ", row)
    print("\nReports written to:", os.path.abspath("reports"))
    for f in sorted(os.listdir("reports")):
        print(f"  {f:14s} {os.path.getsize(os.path.join('reports', f)):>8} bytes")
    print("\nOpen reports/report.html in a browser to see the full report. Done.")


if __name__ == "__main__":
    main()
