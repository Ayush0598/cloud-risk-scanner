import json

import boto3

from cra.compliance import coverage, validate_mapping
from cra.evaluation import score_against_truth
from cra.pipeline import run_scan
from cra.reporting import render_html, to_dict
from cra.simulation import REGIONS, SIM_NOW, SIM_TODAY, build_account, fake_aws
from cra.storage import Store, compare_scans
from cra.auth import ScanSession


def test_ground_truth_perfect(scanned):
    truth, result, _ = scanned
    m = score_against_truth(result, truth)
    assert m.missed == [] and m.false_alarms == []
    assert (m.precision, m.recall) == (1.0, 1.0)
    assert {f.fingerprint for f in result.suppressed} == truth.suppressed


def test_scan_was_read_only(scanned):
    _, result, ss = scanned
    assert result.proof["all_read_only"] and result.proof["blocked_writes"] == 0
    assert not any(c.split(":")[1].startswith(("Create", "Put", "Delete", "Update")) for c in ss.calls)


def test_no_secret_values_in_outputs(scanned):
    _, result, _ = scanned
    blob = json.dumps(to_dict(result), default=str) + render_html(result)
    assert "hunter2" not in blob                 # EC2 user-data secret value
    assert "Passw0rd" not in blob                # database / console passwords
    assert "AKIA" not in blob or "AKIA****" in blob


def test_sensitive_bucket_gets_sensitivity_bonus(scanned):
    _, result, _ = scanned
    f = next(f for f in result.active if f.fingerprint == "S3-001|prod-customer-data")
    assert f.sensitivity == "confidential" and f.score == 10.0 and f.score_breakdown["sensitivity_bonus"] == 1.0


def test_standards_attached_and_mapping_complete(scanned, cfg):
    _, result, _ = scanned
    assert validate_mapping(cfg) == []
    f = next(f for f in result.active if f.rule_id == "NET-001")
    assert any(c.startswith("5.2") for c in f.standards["cis_aws_foundations"])
    assert coverage(result.findings, cfg)["cis_aws_foundations"]["failing_controls"]


def test_html_report(scanned):
    _, result, _ = scanned
    html = render_html(result)
    assert "Posture score" in html and "data:image/png;base64" in html and "prod-customer-data" in html


def test_deterministic(cfg):
    runs = []
    for _ in range(2):
        with fake_aws():
            build_account(boto3)
            r = run_scan(ScanSession(regions=REGIONS), cfg, now=SIM_NOW, today=SIM_TODAY)
            runs.append((r.posture, [f.fingerprint for f in r.findings]))
    # resource ids that moto generates differ between runs, so compare shape: score + rule sequence
    assert runs[0][0] == runs[1][0]
    assert [x.split("|")[0] for x in runs[0][1]] == [x.split("|")[0] for x in runs[1][1]]


def test_empty_account(cfg):
    with fake_aws():
        r = run_scan(ScanSession(regions=["us-east-1"]), cfg, now=SIM_NOW, today=SIM_TODAY)
    assert "LOG-001" in {f.rule_id for f in r.active}        # no trail at all is itself a finding


def test_history_and_drift(cfg):
    store = Store()
    with fake_aws():
        build_account(boto3)
        ss = lambda: ScanSession(regions=REGIONS)
        r1 = run_scan(ss(), cfg, now=SIM_NOW, today=SIM_TODAY)
        id1 = store.save_scan("****9012", r1.findings, r1.posture, r1.evaluation.checks_run, "before")
        s3 = boto3.client("s3")
        s3.put_bucket_versioning(Bucket="team-notes", VersioningConfiguration={"Status": "Enabled"})    # fix
        s3.create_bucket(Bucket="new-risky-bucket"); s3.put_bucket_acl(Bucket="new-risky-bucket", ACL="public-read")  # regress
        r2 = run_scan(ss(), cfg, now=SIM_NOW, today=SIM_TODAY)
        id2 = store.save_scan("****9012", r2.findings, r2.posture, r2.evaluation.checks_run, "after")
    drift = compare_scans(store.load_findings(id1), store.load_findings(id2))
    assert "S3-003|team-notes" in {f.fingerprint for f in drift["resolved"]}
    assert {"S3-001|new-risky-bucket"} <= {f.fingerprint for f in drift["new"]}
    assert len(store.history()) == 2
