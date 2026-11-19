"""Integration tests: do the layers work TOGETHER? Each test checks a hand-off between layers
or a behaviour that only exists because several layers cooperate."""
import json

import boto3

from cra.auth import ScanSession
from cra.models import Finding, Resource
from cra.pipeline import assess, run_traced
from cra.simulation import REGIONS, SIM_NOW, SIM_TODAY, build_account, fake_aws
from cra.storage import Store


def test_stage_order_and_types(scanned):
    _, result, _ = scanned
    assert all(isinstance(r, Resource) for r in result.inventory)          # collector -> rules contract
    assert all(isinstance(f, Finding) for f in result.findings)            # rules -> scoring contract
    assert all(f.severity and f.score_breakdown for f in result.findings)  # scoring filled its fields


def test_every_stage_recorded_in_order(cfg):
    with fake_aws():
        build_account(boto3)
        result, stages = run_traced(ScanSession(regions=REGIONS), cfg, SIM_NOW, SIM_TODAY)
    assert [s.layer.split()[0] for s in stages] == ["1", "2", "3", "4", "5a"]
    assert stages[1].items_out == len(result.inventory)
    assert stages[2].items_out == stages[3].items_in == len(result.findings)   # nothing lost between layers


def test_assess_end_to_end_writes_everything(cfg, tmp_path):
    store = Store(f"sqlite:///{tmp_path/'h.db'}")
    with fake_aws():
        build_account(boto3)
        result, drift, stages = assess(ScanSession(regions=REGIONS), cfg, store, str(tmp_path / "out"), "t", SIM_NOW, SIM_TODAY)
    assert drift is None                                           # first scan has no baseline
    assert [s.layer.split()[0] for s in stages][-2:] == ["5b", "5c"]
    assert {p.name for p in (tmp_path / "out").iterdir()} == {"report.html", "report.json", "report.csv"}
    assert store.history()[0]["active"] == len(result.active)
    data = json.loads((tmp_path / "out" / "report.json").read_text())
    assert len(data["findings"]) == len(result.findings)           # report == scan result


def test_second_assess_reports_drift(cfg, tmp_path):
    store = Store(f"sqlite:///{tmp_path/'h.db'}")
    with fake_aws():
        build_account(boto3)
        assess(ScanSession(regions=REGIONS), cfg, store, None, "a", SIM_NOW, SIM_TODAY)
        boto3.client("s3").put_bucket_versioning(Bucket="team-notes", VersioningConfiguration={"Status": "Enabled"})
        _, drift, _ = assess(ScanSession(regions=REGIONS), cfg, store, None, "b", SIM_NOW, SIM_TODAY)
    assert [f.fingerprint for f in drift["resolved"]] == ["S3-003|team-notes"] and drift["new"] == []


def test_denied_service_flows_through_all_layers(cfg):
    """collector note -> rule engine sees no RDS -> no DB findings -> report notes mention it."""
    with fake_aws():
        build_account(boto3)
        ss = ScanSession(regions=REGIONS); ss.simulate_denied("rds")
        result, _ = run_traced(ss, cfg, SIM_NOW, SIM_TODAY)
    assert not any(f.rule_id.startswith("DB-") for f in result.findings)
    assert any("RDS" in n for n in result.notes)
    assert result.proof["all_read_only"]


def test_config_change_flows_to_findings_and_score(cfg):
    stricter = cfg.model_copy(deep=True); stricter.thresholds.access_key_max_age_days = 250   # alice's key is 200 days old
    with fake_aws():
        build_account(boto3)
        base, _ = run_traced(ScanSession(regions=REGIONS), cfg, SIM_NOW, SIM_TODAY)
        loose, _ = run_traced(ScanSession(regions=REGIONS), stricter, SIM_NOW, SIM_TODAY)
    assert "IAM-003" in {f.rule_id for f in base.active} and "IAM-003" not in {f.rule_id for f in loose.active}
    assert loose.posture > base.posture


def test_one_bucket_traced_through_every_layer(scanned):
    _, result, _ = scanned
    res = next(r for r in result.inventory if r.id == "prod-customer-data")
    assert res.data["sensitivity"] == "confidential"                              # collected
    f = next(f for f in result.findings if f.fingerprint == "S3-001|prod-customer-data")   # detected
    assert f.score == 10.0 and f.severity == "CRITICAL"                           # scored with context
    assert f.standards["nist_csf"]                                                # mapped
    assert "prod-customer-data" in json.dumps([x.model_dump() for x in result.findings])    # reportable
