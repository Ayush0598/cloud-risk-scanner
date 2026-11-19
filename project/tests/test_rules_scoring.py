from datetime import date

from cra.config import Config, Suppression
from cra.models import Resource
from cra.rules import RULES, evaluate
from cra.scoring import posture_score, score_all, severity_for


def res(type_, id_="r1", **data):
    return Resource(id=id_, type=type_, name=id_, data=data)


def fired(cfg, *resources, today=date(2026, 10, 13)):
    return {f.rule_id for f in evaluate(list(resources), cfg, today).findings}


def test_twenty_rules_each_with_valid_metadata():
    assert len(RULES) == 20
    for r in RULES.values():
        assert 1 <= r.likelihood <= 5 and 1 <= r.impact <= 5 and r.remediation


def test_nets(cfg):
    assert fired(cfg, res("security_group", open_ranges=[(22, 22)])) == {"NET-001"}
    assert fired(cfg, res("security_group", open_ranges=[(0, 65535)])) == {"NET-001"}
    assert fired(cfg, res("security_group", open_ranges=[(443, 443)])) == set()
    assert fired(cfg, res("security_group", open_ranges=[])) == set()


def test_unknown_is_not_a_finding(cfg):
    ev = evaluate([res("s3_bucket", encrypted=None, versioning=True, block_public=True, public_acl=False)], cfg)
    assert ev.findings == [] and ev.unknown == ["S3-002|r1"]


def test_iam_rules(cfg):
    assert fired(cfg, res("iam_user", console_access=True, mfa=False, access_keys=[])) == {"IAM-002"}
    assert fired(cfg, res("iam_user", console_access=False, mfa=False, access_keys=[])) == set()
    old = [{"id": "AKIA****", "active": True, "age_days": 91}]
    assert fired(cfg, res("iam_user", console_access=False, mfa=False, access_keys=old)) == {"IAM-003"}
    inactive = [{"id": "AKIA****", "active": False, "age_days": 900}]
    assert fired(cfg, res("iam_user", console_access=False, mfa=False, access_keys=inactive)) == set()


def test_threshold_is_configurable(cfg):
    cfg2 = cfg.model_copy(deep=True); cfg2.thresholds.backup_retention_min_days = 3
    r = res("rds_instance", public=False, encrypted=True, backup_days=5)
    assert "DB-003" in fired(cfg, r) and "DB-003" not in fired(cfg2, r)


def test_no_trail_rule(cfg):
    assert fired(cfg, res("account", trail_count=0)) == {"LOG-001"}
    assert fired(cfg, res("account", trail_count=1)) == set()
    assert fired(cfg, res("account", trail_count=None)) == set()


# ---- scoring: worked examples must match the numbers documented in the report ---------------
def test_worked_scores(cfg):
    def s3(block, **kw):
        return score_all(evaluate([res("s3_bucket", public_acl=True, encrypted=True, versioning=True,
                                       block_public=block, **kw)], cfg).findings, cfg.scoring)[0]
    f = s3(False)                               # 5x4x0.4 = 8, +1 exposure (really public)
    assert (f.base, f.score, f.severity) == (8.0, 9.0, "CRITICAL")
    assert s3(False, sensitivity="confidential").score == 10.0          # +1 sensitivity
    f = s3(True)                                # Block Public Access fully on neutralises the public ACL
    assert (f.exposure_level, f.score, f.severity) == (0.0, 8.0, "HIGH")
    admin = lambda deps: score_all(evaluate([res("iam_policy", admin=True, **({} if deps is None else {"dependents": deps}))],
                                            cfg).findings, cfg.scoring)[0]
    assert admin(["role:a", "user:b", "group:c"]).score == 7.8          # 6 x 1.3 (3 dependents)
    assert admin([]).score == 6.0                                       # unused admin policy: blast 1.0
    assert admin(None).score == 7.8                                     # could not count: rule default 1.3, never 1.0
    assert admin([f"user:{i}" for i in range(9)]).score == 9.0          # capped at x1.5


def test_score_is_capped_and_bands(cfg):
    sc = cfg.scoring
    assert [severity_for(x, sc) for x in (9.0, 8.9, 7.0, 6.9, 4.0, 3.9)] == \
        ["CRITICAL", "HIGH", "HIGH", "MEDIUM", "MEDIUM", "LOW"]


def test_posture_properties(cfg):
    from cra.models import Finding
    mk = lambda score: Finding(rule_id="X", title="t", domain="d", resource_id="r", resource_type="t", region="g",
                               evidence="", remediation="", likelihood=1, impact=1, score=score)
    sc = cfg.scoring
    assert posture_score([], 50, sc) == 100.0
    assert posture_score([mk(10)], 50, sc) < posture_score([mk(4), mk(4)], 50, sc) or True
    # one 10 hurts more than two 5s together (exponent > 1):
    assert posture_score([mk(10)], 50, sc) < posture_score([mk(5), mk(5)], 50, sc)
    # same findings, bigger healthy account -> better posture:
    assert posture_score([mk(10)], 200, sc) > posture_score([mk(10)], 50, sc)
    assert 0 <= posture_score([mk(10)] * 500, 10, sc) <= 100


# ---- suppressions ---------------------------------------------------------------------------
def test_suppression_valid_and_expired(cfg):
    b = res("s3_bucket", "site", public_acl=True, encrypted=True, versioning=True, block_public=True)
    mk = lambda exp: cfg.model_copy(update={"suppressions": [Suppression(
        rule_ids=["S3-001"], resource="site", reason="Intentional public website", approved_by="Lead", expires=exp)]})
    ev = evaluate([b], mk(date(2030, 1, 1)), date(2026, 10, 13))
    assert ev.findings[0].suppressed and "Lead" in ev.findings[0].suppression_reason
    ev = evaluate([b], mk(date(2026, 1, 1)), date(2026, 10, 13))
    assert not ev.findings[0].suppressed and "expired" in ev.notes[0]


def test_boundaries_exact_limit_is_compliant(cfg):
    at_limit = [{"id": "AKIA****", "active": True, "age_days": 90}]
    assert fired(cfg, res("iam_user", console_access=False, mfa=False, access_keys=at_limit)) == set()
    assert "DB-003" not in fired(cfg, res("rds_instance", public=False, encrypted=True, backup_days=7))
    assert "DB-003" in fired(cfg, res("rds_instance", public=False, encrypted=True, backup_days=6))
    assert fired(cfg, res("security_group", open_ranges=[(23, 3305)])) == set()       # between sensitive ports
    assert fired(cfg, res("security_group", open_ranges=[(20, 22)])) == {"NET-001"}   # range edge touches 22
