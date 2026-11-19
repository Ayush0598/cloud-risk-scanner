import pytest
from pydantic import ValidationError

from cra.config import Suppression, Thresholds


def test_defaults_loaded(cfg):
    assert cfg.thresholds.access_key_max_age_days == 90
    assert cfg.scoring.scale_factor == 0.4
    assert len(cfg.suppressions) == 2


def test_negative_threshold_rejected():
    with pytest.raises(ValidationError):
        Thresholds(access_key_max_age_days=-5)


def test_suppression_needs_real_reason_and_approver():
    ok = dict(rule_ids=["S3-001"], resource="site-bucket", reason="Intentional public website bucket", approved_by="Lead", expires="2030-01-01")
    Suppression(**ok)
    with pytest.raises(ValidationError):
        Suppression(**{**ok, "reason": "ok"})
    with pytest.raises(ValidationError):
        Suppression(**{**ok, "approved_by": " "})
    with pytest.raises(ValidationError):
        Suppression(**{k: v for k, v in ok.items() if k != "expires"})
