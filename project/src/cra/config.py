"""Configuration: PyYAML reads the files, pydantic validates them.
Thresholds, scoring weights, suppressions and the standards map all live in config/ so they
can be tuned without touching code."""
from __future__ import annotations

import datetime as dt
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, Field, field_validator


class Thresholds(BaseModel):
    """Tunable limits used by rules (key age, backup retention, sensitive ports)."""
    access_key_max_age_days: int = Field(90, gt=0)
    backup_retention_min_days: int = Field(7, ge=0)
    sensitive_ports: list[int] = Field(default_factory=lambda: [22, 3389, 3306, 5432])


class ScoringConfig(BaseModel):
    """All weights and bands of the scoring model; defaults match config/scoring.yaml."""
    scale_factor: float = 0.4
    exposure_bonus: float = 1.0
    no_logging_bonus: float = 0.5
    sensitivity_bonus: float = 1.0
    sensitivity_tag: str = "data-classification"
    sensitive_labels: list[str] = Field(default_factory=lambda: ["confidential", "restricted"])
    max_score: float = 10.0
    band_critical: float = 9.0
    band_high: float = 7.0
    band_medium: float = 4.0
    posture_exponent: float = 1.5
    posture_worst_case_factor: float = 0.25
    blast_per_dependent: float = Field(0.1, ge=0)   # blast multiplier grows by this per dependent
    blast_cap: float = Field(1.5, ge=1)             # ... but never above this


class Suppression(BaseModel):
    """A documented exception. Reason, approver and expiry are mandatory."""
    rule_ids: list[str]
    resource: str                       # resource id or name; shell-style wildcards allowed
    reason: str
    approved_by: str
    expires: dt.date

    @field_validator("resource")
    @classmethod
    def resource_must_be_specific(cls, v: str) -> str:
        """Block blanket exceptions such as '*' that would silence every resource with one line."""
        if len(v.strip().replace("*", "").replace("?", "")) < 3:
            raise ValueError("a suppression must name a specific resource (wildcards alone are not allowed)")
        return v.strip()

    @field_validator("rule_ids")
    @classmethod
    def rules_must_exist(cls, v: list[str]) -> list[str]:
        """A typo in a rule id would make the exception silently do nothing - fail loudly instead."""
        from .rules import RULES            # imported here to avoid a circular import
        unknown = [r for r in v if r not in RULES]
        if unknown or not v:
            raise ValueError(f"unknown rule id(s) in suppression: {unknown or 'empty list'}")
        return v

    @field_validator("reason")
    @classmethod
    def reason_must_be_meaningful(cls, v: str) -> str:
        """Reject one-word reasons: an exception must be explained."""
        if len(v.strip()) < 10:
            raise ValueError("a suppression needs a real reason (at least 10 characters)")
        return v

    @field_validator("approved_by")
    @classmethod
    def approver_required(cls, v: str) -> str:
        """Reject exceptions with no named approver."""
        if not v.strip():
            raise ValueError("a suppression needs an approver")
        return v


class Config(BaseModel):
    """Everything the scanner needs, loaded and validated once at start-up."""
    thresholds: Thresholds = Field(default_factory=Thresholds)
    scoring: ScoringConfig = Field(default_factory=ScoringConfig)
    suppressions: list[Suppression] = Field(default_factory=list)
    standards: dict[str, Any] = Field(default_factory=dict)
    source_dir: str = ""


def _read(path: Path) -> dict:
    """Read one YAML file with yaml.safe_load (cannot execute code); a missing file gives {}."""
    if not path.exists():
        return {}
    with path.open(encoding="utf-8") as fh:
        return yaml.safe_load(fh) or {}


def load_config(config_dir: str | Path = "config") -> Config:
    """Load and validate every config file. Missing files fall back to safe defaults;
    invalid values raise a pydantic ValidationError immediately."""
    d = Path(config_dir)
    sup = []
    for item in _read(d / "suppressions.yaml").get("suppressions", []):
        item = dict(item)
        if "rule_id" in item:                      # accept a single id or a list
            item["rule_ids"] = [item.pop("rule_id")]
        sup.append(Suppression(**item))
    return Config(
        thresholds=Thresholds(**_read(d / "thresholds.yaml")),
        scoring=ScoringConfig(**_read(d / "scoring.yaml")),
        suppressions=sup,
        standards=_read(d / "standards_map.yaml"),
        source_dir=str(d),
    )
