"""Compliance mapping: attach CIS / NIST CSF / ISO 27001 references to findings and report coverage.
The mapping lives in config/standards_map.yaml (its header says which entries are source-verified)."""
from __future__ import annotations

from .config import Config
from .models import Finding
from .rules import RULES

FRAMEWORKS = {"cis_aws_foundations": "CIS AWS Foundations v3.0.0", "nist_csf": "NIST CSF 1.1",
              "iso_27001": "ISO/IEC 27001:2022 Annex A"}


def attach_standards(findings: list[Finding], cfg: Config) -> list[Finding]:
    """Fill finding.standards with the CIS/NIST/ISO references listed for its rule."""
    rules = cfg.standards.get("rules", {})
    for f in findings:
        entry = rules.get(f.rule_id, {})
        f.standards = {fw: [f"{c['id']} {c['title']}" for c in entry.get(fw, [])] for fw in FRAMEWORKS}
    return findings


def validate_mapping(cfg: Config) -> list[str]:
    """Return problems: rules without a mapping entry, or mapping entries for unknown rules."""
    mapped = set(cfg.standards.get("rules", {}))
    problems = [f"rule {r} has no entry in standards_map.yaml" for r in sorted(set(RULES) - mapped)]
    problems += [f"standards_map.yaml mentions unknown rule {r}" for r in sorted(mapped - set(RULES))]
    return problems


def coverage(findings: list[Finding], cfg: Config) -> dict[str, dict]:
    """Per framework: how many of our rules map to it, and which controls currently FAIL."""
    rules = cfg.standards.get("rules", {})
    out = {}
    for fw, label in FRAMEWORKS.items():
        mapped_rules = [r for r in RULES if rules.get(r, {}).get(fw)]
        failing: dict[str, set[str]] = {}
        for f in findings:
            if f.suppressed:
                continue
            for ref in f.standards.get(fw, []):
                failing.setdefault(ref, set()).add(f.rule_id)
        out[fw] = {"label": label, "rules_mapped": len(mapped_rules), "rules_total": len(RULES),
                   "failing_controls": {k: sorted(v) for k, v in sorted(failing.items())}}
    return out
