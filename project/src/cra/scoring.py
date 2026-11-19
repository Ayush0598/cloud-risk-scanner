"""Layer 4 - Risk scoring (separate from detection: rules say WHAT is wrong, this says HOW BAD).

  base      = likelihood x impact x scale_factor                    (0..10)
  blast     = min(blast_cap, 1 + blast_per_dependent x dependents)   when dependents were counted,
              otherwise the rule's fixed default (an unreadable count is never treated as zero)
  exposure  = exposure_bonus x exposure_level          (1.0 reachable, 0.5 partly, 0 not reachable)
  score     = base x blast + exposure + no_logging + sensitivity, capped at max_score
  severity  = band of the score (Critical >= 9, High >= 7, Medium >= 4, Low < 4)
  posture   = 100 - 100 * sum(score^p) / (checks_run * 10^p * worst_case_factor)    (clamped 0..100)
The exponent p > 1 makes one critical finding hurt more than several low ones, and dividing by
checks_run means a bigger, mostly-healthy account is not punished for its size.
Every number used is stored in finding.score_breakdown, so a score can be explained line by line."""
from __future__ import annotations

from .config import ScoringConfig
from .models import Finding


def severity_for(score: float, sc: ScoringConfig) -> str:
    """Map a 0-10 score to CRITICAL/HIGH/MEDIUM/LOW using the configured bands."""
    if score >= sc.band_critical: return "CRITICAL"
    if score >= sc.band_high: return "HIGH"
    if score >= sc.band_medium: return "MEDIUM"
    return "LOW"


def blast_multiplier(f: Finding, sc: ScoringConfig) -> float:
    """Counted blast radius: grows with the number of dependents, capped. Falls back to the rule default."""
    if f.dependents is None:
        return f.blast
    return round(min(sc.blast_cap, 1.0 + sc.blast_per_dependent * f.dependents), 2)


def score_finding(f: Finding, sc: ScoringConfig) -> Finding:
    """Apply the scoring formula to one finding and store the full breakdown on it."""
    base = f.likelihood * f.impact * sc.scale_factor
    f.blast = blast_multiplier(f, sc)
    scaled = base * f.blast
    level = f.exposure_level if f.exposure_level else (1.0 if f.exposure else 0.0)   # old-style flag = full
    exposure = round(sc.exposure_bonus * level, 2)
    nolog = sc.no_logging_bonus if f.no_logging else 0.0
    sens = sc.sensitivity_bonus if f.sensitivity else 0.0
    raw = scaled + exposure + nolog + sens
    f.base = round(base, 2)
    f.score = round(min(raw, sc.max_score), 1)
    f.severity = severity_for(f.score, sc)
    f.score_breakdown = {"base": round(base, 2), "dependents": f.dependents if f.dependents is not None else -1,
                         "blast_multiplier": f.blast, "after_blast": round(scaled, 2),
                         "exposure_level": level, "exposure_bonus": exposure, "no_logging_bonus": nolog, "sensitivity_bonus": sens,
                         "raw_total": round(raw, 2), "capped_score": f.score}
    return f


def score_all(findings: list[Finding], sc: ScoringConfig) -> list[Finding]:
    """Score every finding and return them highest risk first."""
    for f in findings:
        score_finding(f, sc)
    return sorted(findings, key=lambda f: (-f.score, f.rule_id, f.resource_id))


def posture_score(findings: list[Finding], checks_run: int, sc: ScoringConfig) -> float:
    """0-100, higher is healthier. Suppressed findings are excluded (they are approved exceptions)."""
    if checks_run <= 0:
        return 100.0
    p = sc.posture_exponent
    penalty = sum(f.score ** p for f in findings if not f.suppressed)
    worst = checks_run * (sc.max_score ** p) * sc.posture_worst_case_factor
    return round(max(0.0, 100.0 - 100.0 * penalty / worst), 1)


def severity_counts(findings: list[Finding]) -> dict[str, int]:
    """Count active (non-suppressed) findings per severity."""
    out = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for f in findings:
        if not f.suppressed:
            out[f.severity] += 1
    return out
