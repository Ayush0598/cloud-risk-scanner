"""Accuracy check: compare what the scanner reported with the hand-written ground truth.
TP = planted flaw reported, FP = reported but not planted, FN = planted but missed,
TN = every other (rule, resource) pair that was checked and correctly NOT reported."""
from __future__ import annotations

from dataclasses import dataclass

from .pipeline import ScanResult
from .simulation import GroundTruth


@dataclass
class Metrics:
    """Confusion counts plus the lists of missed and falsely reported findings."""
    tp: int; fp: int; fn: int; tn: int
    missed: list[str]; false_alarms: list[str]

    @property
    def precision(self) -> float:
        """Share of reported findings that were real: TP / (TP + FP)."""
        return self.tp / (self.tp + self.fp) if self.tp + self.fp else 1.0

    @property
    def recall(self) -> float:
        """Share of planted flaws that were found: TP / (TP + FN)."""
        return self.tp / (self.tp + self.fn) if self.tp + self.fn else 1.0


def score_against_truth(result: ScanResult, truth: GroundTruth) -> Metrics:
    """Compare reported active findings with the hand-written answer key."""
    reported = {f.fingerprint for f in result.active}
    tp = len(reported & truth.active)
    fp_set, fn_set = reported - truth.active, truth.active - reported
    checked = result.evaluation.checks_run
    unknown = len(result.evaluation.unknown)
    tn = checked - unknown - tp - len(fp_set) - len(fn_set) - len(truth.suppressed)
    return Metrics(tp, len(fp_set), len(fn_set), tn, sorted(fn_set), sorted(fp_set))


def check_context(result: ScanResult, truth: GroundTruth) -> list[str]:
    """Compare exposure level and counted dependents of the reported findings with the hand-written expectation.
    Returns a list of mismatches (empty = every planted context was measured correctly)."""
    by_fp = {f.fingerprint: f for f in result.findings}
    problems = []
    for fp, (level, deps) in sorted(truth.context.items()):
        f = by_fp.get(fp)
        if f is None:
            problems.append(f"{fp}: finding missing")
            continue
        if abs(f.exposure_level - level) > 1e-9:
            problems.append(f"{fp}: exposure {f.exposure_level} (expected {level})")
        if deps is not None and f.dependents != deps:
            problems.append(f"{fp}: dependents {f.dependents} (expected {deps})")
    return problems
