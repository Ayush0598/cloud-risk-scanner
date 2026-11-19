"""Glue: runs the five layers in order. Each layer is also usable alone (that is how the tests and
the notebook demonstrate them one by one)."""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from datetime import date, datetime
from pathlib import Path
from typing import Optional

from .auth import ScanSession
from .collector import collect
from .compliance import attach_standards, coverage
from .config import Config
from .models import Finding, Resource
from .rules import Evaluation, evaluate
from .scoring import posture_score, score_all, severity_counts


@dataclass
class ScanResult:
    """Everything one scan produced, handed to storage and reporting."""
    identity: dict
    inventory: list[Resource]
    evaluation: Evaluation
    findings: list[Finding]
    posture: float
    counts: dict
    coverage: dict
    proof: dict
    notes: list[str] = field(default_factory=list)

    @property
    def active(self) -> list[Finding]:
        """Findings that count (not covered by a valid exception)."""
        return [f for f in self.findings if not f.suppressed]

    @property
    def suppressed(self) -> list[Finding]:
        """Findings covered by a valid, unexpired exception."""
        return [f for f in self.findings if f.suppressed]


@dataclass
class Stage:
    """One hop in the data flow: which layer ran, what it consumed, what it produced, how long it took."""
    layer: str
    consumes: str
    produces: str
    items_in: int
    items_out: int
    seconds: float
    detail: str = ""


def analyse(inventory: list[Resource], cfg: Config, today: Optional[date] = None) -> tuple[Evaluation, list[Finding], float]:
    """Layers 3-4 on an inventory only (no cloud access): rules -> scoring -> standards."""
    ev = evaluate(inventory, cfg, today)
    findings = score_all(ev.findings, cfg.scoring)
    attach_standards(findings, cfg)
    return ev, findings, posture_score(findings, ev.checks_run, cfg.scoring)


def run_traced(ss: ScanSession, cfg: Config, now: Optional[datetime] = None,
               today: Optional[date] = None) -> tuple[ScanResult, list[Stage]]:
    """The integrated system: every layer in order, recording what flows between them."""
    stages: list[Stage] = []

    def timed(layer, consumes, produces, n_in, fn, describe):
        """Run one layer, time it, and append a Stage record describing the hand-off."""
        t0 = time.perf_counter()
        out = fn()
        stages.append(Stage(layer, consumes, produces, n_in, describe(out)[0], round(time.perf_counter() - t0, 3),
                            describe(out)[1]))
        return out

    identity = timed("1 Authentication", "boto3 credential chain", "ScanSession + masked identity", 1,
                     ss.identity, lambda o: (1, f"account {o['account']}, guard={'on' if ss.guard else 'off'}"))
    inventory = timed("2 Collector", "read-only AWS API answers", "Resource objects", len(ss.regions),
                      lambda: collect(ss, cfg.scoring.sensitivity_tag, now),
                      lambda o: (len(o), f"{len(ss.calls)} API calls, {len(ss.notes)} 'could not check' notes"))
    ev = timed("3 Rule engine", "Resource objects + thresholds/suppressions", "raw Finding objects", len(inventory),
               lambda: evaluate(inventory, cfg, today),
               lambda o: (len(o.findings), f"{o.checks_run} checks, {sum(f.suppressed for f in o.findings)} suppressed, "
                                           f"{len(o.unknown)} unknown"))
    findings = timed("4 Risk scoring", "raw Finding objects + scoring weights", "scored, ranked Findings", len(ev.findings),
                     lambda: score_all(ev.findings, cfg.scoring),
                     lambda o: (len(o), f"highest score {o[0].score if o else 0}"))
    findings = timed("5a Compliance", "scored Findings + standards_map", "Findings with CIS/NIST/ISO refs", len(findings),
                     lambda: attach_standards(findings, cfg),
                     lambda o: (sum(1 for f in o if any(f.standards.values())), "findings carrying at least one reference"))
    posture = posture_score(findings, ev.checks_run, cfg.scoring)
    result = ScanResult(identity=identity, inventory=inventory, evaluation=ev, findings=findings, posture=posture,
                        counts=severity_counts(findings), coverage=coverage(findings, cfg),
                        proof=ss.read_only_proof, notes=list(ss.notes) + ev.notes)
    return result, stages


def run_scan(ss: ScanSession, cfg: Config, now: Optional[datetime] = None, today: Optional[date] = None) -> ScanResult:
    """Run all layers and return only the result (see run_traced for the data-flow trace)."""
    return run_traced(ss, cfg, now, today)[0]


def assess(ss: ScanSession, cfg: Config, store=None, out_dir: Optional[str] = None, label: str = "",
           now: Optional[datetime] = None, today: Optional[date] = None):
    """The single entry point of the whole system: scan -> (save history) -> (compare with previous scan)
    -> (write reports). Returns (result, drift, stages); drift is None when there is no earlier scan."""
    from .storage import compare_scans
    result, stages = run_traced(ss, cfg, now, today)
    drift = None
    if store is not None:
        history = store.history()
        previous = store.load_findings(history[-1]["scan"]) if history else None
        t0 = time.perf_counter()
        scan_id = store.save_scan(result.identity["account"], result.findings, result.posture,
                                  result.evaluation.checks_run, label)
        drift = compare_scans(previous, result.findings) if previous is not None else None
        stages.append(Stage("5b Storage", "scored Findings", "scan row + finding rows (SQLite)", len(result.findings),
                            len(result.findings), round(time.perf_counter() - t0, 3),
                            f"scan #{scan_id}" + (f", drift: {len(drift['new'])} new / {len(drift['resolved'])} resolved"
                                                  if drift else ", first scan (no baseline)")))
    if out_dir:
        from .reporting import write_csv, write_html, write_json
        t0 = time.perf_counter()
        Path(out_dir).mkdir(parents=True, exist_ok=True)
        write_json(result, Path(out_dir) / "report.json"); write_csv(result, Path(out_dir) / "report.csv")
        write_html(result, Path(out_dir) / "report.html")
        stages.append(Stage("5c Reporting", "ScanResult", "report.html / .json / .csv", len(result.findings), 3,
                            round(time.perf_counter() - t0, 3), f"written to {out_dir}"))
    return result, drift, stages
