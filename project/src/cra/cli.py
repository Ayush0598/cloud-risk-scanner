"""Command-line entry point:  python -m cra scan --regions us-east-1 --out reports/
Uses whatever credentials boto3 finds (environment, profile, CloudShell role). `--demo` scans the built-in
fake account instead, so the tool can be shown with no AWS account at all."""
from __future__ import annotations


import click
from rich.console import Console
from rich.table import Table

from .auth import ScanSession
from .config import load_config
from .pipeline import assess
from .storage import Store

STYLE = {"CRITICAL": "bold red", "HIGH": "dark_orange", "MEDIUM": "yellow", "LOW": "green"}


@click.group()
def main():
    """Read-only AWS cloud risk assessor."""


@main.command()
@click.option("--regions", default="us-east-1", help="Comma-separated regions to scan")
@click.option("--config", "config_dir", default="config", show_default=True)
@click.option("--out", default="reports", show_default=True, help="Output folder")
@click.option("--db", default=None, help="SQLite file for scan history + drift comparison")
@click.option("--label", default="", help="Label stored with this scan")
@click.option("--demo", is_flag=True, help="Scan the built-in fake AWS account (moto). It gets new random resource ids every run, so drift between two demo runs is not meaningful")
def scan(regions, config_dir, out, db, label, demo):
    """Run a full scan and write HTML/JSON/CSV reports (and history when --db is given)."""
    console = Console()
    cfg = load_config(config_dir)
    region_list = [r.strip() for r in regions.split(",") if r.strip()]
    store = Store(f"sqlite:///{db}") if db else None
    if demo:
        import boto3
        from .simulation import REGIONS, SIM_NOW, SIM_TODAY, build_account, fake_aws
        with fake_aws():
            build_account(boto3)
            result, drift, stages = assess(ScanSession(regions=REGIONS), cfg, store, out, label, SIM_NOW, SIM_TODAY)
    else:
        result, drift, stages = assess(ScanSession(regions=region_list), cfg, store, out, label)

    t = Table(title=f"Findings - posture {result.posture}/100")
    for c in ("Sev", "Score", "Rule", "Resource", "Evidence"): t.add_column(c)
    for f in result.active[:25]:
        t.add_row(f"[{STYLE[f.severity]}]{f.severity}[/]", str(f.score), f.rule_id, f.resource_id, f.evidence[:60])
    console.print(t)
    console.print(f"{len(result.active)} active, {len(result.suppressed)} suppressed, "
                  f"{len(result.evaluation.unknown)} unknown. Read-only proof: {result.proof}")
    if drift:
        console.print(f"Drift since last scan: {len(drift['new'])} new, {len(drift['resolved'])} resolved, "
                      f"{len(drift['persisting'])} still open")
    console.print("Data flow: " + " -> ".join(f"{st.layer.split(' ',1)[1]}({st.items_out})" for st in stages))
    console.print(f"Reports written to {out}/")
