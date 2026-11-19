"""Layer 5b - Reporting: machine-readable JSON/CSV and a human HTML report (Jinja2 + matplotlib charts
embedded as base64 so the report is a single shareable file)."""
from __future__ import annotations

import base64
import csv
import io
import json
from datetime import datetime, timezone
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from jinja2 import Environment, select_autoescape

from .exposure_graph import graph_png
from .pipeline import ScanResult

COLORS = {"CRITICAL": "#b71c1c", "HIGH": "#e65100", "MEDIUM": "#f9a825", "LOW": "#2e7d32"}


def to_dict(r: ScanResult) -> dict:
    """Plain-dict form of a scan result for the JSON report."""
    return {"identity": r.identity, "posture_score": r.posture, "counts": r.counts,
            "checks_run": r.evaluation.checks_run, "per_rule": r.evaluation.stats,
            "unknown": r.evaluation.unknown, "notes": r.notes, "read_only_proof": r.proof,
            "findings": [f.model_dump() for f in r.findings]}


def write_json(r: ScanResult, path: str | Path) -> None:
    """Write the machine-readable report."""
    Path(path).write_text(json.dumps(to_dict(r), indent=2, default=str), encoding="utf-8")


def _csv_safe(value):
    """Spreadsheet programs run text that starts with = + - @ as a formula (CSV injection). A resource name is
    attacker-influenced, so such cells get a leading apostrophe and are shown as plain text."""
    if isinstance(value, str) and value[:1] in ("=", "+", "-", "@", "\t", "\r"):
        return "'" + value
    return value


def write_csv(r: ScanResult, path: str | Path) -> None:
    """Write the spreadsheet report; cell text is made formula-safe by _csv_safe."""
    cols = ["severity", "score", "rule_id", "title", "resource_type", "resource_id", "region", "evidence",
            "remediation", "exposure_level", "dependents", "suppressed"]
    with open(path, "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=cols, extrasaction="ignore")
        w.writeheader()
        for f in r.findings:
            w.writerow({k: _csv_safe(v) for k, v in f.model_dump().items()})


def _png(fig) -> str:
    """Render a matplotlib figure to base64 PNG so the HTML report is one self-contained file."""
    buf = io.BytesIO()
    fig.savefig(buf, format="png", dpi=110, bbox_inches="tight")
    plt.close(fig)
    return base64.b64encode(buf.getvalue()).decode()


def severity_chart(counts: dict) -> str:
    """Bar chart of active findings per severity."""
    fig, ax = plt.subplots(figsize=(4.2, 2.6))
    keys = list(counts)
    ax.bar(keys, [counts[k] for k in keys], color=[COLORS[k] for k in keys])
    ax.set_title("Active findings by severity")
    for i, k in enumerate(keys):
        ax.text(i, counts[k], str(counts[k]), ha="center", va="bottom")
    return _png(fig)


def domain_chart(findings) -> str:
    """Horizontal bar chart of active findings per domain."""
    dom: dict[str, int] = {}
    for f in findings:
        if not f.suppressed:
            dom[f.domain] = dom.get(f.domain, 0) + 1
    fig, ax = plt.subplots(figsize=(4.6, 2.6))
    items = sorted(dom.items(), key=lambda kv: kv[1])
    ax.barh([k for k, _ in items], [v for _, v in items], color="#37474f")
    ax.set_title("Active findings by domain")
    return _png(fig)


TEMPLATE = """<!doctype html><html><head><meta charset="utf-8"><title>Cloud Risk Assessment</title>
<style>body{font-family:Arial,sans-serif;margin:24px;color:#222;background:#fff}table{border-collapse:collapse;width:100%;margin:8px 0}
th,td{border:1px solid #ccc;padding:5px 8px;font-size:13px;vertical-align:top}th{background:#eceff1;text-align:left}
.sev{color:#fff;padding:1px 6px;border-radius:3px;font-weight:bold}.big{font-size:42px;font-weight:bold}
.muted{color:#666;font-size:12px}</style></head><body>
<h1>Cloud Risk Assessment Report</h1>
<p class="muted">Account {{ identity.account }} ({{ identity.arn_type }}) &middot; generated {{ generated }} &middot; read-only scan</p>
<p>Posture score: <span class="big">{{ posture }}</span> / 100 &nbsp; ({{ r.evaluation.checks_run }} checks run,
{{ r.active|length }} active findings, {{ r.suppressed|length }} suppressed, {{ r.evaluation.unknown|length }} could not be checked)</p>
<img src="data:image/png;base64,{{ sev_png }}"> <img src="data:image/png;base64,{{ dom_png }}">
<h2>Exposure and blast radius</h2>
<p class="muted">Left: can the internet reach the resource? Right: what else depends on it, so how far damage could spread.
Exposure adds up to +1.0 to a score; the blast multiplier grows with the number of dependents (capped).</p>
<img style="max-width:100%" src="data:image/png;base64,{{ graph_png }}">
<h2>Findings (highest risk first)</h2>
<table><tr><th>Severity</th><th>Score</th><th>Rule</th><th>Resource</th><th>Evidence</th><th>Fix</th><th>Standards</th></tr>
{% for f in r.active %}<tr><td><span class="sev" style="background:{{ colors[f.severity] }}">{{ f.severity }}</span></td>
<td>{{ f.score }}</td><td>{{ f.rule_id }}<br>{{ f.title }}</td><td>{{ f.resource_type }}<br>{{ f.resource_id }}<br><span class="muted">{{ f.region }}</span></td>
<td>{{ f.evidence }}{% if f.exposure_reason %}<br><span class="muted">Exposure +{{ f.score_breakdown.exposure_bonus }}: {{ f.exposure_reason }}</span>{% endif %}{% if f.dependents is not none %}<br><span class="muted">Blast radius &times;{{ f.blast }}: {{ f.dependents }} dependent(s){% if f.dependent_names %} ({{ f.dependent_names|join(", ") }}){% endif %}</span>{% endif %}</td><td>{{ f.remediation }}</td>
<td class="muted">{% for fw, refs in f.standards.items() %}{% for x in refs %}{{ x }}<br>{% endfor %}{% endfor %}</td></tr>{% endfor %}</table>
{% if r.suppressed %}<h2>Approved exceptions (suppressed)</h2><table><tr><th>Rule</th><th>Resource</th><th>Reason</th></tr>
{% for f in r.suppressed %}<tr><td>{{ f.rule_id }}</td><td>{{ f.resource_id }}</td><td>{{ f.suppression_reason }}</td></tr>{% endfor %}</table>{% endif %}
<h2>Compliance view</h2><table><tr><th>Framework</th><th>Rules mapped</th><th>Failing controls</th></tr>
{% for k, c in r.coverage.items() %}<tr><td>{{ c.label }}</td><td>{{ c.rules_mapped }} / {{ c.rules_total }}</td>
<td>{% for ctl, rules in c.failing_controls.items() %}{{ ctl }} <span class="muted">({{ rules|join(", ") }})</span><br>{% endfor %}</td></tr>{% endfor %}</table>
<h2>Scan integrity</h2><p>{{ r.proof.total_calls }} API calls, {{ r.proof.distinct_operations }} distinct operations,
all read-only: <b>{{ r.proof.all_read_only }}</b>, writes blocked: {{ r.proof.blocked_writes }}.</p>
{% if r.notes %}<h3>Notes</h3><ul>{% for n in r.notes %}<li>{{ n }}</li>{% endfor %}</ul>{% endif %}
</body></html>"""


def render_html(r: ScanResult) -> str:
    """Build the human-readable report (Jinja2 with auto-escaping, so names cannot inject HTML)."""
    env = Environment(autoescape=select_autoescape(default=True))
    return env.from_string(TEMPLATE).render(
        r=r, identity=r.identity, posture=r.posture, colors=COLORS,
        generated=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
        sev_png=severity_chart(r.counts), dom_png=domain_chart(r.findings), graph_png=graph_png(r.findings))


def write_html(r: ScanResult, path: str | Path) -> None:
    """Write the HTML report to disk."""
    Path(path).write_text(render_html(r), encoding="utf-8")
