"""Exposure and blast-radius graph.

Shows, in one picture, WHICH risky resources the internet can reach (left -> middle) and WHAT depends on each of
them (middle -> right). The picture is drawn from the Findings only (no cloud access), so it is deterministic.

  Internet  --(solid red = reachable, dashed orange = partly, dotted grey = not reachable)-->  resource
  resource  --(grey line)-->  the users / roles / functions / network interfaces that depend on it  (blast radius)
"""
from __future__ import annotations

import math
from dataclasses import dataclass, field

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.lines import Line2D

from .models import Finding

SEV_COLORS = {"CRITICAL": "#b71c1c", "HIGH": "#e65100", "MEDIUM": "#f9a825", "LOW": "#2e7d32"}
_RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "": 0}


@dataclass
class GraphNode:
    """One risky resource: its worst score, how reachable it is, and who depends on it."""
    resource_id: str
    resource_type: str
    name: str = ""
    rules: list[str] = field(default_factory=list)
    score: float = 0.0
    severity: str = ""
    exposure_level: float = 0.0
    exposure_reason: str = ""
    blast: float = 1.0
    dependents: list[str] = field(default_factory=list)
    dependents_known: bool = False           # True when the number of dependents was actually counted


def graph_nodes(findings: list[Finding], top: int = 10) -> list[GraphNode]:
    """Group active findings by resource and keep those that have something to say about exposure or blast
    radius (an exposure explanation, or at least one dependent). Highest score first, at most `top`."""
    nodes: dict[str, GraphNode] = {}
    for f in findings:
        if f.suppressed or not (f.exposure_reason or f.dependents):
            continue
        n = nodes.setdefault(f.resource_id, GraphNode(f.resource_id, f.resource_type, f.resource_name))
        n.rules.append(f.rule_id)
        if f.score > n.score:
            n.score, n.severity = f.score, f.severity
        if f.exposure_level >= n.exposure_level:
            n.exposure_level = f.exposure_level
            n.exposure_reason = f.exposure_reason or n.exposure_reason
        if f.dependents is not None:
            n.dependents_known = True
            n.blast = max(n.blast, f.blast)
            n.dependents = sorted(set(n.dependents) | set(f.dependent_names))
    return sorted(nodes.values(), key=lambda n: (-n.score, n.resource_id))[:top]


def _short(text: str, n: int = 26) -> str:
    return text if len(text) <= n else text[: n - 1] + "…"


def draw_exposure_graph(findings: list[Finding], top: int = 10):
    """Return a matplotlib figure of the exposure / blast-radius graph (or a short message if nothing qualifies)."""
    nodes = graph_nodes(findings, top)
    if not nodes:
        fig, ax = plt.subplots(figsize=(6, 1.2)); ax.axis("off")
        ax.text(0.5, 0.5, "No exposure or blast-radius context to show", ha="center", va="center")
        return fig

    row = 0.46                                           # vertical space per dependent
    bands = [max(1, len(n.dependents)) * row + (0.62 if n.dependents else 0.36) for n in nodes]
    total = sum(bands)
    fig, ax = plt.subplots(figsize=(11.5, max(3.2, total + 1.4)))
    ax.set_xlim(0, 1); ax.set_ylim(-0.9, total); ax.axis("off")
    X_NET, X_RES, X_DEP = 0.07, 0.46, 0.86

    ax.text(X_NET, total - 0.1, "INTERNET", ha="center", va="top", fontsize=11, fontweight="bold", color="#263238",
            bbox=dict(boxstyle="round,pad=0.5", fc="#eceff1", ec="#37474f"))
    y_net = total - 0.1 - 0.35
    top_y = total
    exposed_mids, acc = [], total                      # y positions of rows that have an internet edge
    for n, band in zip(nodes, bands):
        if n.exposure_reason:
            exposed_mids.append(acc - band / 2)
        acc -= band
    if exposed_mids:                                   # the trunk: one line down from the INTERNET box
        ax.plot([X_NET, X_NET], [y_net, min(exposed_mids)], color="#b0bec5", lw=1.4, solid_capstyle="round", zorder=0)
    for n, band in zip(nodes, bands):
        y_top = top_y; top_y -= band
        y_mid = y_top - band / 2
        color = SEV_COLORS.get(n.severity, "#546e7a")
        # --- resource node
        title = n.name if n.name and n.name != n.resource_id else n.resource_id
        label = f"{_short(title, 24)}\n{n.resource_type}  ·  {', '.join(sorted(set(n.rules)))}\nscore {n.score}  {n.severity}"
        ax.text(X_RES, y_mid, label, ha="center", va="center", fontsize=8, color="white", fontweight="bold",
                bbox=dict(boxstyle="round,pad=0.45", fc=color, ec="none"))
        # --- internet -> resource edge, styled by exposure level
        if n.exposure_reason:
            if n.exposure_level >= 1.0:
                style, col, lw, txt = "-", "#c62828", 2.6, "reachable  +1.0"
            elif n.exposure_level > 0:
                style, col, lw, txt = (0, (5, 3)), "#ef6c00", 2.0, f"partly  +{n.exposure_level:.1f}"
            else:
                style, col, lw, txt = (0, (1, 3)), "#90a4ae", 1.6, "not reachable  +0"
            ax.annotate("", xy=(X_RES - 0.115, y_mid), xytext=(X_NET, y_mid),          # branch from the trunk
                        arrowprops=dict(arrowstyle="-|>", color=col, lw=lw, linestyle=style, shrinkA=0, shrinkB=0))
            ax.text((X_NET + X_RES - 0.115) / 2 + 0.02, y_mid + 0.04, txt, fontsize=7.5, color=col, ha="center",
                    va="bottom", fontweight="bold")
        # --- resource -> dependents (blast radius)
        if n.dependents:
            ys = [y_mid + (len(n.dependents) - 1) * row / 2 - i * row for i in range(len(n.dependents))]
            for d, yd in zip(n.dependents, ys):
                ax.annotate("", xy=(X_DEP - 0.085, yd), xytext=(X_RES + 0.115, y_mid),
                            arrowprops=dict(arrowstyle="-", color="#78909c", lw=1.2, shrinkA=0, shrinkB=0))
                ax.text(X_DEP, yd, _short(d, 22), ha="center", va="center", fontsize=7.5, color="#263238",
                        bbox=dict(boxstyle="round,pad=0.3", fc="#cfd8dc", ec="#78909c"))
            ax.text(X_RES, y_mid - 0.40, f"blast ×{n.blast:g}  ({len(n.dependents)} dependent"
                    f"{'s' if len(n.dependents) != 1 else ''})", ha="center", va="top", fontsize=7.5, color="#455a64")
        elif n.dependents_known:
            ax.text(X_DEP, y_mid, "nothing depends on it", ha="center", va="center", fontsize=7.5,
                    color="#90a4ae", style="italic")
    ax.text(X_RES, total + 0.15, "RISKY RESOURCE (colour = severity)", ha="center", fontsize=8.5, color="#37474f")
    ax.text(X_DEP, total + 0.15, "WHAT DEPENDS ON IT (blast radius)", ha="center", fontsize=8.5, color="#37474f")
    ax.text(X_NET, total + 0.15, "can reach?", ha="center", fontsize=8.5, color="#37474f")
    ax.text(0.5, -0.62, "Blast radius is counted for IAM policies (who uses them), Lambda roles (functions sharing them) and "
            "security groups (what they protect); other rules keep their fixed default.", ha="center", fontsize=7.5,
            color="#78909c")
    handles = [Line2D([0], [0], color="#c62828", lw=2.6, label="reachable from the internet (+1.0)"),
               Line2D([0], [0], color="#ef6c00", lw=2, ls=(0, (5, 3)), label="partly reachable (+0.5)"),
               Line2D([0], [0], color="#90a4ae", lw=1.6, ls=(0, (1, 3)), label="not reachable (+0)"),
               Line2D([0], [0], color="#78909c", lw=1.2, label="depends on  ->  larger blast radius")]
    ax.legend(handles=handles, loc="lower center", ncol=4, fontsize=8, frameon=False, bbox_to_anchor=(0.5, -0.02))
    return fig


def graph_png(findings: list[Finding], top: int = 10) -> str:
    """Base64 PNG of the graph, ready to embed in the single-file HTML report."""
    import base64, io
    fig = draw_exposure_graph(findings, top)
    buf = io.BytesIO()
    fig.savefig(buf, format="png", dpi=110, bbox_inches="tight", facecolor="white")
    plt.close(fig)
    return base64.b64encode(buf.getvalue()).decode()
