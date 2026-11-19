"""Layer 5a - Storage: scan history in SQLite via SQLAlchemy, plus drift comparison between scans.
Only derived findings and counts are stored - never credentials, secret values or full account ids."""
from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import Boolean, Float, ForeignKey, Integer, String, Text, create_engine, select
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column, relationship

from .models import Finding


class Base(DeclarativeBase):
    """SQLAlchemy declarative base."""
    pass


class ScanRow(Base):
    """One row per scan: time, masked account, posture score."""
    __tablename__ = "scans"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    started: Mapped[str] = mapped_column(String(40))
    account: Mapped[str] = mapped_column(String(40))
    label: Mapped[str] = mapped_column(String(80), default="")
    posture: Mapped[float] = mapped_column(Float)
    checks_run: Mapped[int] = mapped_column(Integer)
    findings: Mapped[list["FindingRow"]] = relationship(back_populates="scan", cascade="all, delete-orphan")


class FindingRow(Base):
    """One row per finding in a scan, with the full finding as JSON."""
    __tablename__ = "findings"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id"))
    fingerprint: Mapped[str] = mapped_column(String(200), index=True)
    rule_id: Mapped[str] = mapped_column(String(20))
    resource_id: Mapped[str] = mapped_column(String(200))
    severity: Mapped[str] = mapped_column(String(10))
    score: Mapped[float] = mapped_column(Float)
    suppressed: Mapped[bool] = mapped_column(Boolean, default=False)
    payload: Mapped[str] = mapped_column(Text)
    scan: Mapped[ScanRow] = relationship(back_populates="findings")


class Store:
    """SQLite scan history."""
    def __init__(self, url: str = "sqlite:///:memory:"):
        """Open (or create) the database; ':memory:' keeps it in RAM."""
        self.engine = create_engine(url)
        Base.metadata.create_all(self.engine)

    def save_scan(self, account: str, findings: list[Finding], posture: float, checks_run: int,
                  label: str = "", started: Optional[str] = None) -> int:
        """Store a scan and its findings; returns the scan id."""
        with Session(self.engine) as s:
            row = ScanRow(started=started or datetime.now(timezone.utc).isoformat(timespec="seconds"),
                          account=account, label=label, posture=posture, checks_run=checks_run)
            for f in findings:
                row.findings.append(FindingRow(fingerprint=f.fingerprint, rule_id=f.rule_id,
                                               resource_id=f.resource_id, severity=f.severity, score=f.score,
                                               suppressed=f.suppressed, payload=f.model_dump_json()))
            s.add(row)
            s.commit()
            return row.id

    def history(self) -> list[dict]:
        """List all scans, oldest first."""
        with Session(self.engine) as s:
            return [dict(scan=r.id, started=r.started, label=r.label, posture=r.posture,
                         active=sum(1 for f in r.findings if not f.suppressed))
                    for r in s.scalars(select(ScanRow).order_by(ScanRow.id))]

    def load_findings(self, scan_id: int) -> list[Finding]:
        """Load the findings of one stored scan."""
        with Session(self.engine) as s:
            rows = s.scalars(select(FindingRow).where(FindingRow.scan_id == scan_id)).all()
            return [Finding(**json.loads(r.payload)) for r in rows]


def compare_scans(old: list[Finding], new: list[Finding]) -> dict[str, list[Finding]]:
    """Drift detection on ACTIVE findings: what is new, what was fixed, what is still open."""
    o = {f.fingerprint: f for f in old if not f.suppressed}
    n = {f.fingerprint: f for f in new if not f.suppressed}
    return {"new": [n[k] for k in sorted(n.keys() - o.keys())],
            "resolved": [o[k] for k in sorted(o.keys() - n.keys())],
            "persisting": [n[k] for k in sorted(n.keys() & o.keys())]}
