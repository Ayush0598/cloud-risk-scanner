"""Shared data models (pydantic). Every layer exchanges these typed objects, so malformed
API data fails loudly at the boundary instead of silently corrupting results."""
from __future__ import annotations

from typing import Any, Optional

from pydantic import BaseModel, Field


class Resource(BaseModel):
    """One cloud resource in the common, provider-independent inventory format."""
    id: str                      # stable natural identifier (bucket name, sg-id, user name ...)
    type: str                    # s3_bucket, security_group, vpc, ec2_instance, ebs_volume, ...
    region: str = "global"
    name: str = ""
    data: dict[str, Any] = Field(default_factory=dict)   # normalised settings the rules read


class Finding(BaseModel):
    """One failed check on one resource, with evidence, fix, score and standards references."""
    rule_id: str
    title: str
    domain: str
    resource_id: str
    resource_name: str = ""       # human-friendly name (for example a security group's name)
    resource_type: str
    region: str
    evidence: str
    remediation: str
    likelihood: int              # 1-5, from the rule definition
    impact: int                  # 1-5, from the rule definition
    blast: float = 1.0           # blast-radius multiplier (rule default; replaced by the counted value when known)
    exposure: bool = False       # reachable from the public internet at all? (True when exposure_level > 0)
    exposure_level: float = 0.0  # 0 = not reachable, 0.5 = partly, 1.0 = reachable; scales the exposure bonus
    exposure_reason: str = ""    # plain-words explanation of the level (shown in the report)
    dependents: Optional[int] = None    # how many other things depend on / are reached through this resource
    dependent_names: list[str] = Field(default_factory=list)   # who they are (used by the graph)
    no_logging: bool = False     # would abuse go unnoticed?
    sensitivity: Optional[str] = None   # data-classification tag of the resource, if any
    base: float = 0.0            # filled in by scoring
    score: float = 0.0           # 0-10, filled in by scoring
    severity: str = ""           # CRITICAL / HIGH / MEDIUM / LOW
    score_breakdown: dict[str, float] = Field(default_factory=dict)
    suppressed: bool = False
    suppression_reason: str = ""
    standards: dict[str, list[str]] = Field(default_factory=dict)

    @property
    def fingerprint(self) -> str:
        """Stable key used to compare scans over time (rule + resource)."""
        return f"{self.rule_id}|{self.resource_id}"
