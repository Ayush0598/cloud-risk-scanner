"""Layer 3 - Rule engine.

A rule is a small declarative object: metadata (title, domain, likelihood, impact, blast radius,
flags) plus a check function that looks at ONE normalised Resource and returns
    True  -> compliant            False -> misconfiguration (a finding)
    None  -> unknown ("could not check"): never turned into a finding, counted separately.
Rules never call the cloud: they only read the inventory, so they are deterministic and unit-testable.
"""
from __future__ import annotations

import fnmatch
from dataclasses import dataclass, field
from datetime import date
from typing import Callable, Optional

from .config import Config, Thresholds
from .models import Finding, Resource

Check = Callable[[Resource, Thresholds], Optional[bool]]
Evidence = Callable[[Resource, Thresholds], str]


@dataclass(frozen=True)
class Rule:
    id: str
    title: str
    domain: str
    resource_type: str
    likelihood: int
    impact: int
    check: Check
    evidence: Evidence
    remediation: str
    blast: float = 1.0
    no_logging: bool = False
    exposure: Callable[[Resource], float] = lambda r: 0.0          # 0 not reachable .. 1.0 reachable from the internet
    exposure_why: Callable[[Resource], str] = lambda r: ""         # plain-words reason for that level
    dependents: Callable[[Resource], Optional[list]] = lambda r: None   # who depends on this resource (None = unknown / not counted)


RULES: dict[str, Rule] = {}


def rule(**kw):
    """Decorator-style registration: @rule(id=..., ...) on the check function."""
    def deco(fn):
        evidence = kw.pop("evidence")
        r = Rule(check=fn, evidence=evidence, **kw)
        assert r.id not in RULES, f"duplicate rule {r.id}"
        assert 1 <= r.likelihood <= 5 and 1 <= r.impact <= 5
        RULES[r.id] = r
        return fn
    return deco


def _not(value: Optional[bool]) -> Optional[bool]:
    return None if value is None else not value


# ---- exposure and blast radius are worked out from the resource itself, not fixed per rule ---------------
def _deps(r: Resource) -> Optional[list]:
    """Names of the things that depend on this resource (collector fills it; None = could not be counted)."""
    return r.data.get("dependents")


def _s3_acl_exposure(r: Resource) -> float:
    """A public ACL is only reachable if Block Public Access is not fully on (fully on neutralises it)."""
    return 0.0 if r.data.get("block_public") is True else 1.0


def _s3_acl_why(r: Resource) -> str:
    if r.data.get("block_public") is True:
        return "ACL is public, but Block Public Access is fully on, so the public grant has no effect"
    return "ACL is public and Block Public Access is not fully on: anyone on the internet can read the bucket"


def _s3_bpa_exposure(r: Resource) -> float:
    """Missing Block Public Access only matters if something public exists: a public ACL (unknown = half)."""
    acl = r.data.get("public_acl")
    return 0.5 if acl is None else (1.0 if acl else 0.0)


def _s3_bpa_why(r: Resource) -> str:
    acl = r.data.get("public_acl")
    if acl is None:
        return "Could not read the ACL, so exposure is only assumed (half)"
    return ("Block Public Access is off and the bucket ACL is public: the bucket is open to the internet" if acl
            else "Block Public Access is off, but no public grant exists right now: nothing is reachable yet")


def _sg_exposure(r: Resource) -> float:
    """An open security group is reachable only if it protects something that has a public IP."""
    reach = r.data.get("public_reach")
    if reach is None:                       # could not check: be careful, assume reachable
        return 1.0
    if reach:
        return 1.0
    return 0.5 if r.data.get("dependents") else 0.0


def _sg_why(r: Resource) -> str:
    reach, deps = r.data.get("public_reach"), r.data.get("dependents")
    if reach is None:
        return "Could not check what the group protects, so it is assumed reachable"
    if reach:
        return f"Attached to {', '.join(deps)}, which has a public IP address: reachable from the internet"
    if deps:
        return f"Attached to {', '.join(deps)}, but none has a public IP: not reachable from the internet directly"
    return "Not attached to anything right now: the rule is wide open but nothing is reachable through it"


# ----------------------------------------------------------------------------- storage (S3)
@rule(id="S3-001", title="S3 bucket ACL grants access to everyone", domain="Storage",
      resource_type="s3_bucket", likelihood=5, impact=4,
      exposure=_s3_acl_exposure, exposure_why=_s3_acl_why,
      evidence=lambda r, t: "ACL grants permissions to the AllUsers/AuthenticatedUsers group",
      remediation="Remove public grants from the ACL and enable S3 Block Public Access.")
def s3_public_acl(r, t): return _not(r.data.get("public_acl"))


@rule(id="S3-002", title="S3 bucket has no default encryption", domain="Storage",
      resource_type="s3_bucket", likelihood=2, impact=4,
      evidence=lambda r, t: "No default server-side encryption configuration",
      remediation="Enable default encryption (SSE-S3 or SSE-KMS) on the bucket.")
def s3_encryption(r, t): return r.data.get("encrypted")


@rule(id="S3-003", title="S3 bucket versioning is disabled", domain="Storage",
      resource_type="s3_bucket", likelihood=2, impact=3,
      evidence=lambda r, t: "Versioning is not enabled, so overwritten/deleted objects cannot be recovered",
      remediation="Enable bucket versioning (and a lifecycle rule to control cost).")
def s3_versioning(r, t): return r.data.get("versioning")


@rule(id="S3-004", title="S3 Block Public Access is not fully enabled", domain="Storage",
      resource_type="s3_bucket", likelihood=3, impact=4,
      exposure=_s3_bpa_exposure, exposure_why=_s3_bpa_why,
      evidence=lambda r, t: "One or more of the four Block Public Access settings is off",
      remediation="Turn on all four Block Public Access settings for the bucket.")
def s3_block_public(r, t): return r.data.get("block_public")


# ----------------------------------------------------------------------------- network
def _exposed_ports(r: Resource, t: Thresholds) -> list[int]:
    hit = []
    for lo, hi in r.data.get("open_ranges") or []:
        hit += [p for p in t.sensitive_ports if lo <= p <= hi]
    return sorted(set(hit))


@rule(id="NET-001", title="Security group opens admin/database ports to the internet", domain="Network",
      resource_type="security_group", likelihood=5, impact=4,
      exposure=_sg_exposure, exposure_why=_sg_why, dependents=_deps,
      evidence=lambda r, t: f"0.0.0.0/0 (or ::/0) allowed on port(s) {_exposed_ports(r, t)}",
      remediation="Restrict the source to specific trusted CIDR ranges or use SSM Session Manager.")
def net_open_ports(r, t):
    if r.data.get("open_ranges") is None:
        return None
    return not _exposed_ports(r, t)


@rule(id="NET-002", title="VPC flow logs are not enabled", domain="Network", resource_type="vpc",
      likelihood=3, impact=2, no_logging=True,
      evidence=lambda r, t: "No flow log is attached to this VPC",
      remediation="Create a VPC flow log delivering to CloudWatch Logs or S3.")
def net_flow_logs(r, t): return r.data.get("flow_logs")


# ----------------------------------------------------------------------------- compute
@rule(id="CMP-001", title="EC2 instance allows IMDSv1", domain="Compute", resource_type="ec2_instance",
      likelihood=3, impact=4,
      evidence=lambda r, t: "Instance metadata does not require session tokens (HttpTokens != required)",
      remediation="Set HttpTokens=required (IMDSv2) on the instance.")
def cmp_imds(r, t): return r.data.get("imds_v2_required")


@rule(id="CMP-002", title="Credential-like text found in EC2 user data", domain="Compute",
      resource_type="ec2_instance", likelihood=4, impact=5,
      evidence=lambda r, t: "User data contains a password/secret/token-style assignment (value not stored)",
      remediation="Move secrets to AWS Secrets Manager or SSM Parameter Store and rotate the exposed value.")
def cmp_secret(r, t): return _not(r.data.get("secret_in_user_data"))


@rule(id="CMP-003", title="EBS volume is not encrypted", domain="Compute", resource_type="ebs_volume",
      likelihood=2, impact=4,
      evidence=lambda r, t: "Volume encryption is off",
      remediation="Snapshot, copy with encryption, replace the volume; enable EBS encryption by default.")
def cmp_ebs(r, t): return r.data.get("encrypted")


# ----------------------------------------------------------------------------- database
@rule(id="DB-001", title="RDS instance is publicly accessible", domain="Database", resource_type="rds_instance",
      likelihood=4, impact=5,
      exposure=lambda r: 1.0, exposure_why=lambda r: "The database is publicly accessible: reachable from the internet",
      evidence=lambda r, t: "PubliclyAccessible = true",
      remediation="Disable public accessibility and place the DB in private subnets.")
def db_public(r, t): return _not(r.data.get("public"))


@rule(id="DB-002", title="RDS storage is not encrypted", domain="Database", resource_type="rds_instance",
      likelihood=2, impact=5,
      evidence=lambda r, t: "StorageEncrypted = false",
      remediation="Restore from an encrypted snapshot copy; enable encryption for new instances.")
def db_encrypted(r, t): return r.data.get("encrypted")


@rule(id="DB-003", title="RDS backup retention is too short", domain="Database", resource_type="rds_instance",
      likelihood=2, impact=3,
      evidence=lambda r, t: f"Backup retention is {r.data.get('backup_days')} day(s); policy minimum is {t.backup_retention_min_days}",
      remediation="Raise BackupRetentionPeriod to at least the configured minimum.")
def db_backup(r, t):
    d = r.data.get("backup_days")
    return None if d is None else d >= t.backup_retention_min_days


# ----------------------------------------------------------------------------- identity
@rule(id="IAM-001", title="Customer-managed policy grants full administrator access", domain="Identity",
      resource_type="iam_policy", likelihood=3, impact=5, blast=1.3, dependents=_deps,
      evidence=lambda r, t: "Policy allows Action '*' on Resource '*'",
      remediation="Replace with least-privilege permissions scoped to the needed actions/resources.")
def iam_admin(r, t): return _not(r.data.get("admin"))


@rule(id="IAM-002", title="Console user has no MFA", domain="Identity", resource_type="iam_user",
      likelihood=4, impact=4,
      evidence=lambda r, t: "User can sign in to the console but has no MFA device",
      remediation="Register an MFA device for the user or remove console access.")
def iam_mfa(r, t):
    if r.data.get("console_access") is None or r.data.get("mfa") is None:
        return None
    return (not r.data["console_access"]) or r.data["mfa"]


@rule(id="IAM-003", title="Active access key is older than the allowed age", domain="Identity",
      resource_type="iam_user", likelihood=3, impact=4,
      evidence=lambda r, t: "Active key(s) older than %d days: %s" % (t.access_key_max_age_days, ", ".join(
          f"{k['id']} ({k['age_days']}d)" for k in r.data.get("access_keys", [])
          if k["active"] and k["age_days"] > t.access_key_max_age_days)),
      remediation="Create a new key, switch applications over, then deactivate and delete the old key.")
def iam_key_age(r, t):
    keys = r.data.get("access_keys")
    if keys is None:
        return None
    return not any(k["active"] and k["age_days"] > t.access_key_max_age_days for k in keys)


# ----------------------------------------------------------------------------- logging
@rule(id="LOG-001", title="No CloudTrail trail exists in the account", domain="Logging", resource_type="account",
      likelihood=3, impact=5, blast=1.2, no_logging=True,
      evidence=lambda r, t: "describe_trails returned zero trails - API activity is not recorded",
      remediation="Create a multi-region trail with log file validation, delivered to a protected S3 bucket.")
def log_trail_exists(r, t):
    c = r.data.get("trail_count")
    return None if c is None else c > 0


@rule(id="LOG-002", title="CloudTrail is single-region or lacks log file validation", domain="Logging",
      resource_type="cloudtrail", likelihood=2, impact=3, no_logging=True,
      evidence=lambda r, t: "multi_region=%s, log_validation=%s" % (r.data.get("multi_region"), r.data.get("log_validation")),
      remediation="Enable IsMultiRegionTrail and EnableLogFileValidation on the trail.")
def log_trail_quality(r, t): return bool(r.data.get("multi_region")) and bool(r.data.get("log_validation"))


# ----------------------------------------------------------------------------- encryption keys / functions
@rule(id="KMS-001", title="Customer-managed KMS key rotation is disabled", domain="Encryption",
      resource_type="kms_key", likelihood=2, impact=3,
      evidence=lambda r, t: "Automatic annual key rotation is off",
      remediation="Enable automatic key rotation on the key.")
def kms_rotation(r, t): return r.data.get("rotation")


@rule(id="FN-001", title="Lambda function runs with an administrator role", domain="Serverless",
      resource_type="lambda_function", likelihood=3, impact=5, blast=1.3, dependents=_deps,
      evidence=lambda r, t: "The execution role allows Action '*' on Resource '*'",
      remediation="Give the function a role with only the permissions it needs.")
def fn_admin(r, t): return _not(r.data.get("role_admin"))


@rule(id="FN-002", title="Lambda environment variable names suggest embedded secrets", domain="Serverless",
      resource_type="lambda_function", likelihood=3, impact=4,
      evidence=lambda r, t: f"Variable name(s) look like secrets: {r.data.get('secret_env_vars')} (values not read into the report)",
      remediation="Store secrets in Secrets Manager/SSM and read them at run time.")
def fn_secrets(r, t):
    v = r.data.get("secret_env_vars")
    return None if v is None else not v


# ============================================================================= evaluation
@dataclass
class Evaluation:
    findings: list[Finding] = field(default_factory=list)
    stats: dict[str, dict[str, int]] = field(default_factory=dict)   # rule -> checked/failed/unknown/passed
    unknown: list[str] = field(default_factory=list)                 # "RULE|resource" that could not be judged
    notes: list[str] = field(default_factory=list)

    @property
    def checks_run(self) -> int:
        return sum(s["checked"] for s in self.stats.values())


def _matches(pattern: str, resource: Resource) -> bool:
    return fnmatch.fnmatch(resource.id, pattern) or fnmatch.fnmatch(resource.name, pattern)


def evaluate(inventory: list[Resource], cfg: Config, today: Optional[date] = None) -> Evaluation:
    """Apply every rule to every matching resource. Suppressions are applied here and expired ones
    are ignored (the finding is active again and a note records why)."""
    today = today or date.today()
    ev = Evaluation(stats={rid: dict(checked=0, passed=0, failed=0, unknown=0) for rid in RULES})
    for res in inventory:
        for rid, rl in RULES.items():
            if res.type != rl.resource_type:
                continue
            ev.stats[rid]["checked"] += 1
            verdict = rl.check(res, cfg.thresholds)
            if verdict is None:
                ev.stats[rid]["unknown"] += 1
                ev.unknown.append(f"{rid}|{res.id}")
                continue
            if verdict:
                ev.stats[rid]["passed"] += 1
                continue
            ev.stats[rid]["failed"] += 1
            sens = res.data.get("sensitivity")
            level = float(rl.exposure(res))
            deps = rl.dependents(res)
            f = Finding(rule_id=rid, title=rl.title, domain=rl.domain, resource_id=res.id, resource_name=res.name,
                        resource_type=res.type, region=res.region, evidence=rl.evidence(res, cfg.thresholds),
                        remediation=rl.remediation, likelihood=rl.likelihood, impact=rl.impact, blast=rl.blast,
                        exposure=level > 0, exposure_level=level,
                        exposure_reason=rl.exposure_why(res),
                        dependents=None if deps is None else len(deps), dependent_names=list(deps or []),
                        no_logging=rl.no_logging,
                        sensitivity=sens if sens in cfg.scoring.sensitive_labels else None)
            for sp in cfg.suppressions:
                if rid in sp.rule_ids and _matches(sp.resource, res):
                    if sp.expires >= today:
                        f.suppressed, f.suppression_reason = True, f"{sp.reason} (approved by {sp.approved_by}, expires {sp.expires})"
                    else:
                        ev.notes.append(f"Suppression for {rid} on {res.id} expired on {sp.expires}; finding is active again")
                    break
            ev.findings.append(f)
    return ev
