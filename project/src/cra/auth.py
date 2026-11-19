"""Layer 1 - Authentication & Session.

Goals (Phase 1, objectives 1 and 8): authenticate with least-privilege credentials, never put
secrets in code, and guarantee the scanner can only READ.

Two independent defences:
  1. Permission audit  - static analysis of the identity's IAM policies: does it allow any write?
  2. Read-only guard   - every API call made through ScanSession is checked client-side, and any
                         operation that is not Get*/List*/Describe* is blocked before it is sent.
"""
from __future__ import annotations

import threading
from dataclasses import dataclass, field
from typing import Any, Optional

import boto3
from botocore.config import Config as BotoConfig
from botocore.exceptions import BotoCoreError, ClientError

READ_ONLY_PREFIXES = ("Get", "List", "Describe")
# Retry with adaptive exponential backoff so large accounts that throttle us still work.
RETRY_CONFIG = BotoConfig(retries={"max_attempts": 8, "mode": "adaptive"})


class WriteBlockedError(RuntimeError):
    """Raised when code tries to make a call that could modify the account."""


def mask_account(account_id: str) -> str:
    """Never print a full account id: keep only the last four digits."""
    return "****" + account_id[-4:] if account_id else "unknown"


class ScanSession:
    """A boto3 session wrapper that audits every call and refuses writes.

    Credentials are never passed in code: they come from environment variables, a named
    profile or the provider credential chain (boto3 handles that)."""

    def __init__(self, boto_session: Optional[boto3.Session] = None,
                 regions: Optional[list[str]] = None, guard: bool = True):
        """Create the guarded session; credentials come from boto3's normal chain, never from our code."""
        self.session = boto_session or boto3.Session()
        self.regions = list(regions or ["us-east-1"])
        self.guard = guard
        self.calls: list[str] = []          # audit log: "service:Operation" for every call made
        self.blocked: list[str] = []        # operations the guard refused
        self.notes: list[str] = []          # "could not check ..." messages from collectors
        self._deny: set[str] = set()
        self._lock = threading.Lock()
        # 'before-call' fires for every API operation of every client made from this session
        self.session.events.register("before-call", self._before_call)

    # ---- the guard -------------------------------------------------------------------------
    def _before_call(self, model, **kwargs):
        """boto3 'before-call' hook: log every API call and refuse anything that is not Get/List/Describe."""
        service = model.service_model.service_name
        op = model.name
        with self._lock:
            self.calls.append(f"{service}:{op}")
        if service in self._deny:
            raise ClientError({"Error": {"Code": "AccessDenied",
                                         "Message": "simulated denied service"}}, op)
        if self.guard and not op.startswith(READ_ONLY_PREFIXES):
            with self._lock:
                self.blocked.append(f"{service}:{op}")
            raise WriteBlockedError(f"Blocked non read-only call {service}:{op}")

    def simulate_denied(self, *services: str) -> None:
        """Testing aid: make every call to these services fail with AccessDenied."""
        self._deny.update(services)

    def note(self, message: str) -> None:
        """Record a 'could not check ...' message (thread-safe) for the report."""
        with self._lock:
            self.notes.append(message)

    def client(self, service: str, region: Optional[str] = None):
        """Return a boto3 client from the guarded session, with adaptive retries for rate limiting."""
        return self.session.client(service, region_name=region or self.regions[0],
                                   config=RETRY_CONFIG)

    # ---- identity --------------------------------------------------------------------------
    def identity(self) -> dict[str, str]:
        """Who are we? (sts:GetCallerIdentity is a read-only call). Account id is masked."""
        try:
            who = self.client("sts").get_caller_identity()
        except (ClientError, BotoCoreError) as exc:
            raise SystemExit(f"Could not authenticate: {exc}")
        return {"account": mask_account(who["Account"]), "arn_type": who["Arn"].split(":")[-1].split("/")[0]}

    @property
    def read_only_proof(self) -> dict[str, Any]:
        """Evidence for the report: how many calls were made and that none were writes."""
        ops = sorted({c.split(":")[1] for c in self.calls})
        return {"total_calls": len(self.calls), "distinct_operations": len(ops),
                "blocked_writes": len(self.blocked),
                "all_read_only": all(o.startswith(READ_ONLY_PREFIXES) for o in ops)}


# ---- permission audit ------------------------------------------------------------------------
def _is_read_action(action: str) -> bool:
    """True if an IAM action name (e.g. 's3:GetObject') is a pure read; '*' is never read-only."""
    if action == "*":
        return False
    name = action.partition(":")[2]
    return name.startswith(READ_ONLY_PREFIXES)


def find_write_actions(policy_document: dict) -> list[str]:
    """Return every action a policy ALLOWS that is not a pure read (Get/List/Describe).
    Wildcards such as '*' or 's3:*' count as write-capable. NotAction cannot be proven safe."""
    statements = policy_document.get("Statement", [])
    if isinstance(statements, dict):
        statements = [statements]
    found: set[str] = set()
    for st in statements:
        if st.get("Effect") != "Allow":
            continue
        if "NotAction" in st:
            found.add("NotAction (cannot prove read-only)")
            continue
        actions = st.get("Action", [])
        for a in ([actions] if isinstance(actions, str) else actions):
            if not _is_read_action(a):
                found.add(a)
    return sorted(found)


@dataclass
class PermissionReport:
    """Result of the static permission audit of one role."""
    role: str
    verdict: str                                  # READ_ONLY | WRITE_CAPABLE | UNKNOWN
    write_actions: list[str] = field(default_factory=list)
    policies: list[str] = field(default_factory=list)


def audit_role_permissions(iam_client, role_name: str) -> PermissionReport:
    """Static analysis of a role's attached and inline policies (read-only IAM calls)."""
    try:
        docs, names = [], []
        for pol in iam_client.list_attached_role_policies(RoleName=role_name)["AttachedPolicies"]:
            version = iam_client.get_policy(PolicyArn=pol["PolicyArn"])["Policy"]["DefaultVersionId"]
            docs.append(iam_client.get_policy_version(PolicyArn=pol["PolicyArn"],
                                                      VersionId=version)["PolicyVersion"]["Document"])
            names.append(pol["PolicyName"])
        for name in iam_client.list_role_policies(RoleName=role_name)["PolicyNames"]:
            docs.append(iam_client.get_role_policy(RoleName=role_name, PolicyName=name)["PolicyDocument"])
            names.append(f"{name} (inline)")
    except ClientError as exc:
        return PermissionReport(role_name, "UNKNOWN", [f"could not read policies: {exc.response['Error']['Code']}"])
    writes = sorted({a for d in docs for a in find_write_actions(d)})
    return PermissionReport(role_name, "WRITE_CAPABLE" if writes else "READ_ONLY", writes, names)
