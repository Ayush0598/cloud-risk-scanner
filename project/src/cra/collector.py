"""Layer 2 - Collector.

Calls the provider's read-only APIs (through the guarded ScanSession) and converts every answer
into the common Resource format. Design rules:
  * only list/get/describe calls; the session guard enforces it
  * paginate everything (real accounts return results in pages)
  * scan regions in parallel (thread pool): scan time is network I/O, not CPU
  * a denied or failing call is recorded as a note and the scan continues ("could not check");
    unknown values are stored as None so rules never turn "unknown" into a false finding
  * never store secrets: user-data and environment-variable VALUES are inspected in memory only,
    and just a true/false result (or variable NAMES) is kept
"""
from __future__ import annotations

import re
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from typing import Any, Callable, Optional

from botocore.exceptions import BotoCoreError, ClientError

from .auth import ScanSession
from .models import Resource

# Built-in patterns used to spot secrets in startup scripts (values are never stored).
SECRET_ASSIGNMENT = re.compile(
    r"(password|passwd|secret|token|api[_-]?key|access[_-]?key|private[_-]?key)\s*[=:]", re.I)
SECRET_NAME = re.compile(r"(password|passwd|secret|token|api[_-]?key|access[_-]?key|private[_-]?key|_key$)", re.I)


def safe(ss: ScanSession, label: str, fn: Callable[[], Any], default: Any = None) -> Any:
    """Run one read-only call; on failure note it and return a default instead of crashing."""
    try:
        return fn()
    except ClientError as exc:
        ss.note(f"Could not check {label}: {exc.response['Error']['Code']}")
    except BotoCoreError as exc:
        ss.note(f"Could not check {label}: {type(exc).__name__}")
    return default


def _pages(client, operation: str, key: str, **kwargs) -> list:
    """Collect ALL results of a paginated AWS list call (real accounts return results in pages)."""
    out: list = []
    for page in client.get_paginator(operation).paginate(**kwargs):
        out += page.get(key, [])
    return out


def _is_admin_document(doc: dict) -> bool:
    """True if a policy Allows Action '*' on Resource '*' (full administrator)."""
    statements = doc.get("Statement", [])
    statements = [statements] if isinstance(statements, dict) else statements
    as_list = lambda v: v if isinstance(v, list) else [v]
    return any(s.get("Effect") == "Allow" and "*" in as_list(s.get("Action", []))
               and "*" in as_list(s.get("Resource", [])) for s in statements)


# ------------------------------------------------------------------------------ S3 (global)
def collect_s3(ss: ScanSession, sensitivity_tag: str = "data-classification") -> list[Resource]:
    """S3 buckets: public ACL, default encryption, versioning, Block Public Access and data-classification tag."""
    out: list[Resource] = []
    s3 = ss.client("s3")
    for b in safe(ss, "S3 list buckets", lambda: s3.list_buckets()["Buckets"], []):
        name = b["Name"]
        loc = safe(ss, f"S3 location {name}",
                   lambda: s3.get_bucket_location(Bucket=name)["LocationConstraint"], "unknown")
        region = "us-east-1" if loc in (None, "unknown") else ("eu-west-1" if loc == "EU" else loc)
        c = ss.client("s3", region)                      # talk to the bucket in its own region

        def public_acl():
            """True if the bucket ACL grants access to AllUsers (anyone) or AuthenticatedUsers (any AWS account)."""
            uris = [g["Grantee"].get("URI", "") for g in c.get_bucket_acl(Bucket=name)["Grants"]]
            return any(u.endswith(("/global/AllUsers", "/global/AuthenticatedUsers")) for u in uris)

        def encrypted():
            """True if default encryption is configured; False if AWS says none is set."""
            try:
                c.get_bucket_encryption(Bucket=name)
                return True
            except ClientError as e:
                if e.response["Error"]["Code"] == "ServerSideEncryptionConfigurationNotFoundError":
                    return False
                raise

        def versioning():
            """True if bucket versioning is Enabled."""
            return c.get_bucket_versioning(Bucket=name).get("Status") == "Enabled"

        def block_public():
            """True only if all four Block Public Access settings are on."""
            try:
                cfg = c.get_public_access_block(Bucket=name)["PublicAccessBlockConfiguration"]
                return all(cfg.values())
            except ClientError as e:
                if e.response["Error"]["Code"] == "NoSuchPublicAccessBlockConfiguration":
                    return False
                raise

        def tag():
            """Return the data-classification tag value, or None if the bucket has no such tag."""
            try:
                tags = {t["Key"]: t["Value"] for t in c.get_bucket_tagging(Bucket=name)["TagSet"]}
                return tags.get(sensitivity_tag)
            except ClientError as e:
                if e.response["Error"]["Code"] == "NoSuchTagSet":
                    return None
                raise

        out.append(Resource(id=name, type="s3_bucket", region=region, name=name, data=dict(
            public_acl=safe(ss, f"bucket ACL {name}", public_acl),
            encrypted=safe(ss, f"bucket encryption {name}", encrypted),
            versioning=safe(ss, f"bucket versioning {name}", versioning),
            block_public=safe(ss, f"bucket public access block {name}", block_public),
            sensitivity=safe(ss, f"bucket tags {name}", tag))))
    return out


# ------------------------------------------------------------------------------ IAM (global)
def collect_iam(ss: ScanSession, now: Optional[datetime] = None) -> list[Resource]:
    """IAM: customer-managed policies (admin?) and users (console access, MFA, access-key ages)."""
    now = now or datetime.now(timezone.utc)
    out: list[Resource] = []
    iam = ss.client("iam")

    for pol in safe(ss, "IAM policies", lambda: _pages(iam, "list_policies", "Policies", Scope="Local"), []):
        def admin():
            """True if the policy's default version allows Action '*' on Resource '*'."""
            doc = iam.get_policy_version(PolicyArn=pol["Arn"],
                                         VersionId=pol["DefaultVersionId"])["PolicyVersion"]["Document"]
            return _is_admin_document(doc)
        def dependents():
            """Who uses this policy: attached users, groups and roles (names only). Used for the blast radius."""
            names: list[str] = []
            for page in iam.get_paginator("list_entities_for_policy").paginate(PolicyArn=pol["Arn"]):
                names += [f"user:{x['UserName']}" for x in page.get("PolicyUsers", [])]
                names += [f"group:{x['GroupName']}" for x in page.get("PolicyGroups", [])]
                names += [f"role:{x['RoleName']}" for x in page.get("PolicyRoles", [])]
            return sorted(names)

        is_admin = safe(ss, f"policy {pol['PolicyName']}", admin)
        data = dict(admin=is_admin)
        if is_admin is not False:               # only an admin (or unknown) policy needs its blast radius counted
            data["dependents"] = safe(ss, f"who uses policy {pol['PolicyName']}", dependents)
        out.append(Resource(id=pol["PolicyName"], type="iam_policy", name=pol["PolicyName"], data=data))

    for u in safe(ss, "IAM users", lambda: _pages(iam, "list_users", "Users"), []):
        name = u["UserName"]

        def console():
            """True if the user has a console password (login profile)."""
            try:
                iam.get_login_profile(UserName=name)
                return True
            except ClientError as e:
                if e.response["Error"]["Code"] == "NoSuchEntity":
                    return False
                raise

        def keys():
            """Access keys as masked id + active flag + age in days (the key secret is never read)."""
            res = []
            for k in iam.list_access_keys(UserName=name)["AccessKeyMetadata"]:
                res.append({"id": k["AccessKeyId"][:4] + "****", "active": k["Status"] == "Active",
                            "age_days": (now - k["CreateDate"]).days})
            return res

        mfa = safe(ss, f"MFA for {name}", lambda: bool(iam.list_mfa_devices(UserName=name)["MFADevices"]))
        out.append(Resource(id=name, type="iam_user", name=name, data=dict(
            console_access=safe(ss, f"login profile {name}", console), mfa=mfa,
            access_keys=safe(ss, f"access keys {name}", keys))))
    return out


# ------------------------------------------------------------------------------ EC2 / VPC
def collect_ec2(ss: ScanSession, region: str) -> list[Resource]:
    """EC2/VPC/EBS in one region: security groups, VPC flow logs, instances (IMDS, user-data secrets), volumes."""
    out: list[Resource] = []
    ec2 = ss.client("ec2", region)

    # Which security groups protect something, and does any of it have a public IP? (read-only describe call)
    enis = safe(ss, f"network interfaces in {region}",
                lambda: _pages(ec2, "describe_network_interfaces", "NetworkInterfaces"))
    sg_users: dict[str, set[str]] = {}
    sg_public: dict[str, bool] = {}
    for ni in enis or []:
        label = (ni.get("Attachment") or {}).get("InstanceId") or ni["NetworkInterfaceId"]
        has_public_ip = bool((ni.get("Association") or {}).get("PublicIp"))
        for g in ni.get("Groups", []):
            sg_users.setdefault(g["GroupId"], set()).add(label)
            sg_public[g["GroupId"]] = sg_public.get(g["GroupId"], False) or has_public_ip

    for sg in safe(ss, f"security groups in {region}",
                   lambda: _pages(ec2, "describe_security_groups", "SecurityGroups"), []):
        ranges = []                                      # (from_port, to_port) open to the world
        for perm in sg.get("IpPermissions", []):
            world = any(r.get("CidrIp") == "0.0.0.0/0" for r in perm.get("IpRanges", [])) or \
                any(r.get("CidrIpv6") == "::/0" for r in perm.get("Ipv6Ranges", []))
            if world:
                if perm.get("IpProtocol") == "-1" or "FromPort" not in perm:
                    ranges.append((0, 65535))            # all traffic
                else:
                    ranges.append((perm["FromPort"], perm["ToPort"]))
        out.append(Resource(id=sg["GroupId"], type="security_group", region=region, name=sg["GroupName"],
                            data=dict(open_ranges=ranges,
                                      dependents=None if enis is None else sorted(sg_users.get(sg["GroupId"], ())),
                                      public_reach=None if enis is None else sg_public.get(sg["GroupId"], False))))

    flow_vpcs = safe(ss, f"flow logs in {region}",
                     lambda: {f["ResourceId"] for f in _pages(ec2, "describe_flow_logs", "FlowLogs")})
    for vpc in safe(ss, f"VPCs in {region}", lambda: _pages(ec2, "describe_vpcs", "Vpcs"), []):
        out.append(Resource(id=vpc["VpcId"], type="vpc", region=region,
                            name="default VPC" if vpc.get("IsDefault") else vpc["VpcId"],
                            data=dict(is_default=bool(vpc.get("IsDefault")),
                                      flow_logs=None if flow_vpcs is None else vpc["VpcId"] in flow_vpcs)))

    reservations = safe(ss, f"instances in {region}",
                        lambda: _pages(ec2, "describe_instances", "Reservations"), [])
    for res in reservations:
        for inst in res["Instances"]:
            if inst["State"]["Name"] == "terminated":
                continue
            iid = inst["InstanceId"]

            def secret_in_user_data():
                """Inspect user-data in memory for password/token-style text; only a True/False is kept."""
                val = ec2.describe_instance_attribute(InstanceId=iid, Attribute="userData")\
                    .get("UserData", {}).get("Value")
                if not val:
                    return False
                import base64
                return bool(SECRET_ASSIGNMENT.search(base64.b64decode(val).decode("utf-8", "ignore")))

            out.append(Resource(id=iid, type="ec2_instance", region=region, name=iid, data=dict(
                imds_v2_required=inst.get("MetadataOptions", {}).get("HttpTokens") == "required",
                secret_in_user_data=safe(ss, f"user data of {iid}", secret_in_user_data))))

    for vol in safe(ss, f"volumes in {region}", lambda: _pages(ec2, "describe_volumes", "Volumes"), []):
        out.append(Resource(id=vol["VolumeId"], type="ebs_volume", region=region, name=vol["VolumeId"],
                            data=dict(encrypted=bool(vol.get("Encrypted")))))
    return out


# ------------------------------------------------------------------------------ RDS
def collect_rds(ss: ScanSession, region: str) -> list[Resource]:
    """RDS instances in one region: public access, storage encryption, backup retention."""
    rds = ss.client("rds", region)
    dbs = safe(ss, f"RDS instances in {region}", lambda: _pages(rds, "describe_db_instances", "DBInstances"), [])
    return [Resource(id=d["DBInstanceIdentifier"], type="rds_instance", region=region,
                     name=d["DBInstanceIdentifier"],
                     data=dict(public=bool(d.get("PubliclyAccessible")),
                               encrypted=bool(d.get("StorageEncrypted")),
                               backup_days=int(d.get("BackupRetentionPeriod", 0)))) for d in dbs]


# ------------------------------------------------------------------------------ KMS
def collect_kms(ss: ScanSession, region: str) -> list[Resource]:
    """Customer-managed, enabled, symmetric KMS keys and whether automatic rotation is on."""
    kms = ss.client("kms", region)
    out: list[Resource] = []
    for k in safe(ss, f"KMS keys in {region}", lambda: _pages(kms, "list_keys", "Keys"), []):
        meta = safe(ss, f"KMS key {k['KeyId'][:8]}", lambda: kms.describe_key(KeyId=k["KeyId"])["KeyMetadata"])
        # Rotation applies only to enabled, customer-managed, symmetric keys.
        if not meta or meta.get("KeyManager") != "CUSTOMER" or meta.get("KeyState") != "Enabled" \
                or meta.get("KeySpec", "SYMMETRIC_DEFAULT") != "SYMMETRIC_DEFAULT":
            continue
        rot = safe(ss, f"KMS rotation {k['KeyId'][:8]}",
                   lambda: kms.get_key_rotation_status(KeyId=k["KeyId"])["KeyRotationEnabled"])
        out.append(Resource(id=k["KeyId"], type="kms_key", region=region, name=meta.get("Description") or k["KeyId"],
                            data=dict(manager="CUSTOMER", rotation=rot)))
    return out


# ------------------------------------------------------------------------------ Lambda
def collect_lambda(ss: ScanSession, region: str) -> list[Resource]:
    """Lambda functions: is the execution role an administrator, and which env-var NAMES look like secrets."""
    lam, iam = ss.client("lambda", region), ss.client("iam")
    admin_cache: dict[str, Optional[bool]] = {}

    def role_is_admin(role_name: str) -> Optional[bool]:
        """Is this role an administrator? Cached per role; None if it could not be checked."""
        if role_name not in admin_cache:
            def check():
                """Read the role's attached and inline policies and test them for full admin."""
                docs = []
                for p in iam.list_attached_role_policies(RoleName=role_name)["AttachedPolicies"]:
                    v = iam.get_policy(PolicyArn=p["PolicyArn"])["Policy"]["DefaultVersionId"]
                    docs.append(iam.get_policy_version(PolicyArn=p["PolicyArn"], VersionId=v)["PolicyVersion"]["Document"])
                for n in iam.list_role_policies(RoleName=role_name)["PolicyNames"]:
                    docs.append(iam.get_role_policy(RoleName=role_name, PolicyName=n)["PolicyDocument"])
                return any(_is_admin_document(d) for d in docs)
            admin_cache[role_name] = safe(ss, f"role {role_name}", check)
        return admin_cache[role_name]

    out: list[Resource] = []
    functions = safe(ss, f"Lambda functions in {region}", lambda: _pages(lam, "list_functions", "Functions"), [])
    by_role: dict[str, list[str]] = {}            # role name -> functions that run with it (blast radius)
    for fn in functions:
        by_role.setdefault(fn["Role"].split("/")[-1], []).append(fn["FunctionName"])
    for fn in functions:
        role_name = fn["Role"].split("/")[-1]
        env_names = list((fn.get("Environment") or {}).get("Variables", {}).keys())
        out.append(Resource(id=fn["FunctionName"], type="lambda_function", region=region, name=fn["FunctionName"],
                            data=dict(role_admin=role_is_admin(role_name), dependents=sorted(by_role[role_name]),
                                      secret_env_vars=[n for n in env_names if SECRET_NAME.search(n)])))
    return out


# ------------------------------------------------------------------------------ CloudTrail
def collect_cloudtrail(ss: ScanSession) -> list[Resource]:
    """CloudTrail: one resource per trail plus an 'account' resource holding the trail count (None = unknown)."""
    trails: dict[str, Resource] = {}
    checked = 0
    for region in ss.regions:
        ct = ss.client("cloudtrail", region)
        found = safe(ss, f"CloudTrail in {region}",
                     lambda: ct.describe_trails(includeShadowTrails=False)["trailList"])
        if found is None:
            continue
        checked += 1
        for t in found:
            trails.setdefault(t["TrailARN"], Resource(
                id=t["Name"], type="cloudtrail", region=t.get("HomeRegion", region), name=t["Name"],
                data=dict(multi_region=bool(t.get("IsMultiRegionTrail")),
                          log_validation=bool(t.get("LogFileValidationEnabled")))))
    account = Resource(id="account", type="account", name="account",
                       data=dict(trail_count=len(trails) if checked else None))   # None = unknown
    return list(trails.values()) + [account]


# ------------------------------------------------------------------------------ orchestration
def collect(ss: ScanSession, sensitivity_tag: str = "data-classification",
            now: Optional[datetime] = None, max_workers: int = 8) -> list[Resource]:
    """Run every collector, regional ones in parallel, and return one sorted inventory."""
    tasks: list[Callable[[], list[Resource]]] = [
        lambda: collect_s3(ss, sensitivity_tag), lambda: collect_iam(ss, now), lambda: collect_cloudtrail(ss)]
    for region in ss.regions:
        for fn in (collect_ec2, collect_rds, collect_kms, collect_lambda):
            tasks.append(lambda fn=fn, region=region: fn(ss, region))
    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        results = list(pool.map(lambda t: t(), tasks))
    inventory = [r for chunk in results for r in chunk]
    return sorted(inventory, key=lambda r: (r.type, r.region, r.id))
