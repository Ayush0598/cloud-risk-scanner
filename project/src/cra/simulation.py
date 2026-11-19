"""A fake AWS account (moto) with deliberately planted flaws AND planted good resources.

The expected results are written down here by hand, from the design of the account - they are NOT
produced by running the scanner. evaluation.py then compares scanner output to this ground truth.
No real AWS account, credentials or money are involved: moto answers the same boto3 calls locally."""
from __future__ import annotations

import io
import json
import os
import zipfile
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

SIM_NOW = datetime(2026, 10, 13, 12, 0, tzinfo=timezone.utc)   # fixed "today" so results are repeatable
SIM_TODAY = SIM_NOW.date()
REGIONS = ["us-east-1", "eu-west-1"]

ADMIN_DOC = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}
S3_DOC = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": ["s3:GetObject"], "Resource": "*"}]}
TRUST = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow",
         "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}]}


@dataclass
class GroundTruth:
    """The hand-written answer key for the planted account."""
    active: set[str] = field(default_factory=set)        # "RULE|resource" that MUST be reported
    suppressed: set[str] = field(default_factory=set)    # planted but covered by a valid exception
    healthy: list[str] = field(default_factory=list)     # human-readable list of planted GOOD resources
    # hand-written expectation for exposure and blast radius: "RULE|resource" -> (exposure_level, dependents)
    context: dict[str, tuple[float, int | None]] = field(default_factory=dict)

    def expect(self, rule: str, resource: str, exposure: float | None = None, dependents: int | None = None) -> None:
        """Record that rule 'rule' must report resource 'resource' (optionally with the expected exposure
        level and number of dependents, so the measured context can be checked too)."""
        self.active.add(f"{rule}|{resource}")
        if exposure is not None:
            self.context[f"{rule}|{resource}"] = (exposure, dependents)


def _zip() -> bytes:
    """Build a tiny in-memory Lambda deployment package."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("lambda_function.py", "def handler(e, c):\n    return 1\n")
    return buf.getvalue()


@contextmanager
def fake_aws():
    """Context manager: everything boto3 does inside this block hits moto, not the internet."""
    os.environ.update(AWS_ACCESS_KEY_ID="testing", AWS_SECRET_ACCESS_KEY="testing",
                      AWS_SECURITY_TOKEN="testing", AWS_SESSION_TOKEN="testing", AWS_DEFAULT_REGION="us-east-1")
    from moto import mock_aws
    with mock_aws():
        yield


def build_account(boto3, truth: GroundTruth | None = None) -> GroundTruth:
    """Create the planted account inside an active fake_aws() block and return the ground truth."""
    from freezegun import freeze_time
    t = truth or GroundTruth()
    e1, e2 = REGIONS
    s3 = boto3.client("s3", region_name=e1)
    iam = boto3.client("iam", region_name=e1)

    # ---------------- S3 ----------------
    def bucket(name, acl="private", enc=False, ver=False, bpa=False, tag=None):
        """Create one S3 bucket with the requested (mis)configuration."""
        s3.create_bucket(Bucket=name)
        if acl != "private": s3.put_bucket_acl(Bucket=name, ACL=acl)
        if enc: s3.put_bucket_encryption(Bucket=name, ServerSideEncryptionConfiguration={
            "Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]})
        if ver: s3.put_bucket_versioning(Bucket=name, VersioningConfiguration={"Status": "Enabled"})
        if bpa: s3.put_public_access_block(Bucket=name, PublicAccessBlockConfiguration=dict(
            BlockPublicAcls=True, IgnorePublicAcls=True, BlockPublicPolicy=True, RestrictPublicBuckets=True))
        if tag: s3.put_bucket_tagging(Bucket=name, Tagging={"TagSet": [{"Key": "data-classification", "Value": tag}]})

    bucket("prod-customer-data", acl="public-read", tag="confidential")      # everything wrong + sensitive
    for r in ("S3-001", "S3-002", "S3-003", "S3-004"):                      # public ACL, Block Public Access off
        t.expect(r, "prod-customer-data", 1.0 if r in ("S3-001", "S3-004") else None)
    bucket("secure-logs-bucket", enc=True, ver=True, bpa=True); t.healthy.append("bucket secure-logs-bucket")
    bucket("team-notes", enc=True, bpa=True); t.expect("S3-003", "team-notes")
    bucket("public-website-assets", acl="public-read", enc=True, ver=True)   # valid, unexpired exception
    t.suppressed |= {"S3-001|public-website-assets", "S3-004|public-website-assets"}
    bucket("legacy-public-site", acl="public-read", enc=True, ver=True)      # exception EXPIRED -> active
    t.expect("S3-001", "legacy-public-site", 1.0); t.expect("S3-004", "legacy-public-site", 1.0)

    # ---------------- network / compute / db per region ----------------
    for region in REGIONS:
        ec2 = boto3.client("ec2", region_name=region)
        for v in ec2.describe_vpcs()["Vpcs"]:                      # every default VPC lacks flow logs
            if v["IsDefault"]: t.expect("NET-002", v["VpcId"])

    ec2 = boto3.client("ec2", region_name=e1)
    vpc_ok = ec2.create_vpc(CidrBlock="10.10.0.0/16")["Vpc"]["VpcId"]
    ec2.create_flow_logs(ResourceIds=[vpc_ok], ResourceType="VPC", TrafficType="ALL",
                         LogDestinationType="s3", LogDestination="arn:aws:s3:::secure-logs-bucket")
    t.healthy.append(f"vpc {vpc_ok} with flow logs")
    vpc_bad = ec2.create_vpc(CidrBlock="10.20.0.0/16")["Vpc"]["VpcId"]; t.expect("NET-002", vpc_bad)
    subnet_ok = ec2.create_subnet(VpcId=vpc_ok, CidrBlock="10.10.1.0/24")["Subnet"]["SubnetId"]

    def sg(client, name, vpc, perms):
        """Create a security group (optionally with ingress rules) and return its id."""
        gid = client.create_security_group(GroupName=name, Description=name, VpcId=vpc)["GroupId"]
        if perms: client.authorize_security_group_ingress(GroupId=gid, IpPermissions=perms)
        return gid

    world = [{"CidrIp": "0.0.0.0/0"}]
    # Exposure context planted on purpose (the expected levels are written down here, by hand):
    #   open-ssh     -> protects an instance WITH a public IP          -> reachable        (1.0), 1 dependent
    #   open-all     -> protects a network interface with NO public IP -> partly           (0.5), 1 dependent
    #   open-rdp-v6  -> attached to nothing                            -> not reachable    (0.0), 0 dependents
    sg_ssh = sg(ec2, "open-ssh", vpc_ok, [dict(IpProtocol="tcp", FromPort=22, ToPort=22, IpRanges=world)])
    sg_all = sg(ec2, "open-all", vpc_ok, [dict(IpProtocol="-1", IpRanges=world)])
    sg_rdp = sg(ec2, "open-rdp-v6", vpc_ok, [dict(IpProtocol="tcp", FromPort=3389, ToPort=3389,
                                                 Ipv6Ranges=[{"CidrIpv6": "::/0"}])])
    t.expect("NET-001", sg_ssh, 1.0, 1); t.expect("NET-001", sg_all, 0.5, 1); t.expect("NET-001", sg_rdp, 0.0, 0)
    private_nic = ec2.create_network_interface(SubnetId=subnet_ok, Groups=[sg_all])["NetworkInterface"]["NetworkInterfaceId"]
    sg(ec2, "web-https", vpc_ok, [dict(IpProtocol="tcp", FromPort=443, ToPort=443, IpRanges=world)])
    t.healthy.append("security group web-https (443 open is allowed)")
    sg(ec2, "office-ssh", vpc_ok, [dict(IpProtocol="tcp", FromPort=22, ToPort=22, IpRanges=[{"CidrIp": "203.0.113.0/24"}])])
    t.healthy.append("security group office-ssh (22 from one trusted range)")

    ami = ec2.describe_images()["Images"][0]["ImageId"]
    bad = ec2.run_instances(ImageId=ami, MinCount=1, MaxCount=1, MetadataOptions={"HttpTokens": "optional"},
                            NetworkInterfaces=[dict(DeviceIndex=0, SubnetId=subnet_ok, Groups=[sg_ssh],
                                                    AssociatePublicIpAddress=True)],
                            UserData="#!/bin/bash\nDB_PASSWORD=hunter2\n")["Instances"][0]["InstanceId"]
    good = ec2.run_instances(ImageId=ami, MinCount=1, MaxCount=1, MetadataOptions={"HttpTokens": "required"},
                             BlockDeviceMappings=[{"DeviceName": "/dev/sda1", "Ebs": {"VolumeSize": 8, "Encrypted": True}}]
                             )["Instances"][0]["InstanceId"]
    t.expect("CMP-001", bad); t.expect("CMP-002", bad); t.healthy.append(f"instance {good}")
    vols = {v["Attachments"][0]["InstanceId"]: v for v in ec2.describe_volumes()["Volumes"] if v["Attachments"]}
    t.expect("CMP-003", vols[bad]["VolumeId"])
    assert vols[good]["Encrypted"], "moto did not honour the encrypted root volume"

    ec2b = boto3.client("ec2", region_name=e2)
    vpc_eu = ec2b.describe_vpcs()["Vpcs"][0]["VpcId"]
    t.expect("NET-001", sg(ec2b, "eu-open-mysql", vpc_eu, [dict(IpProtocol="tcp", FromPort=3306, ToPort=3306, IpRanges=world)]),
             0.0, 0)                                                # attached to nothing -> not reachable
    t.expect("CMP-003", ec2b.create_volume(AvailabilityZone=e2 + "a", Size=8, Encrypted=False)["VolumeId"])

    rds = boto3.client("rds", region_name=e1)
    rds.create_db_instance(DBInstanceIdentifier="db-bad", DBInstanceClass="db.t3.micro", Engine="mysql",
                           MasterUsername="admin", MasterUserPassword="Passw0rd12345", AllocatedStorage=20,
                           PubliclyAccessible=True, StorageEncrypted=False, BackupRetentionPeriod=0)
    for r in ("DB-001", "DB-002", "DB-003"): t.expect(r, "db-bad", 1.0 if r == "DB-001" else None)
    rds.create_db_instance(DBInstanceIdentifier="db-good", DBInstanceClass="db.t3.micro", Engine="mysql",
                           MasterUserPassword="Passw0rd12345", MasterUsername="admin", AllocatedStorage=20,
                           PubliclyAccessible=False, StorageEncrypted=True, BackupRetentionPeriod=14)
    t.healthy.append("rds db-good")

    # ---------------- IAM ----------------
    iam.create_policy(PolicyName="AllowEverything", PolicyDocument=json.dumps(ADMIN_DOC))
    t.expect("IAM-001", "AllowEverything", 0.0, 4)       # blast radius: used by role-admin, user carol, groups ops-team and dev-team
    iam.create_policy(PolicyName="ReadS3Only", PolicyDocument=json.dumps(S3_DOC)); t.healthy.append("policy ReadS3Only")
    for u in ("alice", "bob", "carol"): iam.create_user(UserName=u)
    iam.create_login_profile(UserName="alice", Password="Passw0rd!x23")
    iam.create_login_profile(UserName="bob", Password="Passw0rd!x23")
    t.expect("IAM-002", "alice")
    mfa = iam.create_virtual_mfa_device(VirtualMFADeviceName="bob-mfa")["VirtualMFADevice"]["SerialNumber"]
    iam.enable_mfa_device(UserName="bob", SerialNumber=mfa, AuthenticationCode1="123456", AuthenticationCode2="654321")
    with freeze_time(SIM_NOW - timedelta(days=200)):
        iam.create_access_key(UserName="alice")
    t.expect("IAM-003", "alice")
    with freeze_time(SIM_NOW - timedelta(days=10)):
        iam.create_access_key(UserName="carol")
    t.healthy += ["user bob (console + MFA)", "user carol (new key, no console)"]

    # ---------------- KMS ----------------
    kms = boto3.client("kms", region_name=e1)
    k_off = kms.create_key(Description="rotation-off")["KeyMetadata"]["KeyId"]; t.expect("KMS-001", k_off)
    k_on = kms.create_key(Description="rotation-on")["KeyMetadata"]["KeyId"]
    kms.enable_key_rotation(KeyId=k_on); t.healthy.append("kms key with rotation")
    # Simulator quirk: moto reports its built-in EBS default key as CUSTOMER-managed (real AWS says AWS-managed),
    # so a correct scanner must flag it here. Listed explicitly so the ground truth stays honest.
    for k in kms.list_keys()["Keys"]:
        if k["KeyId"] not in (k_off, k_on):
            meta = kms.describe_key(KeyId=k["KeyId"])["KeyMetadata"]
            if meta["KeyManager"] == "CUSTOMER": t.expect("KMS-001", k["KeyId"])

    # ---------------- Lambda ----------------
    iam.create_role(RoleName="role-admin", AssumeRolePolicyDocument=json.dumps(TRUST))
    admin_arn = [p["Arn"] for p in iam.list_policies(Scope="Local")["Policies"] if p["PolicyName"] == "AllowEverything"][0]
    s3_arn = [p["Arn"] for p in iam.list_policies(Scope="Local")["Policies"] if p["PolicyName"] == "ReadS3Only"][0]
    iam.attach_role_policy(RoleName="role-admin", PolicyArn=admin_arn)
    iam.attach_user_policy(UserName="carol", PolicyArn=admin_arn)           # three more dependents of the admin policy
    for grp in ("ops-team", "dev-team"):
        iam.create_group(GroupName=grp); iam.attach_group_policy(GroupName=grp, PolicyArn=admin_arn)
    iam.create_role(RoleName="role-small", AssumeRolePolicyDocument=json.dumps(TRUST))
    iam.attach_role_policy(RoleName="role-small", PolicyArn=s3_arn)
    lam = boto3.client("lambda", region_name=e1)
    mk = lambda name, role, env: lam.create_function(
        FunctionName=name, Runtime="python3.12", Role=f"arn:aws:iam::123456789012:role/{role}",
        Handler="lambda_function.handler", Code={"ZipFile": _zip()}, Environment={"Variables": env})
    mk("fn-admin", "role-admin", {"DB_PASSWORD": "x", "LOG_LEVEL": "info"})
    t.expect("FN-001", "fn-admin", 0.0, 1); t.expect("FN-002", "fn-admin")   # the admin role runs only this one function
    mk("fn-ok", "role-small", {"LOG_LEVEL": "info"}); t.healthy.append("lambda fn-ok")

    # ---------------- CloudTrail ----------------
    ct = boto3.client("cloudtrail", region_name=e1)
    ct.create_trail(Name="trail-weak", S3BucketName="secure-logs-bucket", IsMultiRegionTrail=False)
    t.expect("LOG-002", "trail-weak")
    ct.create_trail(Name="trail-strong", S3BucketName="secure-logs-bucket", IsMultiRegionTrail=True,
                    EnableLogFileValidation=True)
    t.healthy.append("trail-strong")
    return t
