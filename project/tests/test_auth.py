import boto3
import pytest

from cra.auth import ScanSession, WriteBlockedError, find_write_actions, mask_account
from cra.collector import collect
from cra.simulation import fake_aws


def test_mask_account():
    assert mask_account("123456789012") == "****9012"


def test_guard_blocks_writes_and_allows_reads():
    with fake_aws():
        ss = ScanSession(regions=["us-east-1"])
        assert ss.client("s3").list_buckets()["Buckets"] == []
        with pytest.raises(WriteBlockedError):
            ss.client("s3").create_bucket(Bucket="should-not-exist")
        assert ss.blocked == ["s3:CreateBucket"]
        assert boto3.client("s3").list_buckets()["Buckets"] == []      # nothing was created


def test_identity_is_masked():
    with fake_aws():
        who = ScanSession().identity()
        assert who["account"].startswith("****") and len(who["account"]) == 8


def test_denied_service_degrades_gracefully():
    with fake_aws():
        ss = ScanSession(regions=["us-east-1"])
        ss.simulate_denied("rds")
        inv = collect(ss)
        assert any("RDS" in n for n in ss.notes)
        assert not any(r.type == "rds_instance" for r in inv)


def test_static_policy_audit():
    safe = {"Statement": [{"Effect": "Allow", "Action": ["s3:GetObject", "iam:List*", "ec2:Describe*"], "Resource": "*"}]}
    risky = {"Statement": [{"Effect": "Allow", "Action": ["s3:PutObject", "ec2:*"], "Resource": "*"}]}
    assert find_write_actions(safe) == []
    assert set(find_write_actions(risky)) >= {"s3:PutObject", "ec2:*"}
