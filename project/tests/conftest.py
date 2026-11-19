import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

import boto3
import pytest

from cra.auth import ScanSession
from cra.config import load_config
from cra.pipeline import run_scan
from cra.simulation import REGIONS, SIM_NOW, SIM_TODAY, build_account, fake_aws


@pytest.fixture(scope="session")
def cfg():
    return load_config(ROOT / "config")


@pytest.fixture(scope="module")
def scanned(cfg):
    """One scan of the planted fake account, shared by the tests in a module."""
    with fake_aws():
        truth = build_account(boto3)
        ss = ScanSession(regions=REGIONS)
        result = run_scan(ss, cfg, now=SIM_NOW, today=SIM_TODAY)
    yield truth, result, ss
