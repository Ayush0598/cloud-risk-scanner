# Cloud Risk Assessment System

A **read-only** Python scanner that audits an AWS account for security misconfigurations, ranks each finding by real risk, and maps it to compliance standards.

Most cloud breaches come from misconfiguration, such as a public storage bucket or a database open to the internet, rather than from advanced hacking. This tool checks those settings automatically and repeatably, and shows what changed since the last scan.

**No AWS account needed to try it:** the project includes a simulated AWS account (built with [moto](https://github.com/getmoto/moto)) with planted security mistakes, so every run gives the same, verifiable results.

## Results on the simulated account

| Metric | Result |
| --- | --- |
| Security rules | 20, across storage, network, compute, databases, identity, encryption keys, logging and serverless |
| Planted misconfigurations found | **29 of 29** (precision 1.00, recall 1.00, 0 false alarms) |
| API calls made | 82, all read-only (0 write attempts) |
| Automated tests | **46 passing** (unit and integration) |
| Code coverage | **92%** |

## How it works

```text
Authentication ─► Collector ─► Rule engine ─► Risk scoring ─► Compliance ─► Storage (drift) ─► Reporting
 (read-only)      39 resources   31 findings    0-10 scores    CIS/NIST/ISO   SQLite history     HTML/JSON/CSV
```

The whole pipeline runs in one call, `assess()`.

| Module (`project/src/cra/`) | Job |
| --- | --- |
| `auth.py` | Read-only session with a guard that blocks any API call that isn't Get, List or Describe, and records every call |
| `collector.py` | Gathers configuration of S3, IAM, EC2/VPC, RDS, KMS, Lambda and CloudTrail; marks a service "could not check" instead of failing when access is denied |
| `rules.py` | The 20 security rules (for example public S3 buckets, SSH open to the world, public databases, old access keys, missing CloudTrail) |
| `scoring.py`, `exposure_graph.py` | 0-10 risk score from likelihood and impact, adjusted for **internet exposure** and **blast radius** (what else an attacker could reach) |
| `compliance.py` | Maps each finding to CIS, NIST CSF and ISO 27001 controls |
| `storage.py` | Saves each scan to SQLite and reports **drift**: resolved, new and still-open findings |
| `reporting.py` | HTML report with charts, plus JSON and CSV |
| `pipeline.py`, `cli.py` | Runs everything end to end, from Python or the command line |
| `config/*.yaml` | Thresholds, scoring weights, standards mapping and suppressions, all editable without code changes |

## Quick start

Python 3.10 or newer.

**Windows:** open `project/`, run `setup.bat` once, then `run_demo.bat`. Run `run_tests.bat` for the tests.

**Mac / Linux:**

```bash
cd project
bash setup.sh
bash run_demo.sh
bash run_tests.sh
```

The demo runs two scans: a baseline, then another after one problem is fixed and a new risky bucket is created. It prints the drift between them and writes `reports/report.html`. Sample outputs are in [`expected_results/`](expected_results/).

A notebook version that walks through every module is in [`notebook/`](notebook/) and runs in Google Colab with nothing to install. Full instructions: [`HOW_TO_RUN.md`](HOW_TO_RUN.md).

## Tech stack

Python · boto3 · moto · pydantic · SQLAlchemy / SQLite · Jinja2 · pandas · matplotlib · rich · click · pytest · freezegun

## Limitations and next steps

Validated on a simulated account, not yet on a real production account. AWS only, 20 rules. Next steps: more rules, Azure and GCP support, scheduled scans in CI, and a web dashboard.

## Team

Group 31, Bennett University: Ayush Kumar Yadav · Manvendra Negi · Artham Parashar · Mitali Bhatt
