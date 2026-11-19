# Group 31 - Python-Based Cloud Risk Assessment System
## Milestone 4: Module Integration - How to run the project

| Member | Enrolment no. |
|---|---|
| Ayush Kumar Yadav | E23CSEU0598 |
| Manvendra Negi | E23CSEU1239 |
| Artham Parashar | E23CSEU1695 |
| Mitali Bhatt | E23CSEU2191 |

### What the project does

The project is a **read-only** scanner for AWS misconfigurations. It reads the settings of a cloud account and checks them against **20 security rules** (S3, IAM, EC2/VPC, RDS, KMS, Lambda, CloudTrail). Each finding gets a 0-10 risk score that takes **exposure** and **blast radius** into account. Findings are mapped to CIS, NIST CSF and ISO 27001. Each scan is saved to SQLite so it can be compared with the previous one (drift), and the results are written as HTML, JSON and CSV reports.

In Milestone 4, all the modules work together as one system through a single call, `assess()`:

```
Authentication -> Collector -> Rule engine -> Risk scoring -> Compliance -> Storage (drift) -> Reporting
 (read-only)      39 resources   31 findings    0-10 scores    CIS/NIST/ISO   SQLite history     HTML/JSON/CSV
```

**You do not need an AWS account or credentials.** The project includes a simulated AWS account, built with the `moto` library, that has planted security mistakes. Every run scans the same account, so you get the same results as in our demonstration video.

---

### Folder contents

```
GroupNumber_31/
├── HOW_TO_RUN.md                     <- this file
├── notebook/
│   ├── Milestone4_Module_Integration.ipynb                 <- the notebook shown in the video (run this)
│   └── Milestone4_Module_Integration_with_outputs.ipynb    <- same notebook with all outputs already filled in
├── expected_results/                 <- reports produced by our run, for comparison
│   ├── report.html  report.json  report.csv
│   └── demo_output.txt               <- console output of run_demo.py
└── project/                          <- the same code as plain Python files, to run on a computer
    ├── src/cra/                      <- the modules (auth, collector, rules, scoring, compliance,
    │                                    storage, reporting, exposure_graph, evaluation, pipeline, cli)
    ├── config/                       <- thresholds.yaml, scoring.yaml, suppressions.yaml, standards_map.yaml
    ├── tests/                        <- 46 automated tests (unit + integration)
    ├── requirements.txt
    ├── run_demo.py                   <- the final integrated demo (Part B of the video)
    ├── setup.bat / run_demo.bat / run_tests.bat     (Windows)
    └── setup.sh  / run_demo.sh  / run_tests.sh      (Mac / Linux)
```

There are two ways to run it. **Option A matches the video exactly**, because the video was recorded from this notebook.

---

## Option A - Google Colab (recommended, nothing to install)

1. Open https://colab.research.google.com and choose **File -> Upload notebook**.
2. Upload `notebook/Milestone4_Module_Integration.ipynb`.
3. Click **Runtime -> Run all**. The whole notebook takes about **2-3 minutes**. The first cell installs the libraries, and the tests in Section 9 take about one minute.
4. Scroll through the sections in the same order as the video:
   * **Section 1:** installs the libraries and writes every module as a `.py` file.
   * **Section 2:** architecture and data contracts between the layers.
   * **Part A, Section 3:** each module on its own with a short demo: configuration, authentication, collector, rule engine, scoring, compliance, storage and reporting.
   * **Part B:** the final integrated system in one `assess()` call, with the data-flow table.
   * **Sections 4-6:** data flow stage by stage, one resource followed through every layer, exposure and blast radius, and the graph.
   * **Section 7:** two scans with drift (resolved and new findings), the saved report and the same run from the command line.
   * **Section 8:** four scenarios showing how a change in one component affects the others.
   * **Section 9:** the integration tests (**46 passed**).
5. The reports are saved in the Colab file panel (folder icon on the left) under `project/reports/`. The cell in Section 7 downloads them as a zip.

The notebook also runs in local Jupyter or VS Code with Python 3.10+. Open it and choose **Run All**.

---

## Option B - Run on your own computer

**Needed:** Python **3.10 or newer**, tested with 3.11 and 3.13. Check with `python --version`. You also need internet access once, to install the libraries.

### Windows
1. Open the `project` folder.
2. Double-click **`setup.bat`**. It creates a private environment in `.venv` and installs the libraries from `requirements.txt`. This takes 1-3 minutes and only needs to be done once.
3. Double-click **`run_demo.bat`**. It runs the integrated demo and opens `reports\report.html` in your browser.
4. Optional: double-click **`run_tests.bat`** to run all 46 tests.

### Mac / Linux
```
cd project
bash setup.sh        # once
bash run_demo.sh     # integrated demo, opens reports/report.html
bash run_tests.sh    # 46 tests
```

### Manual commands (any system)
```
cd project
python -m venv .venv
.venv\Scripts\activate            (Windows)     or     source .venv/bin/activate   (Mac/Linux)
pip install -r requirements.txt
python run_demo.py                                   # integrated demo
python -m pytest -q                                  # tests
```

### Command-line interface (same system, one command)
```
Windows:    set PYTHONPATH=src  &&  python -m cra scan --demo --out reports_cli --db cli_history.db --label demo-run
Mac/Linux:  PYTHONPATH=src python -m cra scan --demo --out reports_cli --db cli_history.db --label demo-run
```
`--demo` scans the built-in simulated account. Against a real AWS account with read-only credentials configured, leave `--demo` out, for example `--regions us-east-1`.

---

## Expected results (as in the video)

When `run_demo.py` runs, or Part B and Section 7 of the notebook, you should see:

| What | Expected value |
|---|---|
| Data flow | Authentication(1) -> Collector(**39** resources, 82 read-only API calls) -> Rule engine(**31** findings from 65 checks, 2 suppressed) -> Scoring(31) -> Compliance(31) -> Storage(31) -> Reporting(**3** files) |
| Posture score, scan 1 | **21.7 / 100** |
| Active / suppressed findings | **29 / 2** |
| Read-only proof | 82 calls, **0 blocked writes**, `all_read_only: True` |
| Top finding | **10.0 CRITICAL S3-001 prod-customer-data** (public bucket holding sensitive data) |
| Accuracy vs planted answer key | TP=29, FP=0, FN=0, precision **1.00**, recall **1.00** |
| Drift, scan 2 | resolved: `S3-003\|team-notes`. New: 4 findings on `new-risky-bucket`. Still open: 28. Posture 21.7 -> 17.7 |
| Reports | `reports/report.html`, `report.json`, `report.csv` |
| Tests | **46 passed** |

The full console output from our run is in `expected_results/demo_output.txt`, and the reports it produced are in `expected_results/`.

Notes:
* The posture score, findings and scores are the same on every run. The simulated account uses a fixed date and fixed planted mistakes.
* Some resource IDs, such as VPC and security group IDs, are random in the simulated account, so they differ between runs. Bucket, user and policy names are fixed. Timestamps in the history table are the time you run it.

---

## Troubleshooting

| Problem | Fix |
|---|---|
| `python` is not recognised (Windows) | Install Python from python.org and tick **"Add python.exe to PATH"** during setup, then run `setup.bat` again. |
| `ModuleNotFoundError: cra` | Run from inside the `project` folder, or use `run_demo.py`, which sets the path itself. For the CLI, set `PYTHONPATH=src`. |
| A pip install error | Upgrade pip with `python -m pip install --upgrade pip`, then run setup again. Python 3.10+ is required. |
| A Colab cell fails | Run **Runtime -> Restart and run all**. You can also compare with `Milestone4_Module_Integration_with_outputs.ipynb`. |
