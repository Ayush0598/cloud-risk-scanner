#!/usr/bin/env bash
set -e
cd "$(dirname "$0")"
. .venv/bin/activate
python run_demo.py
( command -v xdg-open >/dev/null && xdg-open reports/report.html >/dev/null 2>&1 ) || ( command -v open >/dev/null && open reports/report.html >/dev/null 2>&1 ) || true
