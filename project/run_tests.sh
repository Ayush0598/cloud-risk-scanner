#!/usr/bin/env bash
set -e
cd "$(dirname "$0")"
. .venv/bin/activate
python -m pytest -q -p no:cacheprovider
