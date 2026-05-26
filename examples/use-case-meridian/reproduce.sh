#!/usr/bin/env bash
# Reproduces the Meridian Capital use case end to end.
# Requires `mcp-bastion` on PATH (pip install -e ".[dev]" from the repo root).
set -euo pipefail

cd "$(dirname "$0")"

# Clean prior state so the demo starts from zero
rm -f ~/.mcp-bastion/meridian-audit.sqlite ~/.mcp-bastion/meridian-audit.anchor.jsonl

echo "==================== DAY 1: legitimate upstream ===================="
python3 drive.py fake_github_mcp_day1.py
echo
echo "==================== DAY 30: poisoned upstream ====================="
python3 drive.py fake_github_mcp_day30.py
echo
echo "==================== AUDIT LOG ====================================="
mcp-bastion inspect-log --policy policy.yaml --verify --limit 12
