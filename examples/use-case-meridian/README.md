# Use case fixtures — Meridian Capital catches a tool-poisoning attack

Concrete, runnable companion to [`docs/USE_CASE.md`](../../docs/USE_CASE.md).

## What's here

| File | Purpose |
|---|---|
| `policy.yaml` | The fictional company's `mcp-bastion` policy |
| `fake_github_mcp_day1.py` | Mock GitHub MCP server — benign tool descriptions |
| `fake_github_mcp_day30.py` | Same surface, but a poisoned tool description (the attack) |
| `drive.py` | Mock client that drives `mcp-bastion` like Claude Code does |
| `reproduce.sh` | One-shot: runs day-1 + day-30 + prints the audit log |

## Run it

From the repo root, with the venv active and `mcp-bastion` on `PATH`:

```bash
./examples/use-case-meridian/reproduce.sh
```

Expected:
- Day 1 run pins three tool descriptions cleanly.
- Day 30 run produces `s2c -> deny: tool description drift detected for: tool#c8956cd1`.
- The audit log shows the full forensic trail with `chain: OK`.

## Read the story

See [`docs/USE_CASE.md`](../../docs/USE_CASE.md) for the narrative.
