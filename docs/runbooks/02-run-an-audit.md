# Runbook 02: run an audit

- **UI/API**: `POST /api/audits {"project": "...", "datasets": [...], "buckets": [...], "sample": true}`; only allow-listed projects, datasets and buckets are accepted.
- **CLI (your credentials)**: `pii audit <project> --dataset d --bucket b --policy policy.json`; `--no-sample` classifies by column names only and reads no data.
- Exit codes: 0 compliant, 1 attention, 2 violations, 3 error. Output lists column names, PII types, counts and masked examples only.
Start with `--no-sample` on a new dataset to inventory it without reading rows; sample only where you have a reason to.
