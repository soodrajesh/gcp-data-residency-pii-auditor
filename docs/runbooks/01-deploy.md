# Runbook 01: deploy

1. `cp deploy.env.example deploy.env`; `gcloud auth login`.
2. `./scripts/up.sh` (foundation, image, services; saved plans; destroys need `ALLOW_DESTROY=1`). Terraform creates canary datasets, tables and a bucket with fake data scaffolding.
3. `./validation/plant.sh plant` loads fake rows into the canary tables.
4. `gcloud run services proxy pii-auditor --region us-central1 --port 8081`.
5. For real use remove the canaries, set `PII_DATASETS`/`PII_BUCKETS` to what may be audited, grant `bigquery.dataViewer` on those datasets (and `objectViewer`/`legacyBucketReader` on those buckets) to the runtime identity, and set `PII_POLICY`.
