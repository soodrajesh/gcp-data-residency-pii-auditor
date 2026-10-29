# Runbook 03: fix a residency violation (P001)

BigQuery datasets cannot change location in place.
1. Create a dataset in an allowed location: `bq mk --location=US <project>:<new_dataset>`.
2. Copy the tables (`bq cp` across locations is not supported for datasets in different regions; use a dataset copy via the BigQuery Data Transfer Service, or export to a bucket in the target region and load).
3. Repoint consumers, verify, then delete the original dataset. Check logs and backups for copies in the old location.
4. Re-run the audit; P001 should be gone.
