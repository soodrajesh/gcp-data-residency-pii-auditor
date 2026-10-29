# Runbook 04: reduce access and tag columns (P002, P005)

- Remove broad principals from the dataset's access list (`bq show --format=prettyjson` to read it, `bq update --source` to apply a corrected list) and grant named groups.
- For analysts who need the table without the PII: an authorized view that selects only the non-PII columns, or column-level security with policy tags on the PII columns.
- For P005 (PII under a name that does not say so): rename or document the column, then tag it so controls follow the data.
