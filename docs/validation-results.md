# Validation against real GCP resources

## 1. Planted canaries (ground truth)

FAKE personal data (valid formats: Luhn-valid test cards, SSN-shaped numbers that pass the area rules, checksummed IBANs, example.* emails) was loaded into real BigQuery tables and a
private bucket created by Terraform (`terraform apply`, then `validation/plant.sh plant`). Policy: restricted data US-only, customer-managed keys required for restricted data.

| Asset (location) | Planted personal data | Detected | Benign columns |
|---|---|---|---|
| `pii_canary_us.customers` (US) | full_name, email, phone, ssn, card_number, signup_ip, **contact_info** (emails under a name that does not say so) | 7 of 7 | `customer_id`, `plan` not flagged |
| `pii_canary_eu.patients` (EU) | email, iban, birth_date | 3 of 3 | `patient_id`, `visit_note` not flagged |
| `gs://…-pii-canary/exports/people.csv` (US-CENTRAL1) | name, email, phone, ssn | 4 of 4 | `id` not flagged |
| `pii_canary_us.orders`, `pii_canary_us.events`, `docs/notes.txt` | none | no PII reported (`is_credit_card` is a BOOL flag; `payment_type`, `sku_code`, `status` are not PII) | |

**Recall 14/14 columns, 0 false positives among the other 14 columns and 3 benign assets.** Expected policy findings all fired: P001 (restricted data in EU), P003 x3 (no CMEK),
P005 (undocumented PII in `contact_info`); none of P002 because the canaries have limited access by design. Local and deployed results were identical, and the deployed response body was checked
to contain none of the planted values.

## 2. A real dataset: what running it on your own project found

Auditing the project's real `lakehouse` dataset (two external tables over GCS, taxi data) with `--no-sample` first reported **a restricted, unencrypted `silver_trips.is_credit_card`**: a false positive, because
`is_credit_card` is a payment-method flag, not card numbers. Name-based classification is now type-aware (booleans, floats and timestamps cannot hold PII) and ignores flag/count/category names
(`is_`, `has_`, `_type`, `_flag`, `_count`...), with regression tests. After the fix the dataset audits as compliant with no personal data, which matches what the data is.

## 3. Findings from running it that were fixed

1. The `is_credit_card` false positive above.
2. External tables and views were skipped entirely (`type == TABLE` only), so a real dataset looked empty; they are now audited by schema (sampling is for native tables only).
3. Names and addresses (types with no value validator) were erased when sampled values did not match; they now keep their name-based class.
4. An unreadable bucket IAM policy was treated as "not public" (fail-open); it is now reported as unknown. The runtime identity also lacked `storage.buckets.get` on the deployed service, which showed up as a degraded GCS source and was fixed with a bucket-scoped read-only grant.
5. Domain-wide dataset access could not be canaried live (BigQuery rejects invalid domains, and a real domain could belong to someone), so the broad and public access rules are covered by unit tests only.
