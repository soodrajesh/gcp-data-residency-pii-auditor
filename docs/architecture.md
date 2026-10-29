# Architecture

```
BigQuery (datasets: location, ACL, CMEK, expiration; tables: schema, rows)      GCS (buckets: location, public?, CMEK; CSV/JSONL/TSV/text objects)
        |  first 50 rows of native tables (allow-listed datasets only)               first 64 KB of up to 40 objects (allow-listed buckets only)
        v                                                                             v
   [detectors]  validated matches: email, phone, SSN (area rules), card (Luhn), IBAN (mod 97), public IPv4   -> counts + masked examples; values dropped
   [classify]   per column: values + names; evidence = name+values | values | name_only | none; class = public/internal/confidential/restricted
        |       type-aware names (flags and counts are not PII); undocumented = PII values under a name that does not say so
   [policy]     residency by class, CMEK for restricted, readers on restricted, expiration, access level from the dataset ACL
        |
   findings P001 residency | P002 access | P003 encryption | P004 retention | P005 undocumented PII
        |
   parallel [explainer]  note from REDACTED metadata (asset, location, column names, PII types, access level); output validated
        |
   posture: violations (any high/critical) | attention | compliant   (rules only)
```

**No raw value is kept.** `detectors.scan_values` counts validated matches and keeps at most two masked examples per type (card/SSN/IBAN/phone show the last four digits; emails `a***@e***.com`; IPs two octets).
The Asset/Column models have no value field, so the API, UI, logs and models cannot receive one. Tests assert that no planted value (raw or space-stripped) appears in a report, a response or a model payload.

**Classification.** A type owns a column when at least half of the sampled non-null values pass its validator. Names add evidence (`name+values`) or stand alone (`name_only`, low confidence). Sampled values disprove a validated name
(`email` containing no emails is not PII) but cannot disprove names, addresses or dates of birth, which have no pattern. Flag/count/category names and non-text types are excluded.

**Policy** is JSON (`PII_POLICY` / `--policy`): `residency` per class (`US` covers the multi-region and `us-*`, `EU` covers `EU` and `europe-*`), `require_cmek`, `max_readers_restricted`, `require_expiration`.
Severity starts from the class (restricted high, confidential medium); a location violation on restricted data is critical; public access is always critical.

**Access** is read from dataset ACL entries: public (allAuthenticatedUsers/allUsers), broad (a domain, three or more groups, or ten or more principals), limited otherwise; project role groups are listed, not expanded.
