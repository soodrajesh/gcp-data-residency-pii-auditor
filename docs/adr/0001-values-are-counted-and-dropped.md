# ADR 0001: values are counted and dropped

**Decision**: detectors validate and count matches and keep at most two masked examples per type; no model has a value field for personal data, and models see only redacted metadata.
**Why**: a PII auditor that stores or ships what it finds becomes a copy of the data it is meant to protect, and sending samples to a model vendor would itself be a disclosure.
**Consequence**: findings are evidence about columns, not a copy of rows; examples show at most the last four digits.
