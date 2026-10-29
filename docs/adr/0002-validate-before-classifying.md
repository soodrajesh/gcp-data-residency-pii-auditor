# ADR 0002: classify on validated values, and let validation disprove names

**Decision**: a PII type needs validated value matches (Luhn, area rules, mod 97) in at least half the sampled values; for types with a validator, sampled values override a misleading name.
**Why**: names alone over-report (`is_credit_card` was a boolean flag in a real dataset) and shapes alone over-report (16 digits is not a card number).
**Consequence**: types with no validator (names, addresses, dates of birth, locations) rely on column names and are marked lower-confidence.
