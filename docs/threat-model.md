# Threat model

The auditor reads samples of personal data. The risks are leaking them, over-broad read access, and sending them to a model vendor.

| Threat | Mitigation | Test |
|---|---|---|
| The auditor leaks personal data (reports, API, UI, CLI, logs) | no value fields; masked examples (last four digits only); errors log type only; CLI prints no exception text | `test_no_personal_value_appears_in_the_report_or_the_model_payload`, `test_api_scope_limits_and_no_values_in_responses`, `test_cli_error_path_prints_no_message` |
| Personal data reaches a model vendor | the explainer receives asset, location, column names, PII types and access level only; the eval audits every payload (raw and space-stripped values) | same test, `evals/run.py` |
| A model writes personal data, a link, a foreign asset or a false "public" claim | notes are rejected if a detector matches, if they link, name another asset, or claim public access that was not found | `test_notes_with_personal_data_links_foreign_assets_or_false_public_claims_are_rejected` |
| Auditing datasets or buckets it should not | project, dataset and bucket allow-lists (403 otherwise); row access is granted per canary dataset, metadata project-wide | `test_api_scope_limits_and_no_values_in_responses` |
| Unreadable policy treated as safe | an unreadable bucket IAM policy is reported as unknown | `test_an_unreadable_bucket_policy_is_reported_as_unknown_not_as_private` |
| Over-broad runtime identity | `bigquery.metadataViewer` (metadata), `dataViewer` on canary datasets only, `objectViewer`/`legacyBucketReader` on the canary bucket only, `iam.securityReviewer`; private service, one invoker | by design |
| Reports as a map of where personal data lives | masked, in memory, 30 most recent; keep the invoker role tight | by design |

Residual risk: the first 50 rows are not a statistical sample, so rare PII can be missed; and the locations of personal data are themselves sensitive.
