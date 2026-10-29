"""Build assets and findings from collected metadata and samples. Raw values exist only inside classify_column
(via detectors.scan_values) and are not kept."""

from __future__ import annotations

from typing import Any

from . import classify, policy
from .models import SEV_RANK, Access, Asset, ColumnPII, Finding, Policy

BASE_SEV = {"restricted": "high", "confidential": "medium"}
SENSITIVE = ("confidential", "restricted")


def bq_asset(
    dataset_meta: dict[str, Any],
    table_id: str,
    meta: dict[str, Any],
    samples: dict[str, list[str | None]] | None,
) -> Asset:
    schema = meta.get("schema", {}).get("fields", [])
    cols = [
        classify.classify_column(f["name"], f.get("type", "STRING"), (samples or {}).get(f["name"]))
        for f in schema
    ]
    a = Asset(
        kind="bigquery_table",
        name=f"{dataset_meta['datasetReference']['datasetId']}.{table_id}",
        container=dataset_meta["datasetReference"]["datasetId"],
        location=dataset_meta.get("location", ""),
        rows=int(meta["numRows"]) if meta.get("numRows") else None,
        bytes=int(meta["numBytes"]) if meta.get("numBytes") else None,
        sampled_rows=max((c.sampled for c in cols), default=0),
        columns=cols,
        cmek=bool(
            meta.get("encryptionConfiguration", {}).get("kmsKeyName")
            or dataset_meta.get("defaultEncryptionConfiguration", {}).get("kmsKeyName")
        ),
        expires=bool(meta.get("expirationTime") or dataset_meta.get("defaultTableExpirationMs")),
    )
    if samples is None:
        a.note = "not sampled: classification is by column name only"
    return classify.classify_asset(a)


def gcs_asset(
    bucket_meta: dict[str, Any], name: str, columns: dict[str, list[str | None]]
) -> Asset:
    cols = [classify.classify_column(c, "text", v) for c, v in columns.items()]
    return classify.classify_asset(
        Asset(
            kind="gcs_object",
            name=f"gs://{bucket_meta['name']}/{name}",
            container=bucket_meta["name"],
            location=bucket_meta.get("location", ""),
            sampled_rows=max((c.sampled for c in cols), default=0),
            columns=cols,
            cmek=bool(bucket_meta.get("encryption", {}).get("defaultKmsKeyName")),
        )
    )


def _pii_cols(a: Asset) -> list[ColumnPII]:
    return [c for c in a.columns if c.pii_types]


def evaluate(
    assets: list[Asset], pol: Policy, dataset_access: dict[str, Access], public_buckets: set[str]
) -> list[Finding]:
    out: list[Finding] = []
    for a in assets:
        if a.data_class not in SENSITIVE:
            continue
        cols = _pii_cols(a)
        types = sorted({t for c in cols for t in c.pii_types})
        names = [c.column for c in cols]
        base = BASE_SEV[a.data_class]
        conf = (
            "from values"
            if any(c.evidence != "name_only" for c in cols)
            else "from column names only (not sampled)"
        )

        def add(rule, sev, title, detail, remediation, access=None, a=a, types=types, names=names):
            out.append(
                Finding(
                    rule=rule,
                    severity=sev,
                    asset=a.name,
                    container=a.container,
                    title=title,
                    detail=detail,
                    data_class=a.data_class,
                    pii_types=types,
                    columns=names[:12],
                    access=access,
                    remediation=remediation,
                )
            )

        allowed = pol.residency.get(a.data_class, [])
        if allowed and a.location and not policy.location_allowed(a.location, allowed):
            add(
                "P001",
                policy.bump(base, 1 if a.data_class == "restricted" else 0),
                f"{a.data_class} data stored in {a.location}, outside the allowed locations {allowed}",
                f"PII types: {', '.join(types)} ({conf}).",
                [
                    f"Move or copy the data to an allowed location ({', '.join(allowed)}) and delete the original; BigQuery datasets cannot change location in place.",
                    "Create a replacement dataset in the allowed location: bq mk --location=<LOCATION> <dataset>, then load or copy the tables.",
                ],
            )
        acc = dataset_access.get(a.container) if a.kind == "bigquery_table" else None
        if a.kind == "gcs_object" and a.container in public_buckets:
            acc = Access(
                level="public",
                entries=["allUsers/allAuthenticatedUsers"],
                principal_count=-1,
                why="the bucket grants public access",
            )
        if acc and (
            acc.level in ("public", "broad")
            or (a.data_class == "restricted" and acc.principal_count > pol.max_readers_restricted)
        ):
            sev = (
                "critical"
                if acc.level == "public"
                else policy.bump(base, 1 if a.data_class == "restricted" else 0)
            )
            add(
                "P002",
                sev,
                f"{a.data_class} data readable by a {acc.level} audience",
                f"{acc.why}. PII types: {', '.join(types)} ({conf}).",
                [
                    "Remove broad principals from the dataset's access list; grant specific groups instead."
                    if a.kind == "bigquery_table"
                    else "Remove public access from the bucket (public access prevention).",
                    "Expose only what is needed through an authorized view or column-level policy tags that hide the PII columns.",
                ],
                acc,
            )
        if a.data_class in pol.require_cmek and not a.cmek:
            add(
                "P003",
                base,
                f"{a.data_class} data without a customer-managed encryption key",
                f"PII types: {', '.join(types)}.",
                [
                    "Create a Cloud KMS key in the same location and set it as the dataset/bucket default encryption key, then re-write the data."
                ],
            )
        if a.data_class in pol.require_expiration and not a.expires:
            add(
                "P004",
                "low",
                f"{a.data_class} data with no expiration",
                "No table, dataset default, or lifecycle expiration is set.",
                [
                    "Set a table or dataset default expiration (bq update --default_table_expiration) or a bucket lifecycle rule that matches your retention policy."
                ],
            )
        undocumented = [c.column for c in cols if c.undocumented]
        if undocumented:
            add(
                "P005",
                "medium",
                f"PII in column(s) whose names do not say so: {', '.join(undocumented[:6])}",
                "The values match validated PII patterns but the names give no hint, so name-based controls and reviews would miss them.",
                [
                    "Rename or document the columns, and attach policy tags so access controls follow the data."
                ],
            )
        if a.note:
            pass
    out.sort(key=lambda f: (-SEV_RANK[f.severity], f.rule, f.asset))
    counters: dict[str, int] = {}
    for f in out:
        counters[f.rule] = counters.get(f.rule, 0) + 1
        f.id = f"{f.rule}-{counters[f.rule]}"
    return out
