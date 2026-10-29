"""Read-only collection of BigQuery and Cloud Storage metadata and bounded samples. Sample values are handed straight
to the detectors by the caller and are never stored."""

from __future__ import annotations

import csv
import io
import json
from typing import Any

from .models import SourceStat

BQ = "https://bigquery.googleapis.com/bigquery/v2"
GCS = "https://storage.googleapis.com/storage/v1"
SAMPLE_ROWS = 50
MAX_TABLES = 60
MAX_OBJECT_BYTES = 65_536
TEXT_EXT = (".csv", ".json", ".jsonl", ".ndjson", ".txt", ".tsv")


class SourceError(RuntimeError):
    pass


def session():
    import google.auth
    from google.auth.transport.requests import AuthorizedSession

    creds, _ = google.auth.default(scopes=["https://www.googleapis.com/auth/cloud-platform"])
    return AuthorizedSession(creds)


def _get(s, url: str, **kw) -> dict[str, Any]:
    r = s.get(url, timeout=60, **kw)
    if r.status_code != 200:
        raise SourceError(f"GET {url.split('//')[1][:70]} -> {r.status_code}: {r.text[:100]}")
    return r.json()


def datasets(s, project: str, only: list[str] | None = None) -> list[dict[str, Any]]:
    out = []
    for d in _get(s, f"{BQ}/projects/{project}/datasets", params={"maxResults": 100}).get(
        "datasets", []
    ):
        ds = d["datasetReference"]["datasetId"]
        if only is not None and ds not in only:
            continue
        out.append(_get(s, f"{BQ}/projects/{project}/datasets/{ds}"))
    return out


def tables(s, project: str, dataset: str) -> list[tuple[str, str]]:
    """(table id, type). Views and external tables have a schema but cannot be sampled with tabledata.list."""
    return [
        (t["tableReference"]["tableId"], t.get("type", "TABLE"))
        for t in _get(
            s, f"{BQ}/projects/{project}/datasets/{dataset}/tables", params={"maxResults": 100}
        ).get("tables", [])
        if t.get("type", "TABLE") in ("TABLE", "EXTERNAL", "VIEW", "MATERIALIZED_VIEW", "SNAPSHOT")
    ]


def table_meta(s, project: str, dataset: str, table: str) -> dict[str, Any]:
    return _get(s, f"{BQ}/projects/{project}/datasets/{dataset}/tables/{table}")


def sample_rows(
    s, project: str, dataset: str, table: str, schema: list[dict[str, Any]], n: int = SAMPLE_ROWS
) -> dict[str, list[str | None]]:
    """First n rows by column. Returns values transiently for the detectors; the caller must not keep them."""
    d = _get(
        s,
        f"{BQ}/projects/{project}/datasets/{dataset}/tables/{table}/data",
        params={"maxResults": n},
    )
    cols: dict[str, list[str | None]] = {f["name"]: [] for f in schema}
    names = [f["name"] for f in schema]
    for row in d.get("rows", []) or []:
        for name, cell in zip(names, row.get("f", []), strict=False):
            v = cell.get("v")
            cols[name].append(None if v is None else (v if isinstance(v, str) else json.dumps(v)))
    return cols


def buckets(s, project: str, only: list[str]) -> list[dict[str, Any]]:
    return [_get(s, f"{GCS}/b/{b}") for b in only]


def bucket_public(s, bucket: str) -> bool | None:
    """True/False, or None when the bucket's IAM policy cannot be read (public access is then UNKNOWN, never assumed absent)."""
    try:
        pol = _get(s, f"{GCS}/b/{bucket}/iam")
    except SourceError:
        return None
    return any(
        m in ("allUsers", "allAuthenticatedUsers")
        for b in pol.get("bindings", [])
        for m in b.get("members", [])
    )


def objects(
    s, bucket: str, stat: SourceStat, limit: int = 40
) -> list[tuple[str, dict[str, list[str | None]]]]:
    """(object name, columns) for CSV/JSONL/text objects, using only the first 64 KB."""
    out = []
    for o in _get(s, f"{GCS}/b/{bucket}/o", params={"maxResults": limit}).get("items", []):
        name = o["name"]
        if not name.lower().endswith(TEXT_EXT) or name.endswith("/"):
            stat.skipped += 1
            continue
        r = s.get(
            f"{GCS}/b/{bucket}/o/{name.replace('/', '%2F')}",
            params={"alt": "media"},
            headers={"Range": f"bytes=0-{MAX_OBJECT_BYTES - 1}"},
            timeout=60,
        )
        if r.status_code not in (200, 206):
            stat.skipped += 1
            continue
        stat.scanned += 1
        out.append((name, _columns(name, r.content.decode("utf-8", "ignore"))))
    return out


def _columns(name: str, text: str) -> dict[str, list[str | None]]:
    cols: dict[str, list[str | None]] = {}
    lower = name.lower()
    if lower.endswith((".json", ".jsonl", ".ndjson")):
        for line in text.splitlines():
            try:
                row = json.loads(line)
            except ValueError:
                continue
            if isinstance(row, dict):
                for k, v in row.items():
                    cols.setdefault(str(k), []).append(None if v is None else str(v))
        return cols
    delim = "\t" if lower.endswith(".tsv") else ","
    rows = list(csv.reader(io.StringIO(text), delimiter=delim))
    if len(rows) >= 2:
        header = rows[0]
        for i, h in enumerate(header):
            cols[h.strip()] = [r[i] if i < len(r) else None for r in rows[1:51]]
    return cols
