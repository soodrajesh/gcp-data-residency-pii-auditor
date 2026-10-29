"""Models. There is no field that holds a raw data value: the auditor reports column names, PII types, match
counts and masked examples only."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field

Severity = Literal["info", "low", "medium", "high", "critical"]
SEV_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
SEVS = ["info", "low", "medium", "high", "critical"]
DataClass = Literal["public", "internal", "confidential", "restricted"]
CLASS_RANK = {"public": 0, "internal": 1, "confidential": 2, "restricted": 3}


class ColumnPII(BaseModel):
    column: str
    type: str  # BigQuery type or "text"
    pii_types: list[str] = Field(default_factory=list)  # e.g. ["email"]
    data_class: DataClass = "internal"
    evidence: Literal["name+values", "values", "name_only", "none"] = "none"
    sampled: int = 0
    matched: int = 0
    examples: list[str] = Field(default_factory=list)  # masked, at most 2
    undocumented: bool = False  # the values are PII but the column name gives no hint


class Asset(BaseModel):
    kind: Literal["bigquery_table", "gcs_object"]
    name: str  # dataset.table or gs://bucket/object
    location: str = ""
    container: str = ""  # dataset or bucket
    rows: int | None = None
    bytes: int | None = None
    sampled_rows: int = 0
    columns: list[ColumnPII] = Field(default_factory=list)
    data_class: DataClass = "internal"
    cmek: bool = False
    expires: bool = False
    note: str = ""


class Access(BaseModel):
    level: Literal["public", "broad", "limited", "unknown"] = "unknown"
    entries: list[str] = Field(default_factory=list)  # capped, human-readable
    principal_count: int = 0
    why: str = ""


class Finding(BaseModel):
    id: str = ""
    rule: str
    severity: Severity
    asset: str
    container: str
    title: str
    detail: str = ""
    data_class: DataClass = "internal"
    pii_types: list[str] = Field(default_factory=list)
    columns: list[str] = Field(default_factory=list)
    access: Access | None = None
    remediation: list[str] = Field(default_factory=list)
    note: str = ""  # validated model explanation (from redacted metadata only)


class SourceStat(BaseModel):
    kind: str
    scanned: int = 0
    skipped: int = 0
    note: str = ""


class TraceStep(BaseModel):
    agent: str
    action: str
    status: Literal["ok", "skipped", "error"] = "ok"
    start_ms: int = 0
    duration_ms: int = 0
    tokens_in: int = 0
    tokens_out: int = 0
    cost_usd: float = 0.0
    note: str = ""


class Policy(BaseModel):
    """What may live where. Locations are matched by group: `US` covers the US multi-region and us-* regions,
    `EU` covers the EU multi-region and europe-* regions; any other entry matches exactly."""

    residency: dict[str, list[str]] = Field(
        default_factory=lambda: {"restricted": ["US"], "confidential": ["US", "EU"]}
    )
    require_cmek: list[DataClass] = Field(default_factory=lambda: ["restricted"])
    max_readers_restricted: int = 10
    require_expiration: list[DataClass] = Field(default_factory=list)


class Report(BaseModel):
    id: str
    created_at: str
    project: str
    provider: str
    model: str
    posture: Literal["compliant", "attention", "violations"]
    summary: str
    policy: Policy
    assets: list[Asset] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)
    sources: list[SourceStat] = Field(default_factory=list)
    counts: dict[str, int] = Field(default_factory=dict)
    dropped: list[dict[str, str]] = Field(default_factory=list)
    degraded: list[str] = Field(default_factory=list)
    trace: list[TraceStep] = Field(default_factory=list)
    duration_ms: int = 0
