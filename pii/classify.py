"""Column and table classification from names and validated value matches. Deterministic; a model may only help
label ambiguous column NAMES (never values) and never changes a class that rules produced."""

from __future__ import annotations

import re

from . import detectors as d
from .models import CLASS_RANK, Asset, ColumnPII

FLAG_NAME = re.compile(
    r"^(is|has|was|can|should|needs?)_|(_flag|_indicator|_count|_status|_type|_code|_ind|_cnt)$",
    re.I,
)
NON_TEXT_TYPES = {"BOOL", "BOOLEAN", "FLOAT", "FLOAT64", "TIMESTAMP", "TIME"}

MATCH_RATIO = (
    0.5  # a type "owns" a column when at least this share of sampled non-null values match
)


def classify_column(name: str, col_type: str, values: list[str | None] | None) -> ColumnPII:
    hints = d.name_types(name)
    # A flag, count or category column that merely mentions PII (`is_credit_card`, `has_email`, `card_type`) is not PII, and
    # booleans/floats/timestamps cannot hold an email, a card number or an SSN. Only a date can be a date of birth.
    if FLAG_NAME.search(name) or col_type.upper() in NON_TEXT_TYPES:
        hints = []
    elif col_type.upper() in ("DATE", "DATETIME"):
        hints = [h for h in hints if h == "date_of_birth"]
    col = ColumnPII(column=name, type=col_type)
    stats = d.scan_values(values) if values else None
    pii_from_values: list[str] = []
    if stats and stats.sampled:
        col.sampled = stats.sampled
        for t, n in stats.matched.items():
            if n / stats.sampled >= MATCH_RATIO:
                pii_from_values.append(t)
                col.matched = max(col.matched, n)
                col.examples = (col.examples + stats.examples.get(t, []))[:2]
    if pii_from_values:
        col.pii_types = sorted(pii_from_values)
        col.evidence = (
            "name+values" if any(h in hints for h in pii_from_values) or hints else "values"
        )
        col.undocumented = not hints
    elif hints:
        col.pii_types = sorted(hints)
        col.evidence = "name_only"
    if col.pii_types:
        col.data_class = max((d.CLASS_OF[t] for t in col.pii_types), key=lambda c: CLASS_RANK[c])  # type: ignore[arg-type]
        if col.evidence == "name_only" and col.sampled:
            # Sampled values did not confirm the name. For types a value check can disprove (email, phone, SSN, card, IBAN, IP) that
            # means "not PII"; names, addresses, dates of birth and locations cannot be validated by pattern, so the name stands.
            kept = [t for t in col.pii_types if t not in d.VALIDATORS]
            col.pii_types = kept
            if kept:
                col.data_class = max((d.CLASS_OF[t] for t in kept), key=lambda c: CLASS_RANK[c])  # type: ignore[arg-type]
            else:
                col.data_class, col.evidence = "internal", "none"
    return col


def classify_asset(asset: Asset) -> Asset:
    asset.data_class = max(
        (c.data_class for c in asset.columns), key=lambda c: CLASS_RANK[c], default="internal"
    )
    return asset
