from __future__ import annotations

import json
import os
from dataclasses import dataclass, field

from .models import Policy


def _list(name: str, default: str = "") -> tuple[str, ...]:
    return tuple(x.strip() for x in os.environ.get(name, default).split(",") if x.strip())


def _policy() -> Policy:
    raw = os.environ.get("PII_POLICY", "")
    return Policy.model_validate(json.loads(raw)) if raw else Policy()


@dataclass
class Settings:
    provider: str = field(default_factory=lambda: os.environ.get("PII_LLM", "mock"))
    model: str | None = field(default_factory=lambda: os.environ.get("PII_MODEL") or None)
    allowed_providers: tuple[str, ...] = field(
        default_factory=lambda: _list("PII_ALLOWED_PROVIDERS", "mock,none")
    )
    projects: tuple[str, ...] = field(default_factory=lambda: _list("PII_PROJECTS"))
    datasets: tuple[str, ...] = field(
        default_factory=lambda: _list("PII_DATASETS")
    )  # datasets that may be audited (and sampled)
    buckets: tuple[str, ...] = field(default_factory=lambda: _list("PII_BUCKETS"))
    policy: Policy = field(default_factory=_policy)
    daily_budget_usd: float = field(
        default_factory=lambda: float(os.environ.get("PII_DAILY_BUDGET_USD", 0.5))
    )
    max_llm_calls: int = 10
    review_budget_usd: float = 0.05
    max_body_bytes: int = 200_000
