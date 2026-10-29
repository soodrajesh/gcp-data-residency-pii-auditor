"""CLI.  Exit codes: 0 compliant, 1 attention, 2 violations, 3 error.

    pii audit my-project --dataset customers --bucket my-bucket --policy policy.json
Output has column names, PII types, counts and masked examples only."""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from pathlib import Path

from pydantic import ValidationError

from .llm import Budget, LLMError, make_llm
from .models import Policy, Report
from .orchestrator import audit_project
from .sources import SourceError

EXIT = {"compliant": 0, "attention": 1, "violations": 2}
COLOR = {"critical": "1;31", "high": "31", "medium": "33", "low": "36", "info": "37"}


def render(r: Report, color: bool) -> str:
    def c(code, s):
        return f"\033[{code}m{s}\033[0m" if color else s

    out = [
        c(
            {"compliant": "32", "attention": "33", "violations": "1;31"}[r.posture],
            f"POSTURE: {r.posture.upper()}",
        ),
        r.summary,
        "",
    ]
    for a in r.assets:
        if a.data_class in ("confidential", "restricted"):
            cols = ", ".join(
                f"{x.column}[{'/'.join(x.pii_types)}]" for x in a.columns if x.pii_types
            )
            out.append(f"  {a.data_class:12} {a.name}  ({a.location or '?'})  {cols}")
    out.append("")
    for f in r.findings:
        out.append(f"{c(COLOR[f.severity], f.severity.upper().ljust(8))} {f.id:8} {f.title}")
        out.append(f"          {f.asset}: {f.detail}")
        out += [f"          -> {x}" for x in f.remediation[:1]]
        if f.note:
            out.append(f"          note: {f.note}")
    return "\n".join(out + [f"! {d}" for d in r.degraded])


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="pii")
    sub = ap.add_subparsers(dest="cmd", required=True)
    a = sub.add_parser(
        "audit", help="audit BigQuery datasets and GCS buckets in a project (read-only)"
    )
    a.add_argument("project")
    a.add_argument("--dataset", action="append")
    a.add_argument("--bucket", action="append")
    a.add_argument(
        "--no-sample", action="store_true", help="classify by column names only; read no data"
    )
    a.add_argument(
        "--policy",
        help="JSON file: {residency, require_cmek, max_readers_restricted, require_expiration}",
    )
    a.add_argument("--llm", default="none", choices=["none", "mock", "vertex", "openai"])
    a.add_argument("--format", default="text", choices=["text", "json"])
    args = ap.parse_args(argv)
    try:
        pol = (
            Policy.model_validate(json.loads(Path(args.policy).read_text()))
            if args.policy
            else Policy()
        )
        rep = asyncio.run(
            audit_project(
                args.project,
                make_llm(args.llm),
                pol=pol,
                datasets=args.dataset,
                buckets=args.bucket,
                sample=not args.no_sample,
                budget=Budget(),
            )
        )
    except (OSError, ValueError, ValidationError, LLMError, SourceError) as e:
        print(f"error: {type(e).__name__}", file=sys.stderr)
        return 3
    print(
        rep.model_dump_json(indent=1) if args.format == "json" else render(rep, sys.stdout.isatty())
    )
    return EXIT[rep.posture]


if __name__ == "__main__":
    sys.exit(main())
