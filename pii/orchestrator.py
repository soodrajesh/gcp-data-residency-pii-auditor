"""collect -> classify (values dropped) -> evaluate policy -> parallel explainer -> posture"""

from __future__ import annotations

import asyncio
import time
import uuid
from datetime import UTC, datetime

from . import agents, audit, policy, sources
from .llm import LLM, Budget
from .models import SEV_RANK, Access, Asset, Finding, Policy, Report, SourceStat, TraceStep

TOP_EXPLAINED = 8


def collect(
    project: str, datasets_wanted: list[str] | None, buckets_wanted: list[str], sample: bool, s=None
):
    s = s or sources.session()
    assets: list[Asset] = []
    stats = [SourceStat(kind="bigquery"), SourceStat(kind="gcs")]
    degraded: list[str] = []
    dataset_access: dict[str, Access] = {}
    public_buckets: set[str] = set()
    try:
        for ds in sources.datasets(s, project, datasets_wanted):
            dsid = ds["datasetReference"]["datasetId"]
            dataset_access[dsid] = policy.access_level(ds.get("access", []))
            for t, ttype in sources.tables(s, project, dsid)[: sources.MAX_TABLES]:
                meta = sources.table_meta(s, project, dsid, t)
                samples = None
                if sample and ttype == "TABLE":
                    try:
                        samples = sources.sample_rows(
                            s, project, dsid, t, meta.get("schema", {}).get("fields", [])
                        )
                    except sources.SourceError as e:
                        degraded.append(
                            f"bigquery {dsid}.{t}: could not sample ({str(e)[:60]}); classified by column names only"
                        )
                stats[0].scanned += 1
                assets.append(audit.bq_asset(ds, t, meta, samples))
    except sources.SourceError as e:
        stats[0].note = f"failed: {e}"[:200]
        degraded.append(f"bigquery: {stats[0].note}")
    for b in buckets_wanted:
        try:
            meta = sources.buckets(s, project, [b])[0]
            pub = sources.bucket_public(s, b)
            if pub:
                public_buckets.add(b)
            elif pub is None:
                degraded.append(
                    f"gcs {b}: could not read the bucket IAM policy, so public access is unknown (not assumed absent)"
                )
            for name, cols in sources.objects(s, b, stats[1]):
                assets.append(audit.gcs_asset(meta, name, cols))
        except sources.SourceError as e:
            stats[1].note = f"failed: {e}"[:200]
            degraded.append(f"gcs {b}: {stats[1].note}")
    return assets, stats, dataset_access, public_buckets, degraded


def posture(findings: list[Finding]) -> str:
    sev = {f.severity for f in findings}
    return "violations" if sev & {"critical", "high"} else "attention" if findings else "compliant"


def summary(assets: list[Asset], findings: list[Finding]) -> str:
    sens = [a for a in assets if a.data_class in ("confidential", "restricted")]
    if not findings:
        return f"{len(assets)} asset(s) audited, {len(sens)} hold personal data, and all comply with the policy."
    n = {k: sum(f.severity == k for f in findings) for k in ("critical", "high", "medium", "low")}
    return (
        f"{len(assets)} asset(s) audited, {len(sens)} hold personal data; {len(findings)} finding(s): {n['critical']} critical, {n['high']} high, "
        f"{n['medium']} medium, {n['low']} low."
    )


async def build_report(
    project: str,
    assets: list[Asset],
    findings: list[Finding],
    stats: list[SourceStat],
    pol: Policy,
    llm: LLM,
    *,
    degraded: list[str] | None = None,
    budget: Budget | None = None,
    timeout: float = 30.0,
    t0: float | None = None,
) -> Report:
    t0, budget, degraded = t0 or time.perf_counter(), budget or Budget(), list(degraded or [])
    loc = {a.name: a.location for a in assets}
    trace = [
        TraceStep(
            agent="audit",
            action="classify+evaluate",
            duration_ms=int((time.perf_counter() - t0) * 1000),
            note=f"{len(assets)} assets, {len(findings)} findings",
        )
    ]
    dropped: list[dict[str, str]] = []
    if llm.name != "none" and findings:
        top = sorted(findings, key=lambda f: -SEV_RANK[f.severity])[:TOP_EXPLAINED]
        for f, (note, step, why) in zip(
            top,
            await asyncio.gather(
                *(agents.explain(f, loc.get(f.asset, ""), llm, budget, t0, timeout) for f in top)
            ),
            strict=True,
        ):
            trace.append(step)
            if note:
                f.note = note
            elif why:
                dropped.append({"agent": "explainer", "item": f"note for {f.id}", "reason": why})
            elif step.status == "error":
                degraded.append(f"explainer {f.id}: {step.note}")
    else:
        trace.append(
            TraceStep(
                agent="explainer",
                action="explain",
                status="skipped",
                note="no model configured or nothing to explain",
            )
        )
    counts = {
        k: sum(f.severity == k for f in findings)
        for k in ("critical", "high", "medium", "low", "info")
    }
    return Report(
        id=uuid.uuid4().hex[:12],
        created_at=datetime.now(UTC).isoformat(timespec="seconds"),
        project=project,
        provider=llm.name,
        model=llm.model,
        posture=posture(findings),
        summary=summary(assets, findings),
        policy=pol,
        assets=assets,
        findings=findings,
        sources=stats,
        counts=counts,
        dropped=dropped,
        degraded=degraded,
        trace=trace,
        duration_ms=int((time.perf_counter() - t0) * 1000),
    )


async def audit_project(
    project: str,
    llm: LLM,
    *,
    pol: Policy | None = None,
    datasets: list[str] | None = None,
    buckets: list[str] | None = None,
    sample: bool = True,
    budget: Budget | None = None,
    s=None,
) -> Report:
    t0, pol = time.perf_counter(), pol or Policy()
    assets, stats, dataset_access, public_buckets, degraded = await asyncio.to_thread(
        collect, project, datasets, buckets or [], sample, s
    )
    findings = audit.evaluate(assets, pol, dataset_access, public_buckets)
    return await build_report(
        project, assets, findings, stats, pol, llm, degraded=degraded, budget=budget, t0=t0
    )
