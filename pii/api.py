"""HTTP API and viewer. Auth is Cloud Run IAM. Reports hold column names, PII types, counts and masked examples only; in memory."""

from __future__ import annotations

import logging
import threading
from collections import OrderedDict
from datetime import UTC, datetime
from importlib import resources

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel

from . import __version__
from .config import Settings
from .llm import Budget, LLMError, make_llm
from .models import Report
from .orchestrator import audit_project


class AuditRequest(BaseModel):
    project: str
    datasets: list[str] | None = None
    buckets: list[str] | None = None
    sample: bool = True
    llm: str | None = None


class _Mem:
    def __init__(self, cap: int = 30):
        self._d: OrderedDict[str, Report] = OrderedDict()
        self._cap, self._lock, self._spend = cap, threading.Lock(), {}

    def save(self, r):
        with self._lock:
            self._d[r.id] = r
            while len(self._d) > self._cap:
                self._d.popitem(last=False)

    def get(self, i):
        return self._d.get(i)

    def recent(self, n):
        return list(reversed(self._d.values()))[:n]

    def spend(self):
        return self._spend.get(datetime.now(UTC).strftime("%Y%m%d"), 0.0)

    def add(self, usd):
        k = datetime.now(UTC).strftime("%Y%m%d")
        with self._lock:
            self._spend[k] = self._spend.get(k, 0.0) + usd


def create_app(settings: Settings | None = None, auditor=audit_project) -> FastAPI:
    cfg, mem = settings or Settings(), _Mem()
    app = FastAPI(title="pii", version=__version__)

    @app.get("/healthz")
    def healthz():
        return {"ok": True, "version": __version__}

    @app.get("/", response_class=HTMLResponse)
    def index():
        return (resources.files("pii") / "ui.html").read_text()

    @app.get("/api/config")
    def config():
        return {
            "version": __version__,
            "provider": cfg.provider,
            "allowed_providers": cfg.allowed_providers,
            "projects": cfg.projects,
            "datasets": cfg.datasets,
            "buckets": cfg.buckets,
            "policy": cfg.policy.model_dump(),
            "daily_budget_usd": cfg.daily_budget_usd,
            "spend_today_usd": round(mem.spend(), 6),
        }

    @app.post("/api/audits", response_model=Report)
    async def create(req: Request):
        raw = await req.body()
        if len(raw) > cfg.max_body_bytes:
            raise HTTPException(413, "too large")
        try:
            body = AuditRequest.model_validate_json(raw)
        except ValueError as e:
            raise HTTPException(422, f"invalid request: {str(e)[:300]}") from e
        if body.project not in cfg.projects:
            raise HTTPException(403, f"auditing '{body.project}' is not enabled here")
        datasets = body.datasets if body.datasets is not None else list(cfg.datasets)
        buckets = body.buckets if body.buckets is not None else list(cfg.buckets)
        if any(d not in cfg.datasets for d in datasets) or any(
            b not in cfg.buckets for b in buckets
        ):
            raise HTTPException(
                403, "datasets and buckets are limited to the configured allow-lists"
            )
        provider = body.llm or cfg.provider
        if provider not in cfg.allowed_providers:
            raise HTTPException(
                403, f"provider '{provider}' not allowed here ({', '.join(cfg.allowed_providers)})"
            )
        notes = []
        if provider not in ("none", "mock") and mem.spend() >= cfg.daily_budget_usd:
            provider = "none"
            notes.append(
                f"daily model budget ${cfg.daily_budget_usd:.2f} reached; no model commentary"
            )
        try:
            llm = make_llm(provider, cfg.model if provider == cfg.provider else None)
        except LLMError as e:
            raise HTTPException(503, str(e)) from e
        rep = await auditor(
            body.project,
            llm,
            pol=cfg.policy,
            datasets=datasets,
            buckets=buckets,
            sample=body.sample,
            budget=Budget(cfg.max_llm_calls, cfg.review_budget_usd),
        )
        rep.degraded = notes + rep.degraded
        mem.add(sum(s.cost_usd for s in rep.trace))
        mem.save(rep)
        return rep

    @app.get("/api/audits", response_model=list[Report])
    def listing(limit: int = 20):
        return mem.recent(max(1, min(limit, 30)))

    @app.get("/api/audits/{rid}", response_model=Report)
    def get(rid: str):
        r = mem.get(rid)
        if r is None:
            raise HTTPException(404, "no such audit")
        return r

    @app.exception_handler(Exception)
    async def unhandled(_: Request, exc: Exception):
        logging.getLogger("pii").error(
            "unhandled error: %s", type(exc).__name__
        )  # never log the message: it may echo data
        return JSONResponse({"detail": "internal error"}, status_code=500)

    return app


def app_factory() -> FastAPI:
    return create_app()
