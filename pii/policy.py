"""Policy evaluation: where may each class of data live, who may read it, must it use CMEK, must it expire."""

from __future__ import annotations

from .models import CLASS_RANK, SEV_RANK, SEVS, Access, Policy

US = ("us", "us-", "northamerica-")
EU = ("eu", "europe-")


def location_group(loc: str) -> str:
    low = (loc or "").lower()
    if low == "us" or low.startswith("us-"):
        return "US"
    if low == "eu" or low.startswith("europe-"):
        return "EU"
    return loc.upper() if loc else "UNKNOWN"


def location_allowed(loc: str, allowed: list[str]) -> bool:
    g = location_group(loc)
    return any(a.upper() == g or a.lower() == (loc or "").lower() for a in allowed)


def bump(sev: str, by: int = 1) -> str:
    return SEVS[max(0, min(4, SEV_RANK[sev] + by))]


def access_level(entries: list[dict]) -> Access:
    """BigQuery dataset ACL entries -> how widely readable. Entries are summarised, never expanded."""
    pub = [
        e
        for e in entries
        if e.get("specialGroup") in ("allAuthenticatedUsers",)
        or e.get("iamMember") in ("allUsers", "allAuthenticatedUsers")
    ]
    if pub:
        return Access(
            level="public",
            entries=["allAuthenticatedUsers/allUsers"],
            principal_count=-1,
            why="every authenticated Google identity (or everyone) can read this dataset",
        )
    domains = [e["domain"] for e in entries if "domain" in e]
    groups = [e["groupByEmail"] for e in entries if "groupByEmail" in e]
    people = [
        e.get("userByEmail") or e.get("iamMember")
        for e in entries
        if e.get("userByEmail") or (e.get("iamMember", "").startswith(("user:", "serviceAccount:")))
    ]
    special = [
        e["specialGroup"]
        for e in entries
        if e.get("specialGroup") in ("projectReaders", "projectWriters", "projectOwners")
    ]
    readers = [x for x in (domains + groups + people) if x]
    desc = (
        [f"domain:{x}" for x in domains]
        + [f"group:{x}" for x in groups]
        + [str(x) for x in people]
        + [f"{s} (all project members with that role)" for s in special]
    )
    if domains or len(groups) >= 3 or len(readers) >= 10:
        return Access(
            level="broad",
            entries=desc[:10],
            principal_count=len(readers),
            why="domain-wide, several groups, or 10+ principals have access",
        )
    return Access(
        level="limited",
        entries=desc[:10],
        principal_count=len(readers),
        why=f"{len(readers)} named principal(s) and {len(special)} project role group(s)",
    )


def class_needs(policy: Policy, data_class: str) -> bool:
    return CLASS_RANK[data_class] >= CLASS_RANK["confidential"]
