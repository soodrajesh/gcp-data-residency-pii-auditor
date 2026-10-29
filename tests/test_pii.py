import json

import pytest
from fastapi.testclient import TestClient

from pii import audit, detectors, policy
from pii.agents import check_note
from pii.api import create_app
from pii.classify import classify_column
from pii.cli import main
from pii.config import Settings
from pii.llm import LLMError, MockLLM
from pii.models import Access, Finding, Policy
from pii.orchestrator import build_report

from .helpers import ALL, CARDS, EMAILS, IPS, PHONES, SSNS, ScriptedLLM, ds_meta, table_meta

# --- detectors: validated, not just shaped --------------------------------------------------------


@pytest.mark.parametrize(
    "v,t",
    [
        (EMAILS[0], "email"),
        (PHONES[0], "phone"),
        (SSNS[0], "ssn"),
        (CARDS[0], "credit_card"),
        (CARDS[3], "credit_card"),
        (IPS[0], "ip_address"),
        ("GB82 WEST 1234 5698 7654 32", "iban"),
    ],
)
def test_each_pii_type_is_detected(v, t):
    assert t in detectors.detect_value(v)


@pytest.mark.parametrize(
    "v",
    [
        "4111 1111 1111 1112",
        "000-12-3456",
        "666-12-3456",
        "900-12-3456",
        "123-00-4567",
        "123-45-0000",
        "10.0.0.1",
        "192.168.1.5",
        "127.0.0.1",
        "order-12345",
        "2026-10-29",
        "hello world",
        "1234567890123456",
        "GB00 WEST 1234 5698 7654 32",
        "",
        "a@b",
        "5551234",
    ],
)
def test_invalid_or_non_pii_values_are_rejected(v):
    assert detectors.detect_value(v) == []


def test_a_card_is_not_also_a_phone_number_and_an_ssn_is_not_either():
    assert detectors.detect_value(CARDS[1]) == ["credit_card"] and detectors.detect_value(
        SSNS[2]
    ) == ["ssn"]


def test_masking_never_reveals_more_than_the_last_four_digits():
    assert detectors.mask("credit_card", CARDS[0]) == "************1111"
    assert detectors.mask("ssn", SSNS[0]) == "*****1120"
    assert detectors.mask("email", EMAILS[0]) == "a***@e***.com"
    assert detectors.mask("ip_address", "208.67.222.222") == "208.67.*.*"
    for v in ALL:
        for t in detectors.detect_value(v):
            assert v not in detectors.mask(t, v)


def test_scan_values_counts_and_keeps_two_masked_examples_only():
    st = detectors.scan_values(EMAILS + [None, "", "n/a"])
    assert st.sampled == 5 and st.matched == {"email": 4} and len(st.examples["email"]) == 2


# --- classification ---------------------------------------------------------------------------------


def test_values_beat_names_and_undocumented_pii_is_flagged():
    c = classify_column("contact", "STRING", EMAILS)
    assert (
        c.pii_types == ["email"]
        and c.evidence == "values"
        and c.undocumented
        and c.data_class == "confidential"
    )


def test_name_and_values_agreeing_is_the_strongest_evidence():
    c = classify_column("ssn", "STRING", SSNS)
    assert c.evidence == "name+values" and c.data_class == "restricted" and not c.undocumented


def test_a_sensitive_name_with_non_matching_values_is_not_escalated():
    c = classify_column("ssn", "STRING", ["hello", "world", "n/a"])
    assert c.pii_types == [] and c.data_class == "internal"


def test_unsampled_columns_are_classified_by_name_with_low_confidence():
    c = classify_column("customer_email", "STRING", None)
    assert c.pii_types == ["email"] and c.evidence == "name_only" and c.data_class == "confidential"
    assert classify_column("order_total", "FLOAT", None).data_class == "internal"


def test_one_in_a_hundred_matches_does_not_make_a_column_pii():
    vals = [EMAILS[0]] + [f"note {i}" for i in range(99)]
    assert classify_column("notes", "STRING", vals).pii_types == []


def test_table_class_is_the_highest_column_class():
    a = audit.bq_asset(
        ds_meta(),
        "t",
        table_meta([("email", "STRING"), ("ssn", "STRING"), ("id", "INT64")]),
        {"email": EMAILS, "ssn": SSNS, "id": ["1", "2"]},
    )
    assert a.data_class == "restricted" and a.location == "EU"


# --- policy -------------------------------------------------------------------------------------------


def test_location_groups():
    for loc, grp in (
        ("US", "US"),
        ("us-central1", "US"),
        ("EU", "EU"),
        ("europe-west4", "EU"),
        ("asia-east1", "ASIA-EAST1"),
        ("", "UNKNOWN"),
    ):
        assert policy.location_group(loc) == grp
    assert (
        policy.location_allowed("us-east1", ["US"])
        and not policy.location_allowed("EU", ["US"])
        and policy.location_allowed("asia-east1", ["asia-east1"])
    )


def test_access_levels_from_dataset_acls():
    assert (
        policy.access_level([{"specialGroup": "allAuthenticatedUsers", "role": "READER"}]).level
        == "public"
    )
    assert policy.access_level([{"iamMember": "allUsers", "role": "READER"}]).level == "public"
    assert policy.access_level([{"domain": "example.com", "role": "READER"}]).level == "broad"
    assert (
        policy.access_level([{"groupByEmail": f"g{i}@example.com"} for i in range(3)]).level
        == "broad"
    )
    lim = policy.access_level([{"userByEmail": "a@example.com"}, {"specialGroup": "projectOwners"}])
    assert lim.level == "limited" and lim.principal_count == 1


def assets_for(location, access, cmek=False, expires=False, fields=None, samples=None):
    fields = fields or [("email", "STRING"), ("ssn", "STRING")]
    samples = samples or {"email": EMAILS, "ssn": SSNS}
    meta = table_meta(fields, **({"expirationTime": "1"} if expires else {}))
    return [audit.bq_asset(ds_meta("cust", location, access, cmek), "people", meta, samples)]


def rules(findings):
    return {f.rule for f in findings}


def test_restricted_data_outside_its_allowed_location_is_a_residency_violation():
    fs = audit.evaluate(assets_for("EU", None), Policy(), {}, set())
    f = next(x for x in fs if x.rule == "P001")
    assert f.severity == "critical" and "EU" in f.title and f.data_class == "restricted"
    assert not [
        x
        for x in audit.evaluate(assets_for("US", None, cmek=True), Policy(), {}, set())
        if x.rule == "P001"
    ]


def test_confidential_data_follows_its_own_residency_list():
    conf = assets_for("asia-east1", None, fields=[("email", "STRING")], samples={"email": EMAILS})
    assert rules(audit.evaluate(conf, Policy(), {}, set())) >= {"P001"}
    assert "P001" not in rules(
        audit.evaluate(
            assets_for("EU", None, fields=[("email", "STRING")], samples={"email": EMAILS}),
            Policy(),
            {},
            set(),
        )
    )


def test_public_or_broad_access_to_personal_data_is_flagged_with_the_right_severity():
    pub = {"cust": Access(level="public", principal_count=-1, why="everyone")}
    brd = {"cust": Access(level="broad", principal_count=40, why="a domain")}
    lim = {"cust": Access(level="limited", principal_count=2, why="two people")}
    a = assets_for("US", None, cmek=True)
    assert (
        next(f for f in audit.evaluate(a, Policy(), pub, set()) if f.rule == "P002").severity
        == "critical"
    )
    assert (
        next(f for f in audit.evaluate(a, Policy(), brd, set()) if f.rule == "P002").severity
        == "critical"
    )  # restricted + broad: high bumped
    assert "P002" not in rules(audit.evaluate(a, Policy(), lim, set()))


def test_restricted_data_with_too_many_named_readers_is_flagged_even_if_not_broad():
    many = {"cust": Access(level="limited", principal_count=25, why="25 people")}
    assert "P002" in rules(audit.evaluate(assets_for("US", None, cmek=True), Policy(), many, set()))


def test_cmek_expiration_and_undocumented_pii_rules():
    a = assets_for(
        "US",
        None,
        fields=[("contact", "STRING"), ("ssn", "STRING")],
        samples={"contact": EMAILS, "ssn": SSNS},
    )
    fs = audit.evaluate(a, Policy(require_expiration=["restricted"]), {}, set())
    assert {"P003", "P004", "P005"} <= rules(fs)
    ok = audit.evaluate(
        assets_for("US", None, cmek=True, expires=True),
        Policy(require_expiration=["restricted"]),
        {},
        set(),
    )
    assert not ({"P003", "P004"} & rules(ok))


def test_non_sensitive_tables_produce_no_findings():
    a = [
        audit.bq_asset(
            ds_meta("ops", "EU"),
            "orders",
            table_meta([("id", "INT64"), ("total", "FLOAT")]),
            {"id": ["1"], "total": ["2.5"]},
        )
    ]
    assert audit.evaluate(a, Policy(), {"ops": Access(level="public")}, set()) == []


def test_public_gcs_bucket_with_personal_data_is_critical():
    g = audit.gcs_asset(
        {"name": "b", "location": "US"}, "people.csv", {"email": EMAILS, "ssn": SSNS}
    )
    f = next(x for x in audit.evaluate([g], Policy(), {}, {"b"}) if x.rule == "P002")
    assert f.severity == "critical" and f.asset == "gs://b/people.csv"


# --- nothing personal ever leaves the auditor -----------------------------------------------------------


def blob_of(report):
    return json.dumps(report.model_dump())


async def full_report(llm):
    a = assets_for(
        "EU",
        [{"role": "READER", "domain": "example.com"}],
        fields=[
            ("email", "STRING"),
            ("phone", "STRING"),
            ("ssn", "STRING"),
            ("card", "STRING"),
            ("ip", "STRING"),
        ],
        samples={"email": EMAILS, "phone": PHONES, "ssn": SSNS, "card": CARDS, "ip": IPS},
    )
    fs = audit.evaluate(
        a, Policy(), {"cust": policy.access_level([{"domain": "example.com"}])}, set()
    )
    return await build_report("p", a, fs, [], Policy(), llm)


async def test_no_personal_value_appears_in_the_report_or_the_model_payload():
    llm = ScriptedLLM({"note": "Several people can read this table."})
    rep = await full_report(llm)
    blob = blob_of(rep) + "\n".join(llm.seen)
    for v in ALL:
        assert v not in blob, v
        assert v.replace(" ", "") not in blob
    assert rep.findings and llm.calls >= 2


async def test_notes_with_personal_data_links_foreign_assets_or_false_public_claims_are_rejected():
    for bad in (
        f"owner is {EMAILS[0]}",
        "see https://evil.example",
        "also affects other_ds.other_table",
        "this table is publicly readable",
        f"card {CARDS[0]}",
    ):
        rep = await full_report(ScriptedLLM({"note": bad}))
        assert not any(f.note for f in rep.findings) and rep.dropped, bad


async def test_model_failure_degrades_and_posture_is_rule_based():
    rep = await full_report(ScriptedLLM(raises=LLMError("429")))
    assert rep.degraded and rep.posture == "violations"
    assert (await full_report(MockLLM())).posture == "violations"
    ok = await build_report("p", [], [], [], Policy(), MockLLM())
    assert ok.posture == "compliant" and "comply" in ok.summary


def test_check_note_accepts_a_plain_explanation():
    f = Finding(
        rule="P001",
        severity="high",
        asset="cust.people",
        container="cust",
        title="t",
        access=Access(level="limited"),
    )
    assert check_note("This table holds restricted data and sits in the wrong region.", f) is None
    assert check_note("Data in cust.people is readable by many.", f) is None


# --- API and CLI --------------------------------------------------------------------------------------------


def test_api_scope_limits_and_no_values_in_responses():
    async def fake(project, llm, **kw):
        return await full_report(llm)

    app = create_app(
        Settings(
            provider="none",
            allowed_providers=("none", "mock"),
            projects=("p",),
            datasets=("cust",),
            buckets=("b",),
        ),
        auditor=fake,
    )
    c = TestClient(app)
    assert c.get("/healthz").json()["ok"] and "PII" in c.get("/").text
    r = c.post("/api/audits", json={"project": "p", "llm": "none"})
    assert (
        r.status_code == 200
        and not any(v in r.text for v in ALL)
        and r.json()["posture"] == "violations"
    )
    assert (
        c.get(f"/api/audits/{r.json()['id']}").status_code == 200
        and len(c.get("/api/audits").json()) == 1
    )
    assert c.post("/api/audits", json={"project": "other"}).status_code == 403
    assert (
        c.post("/api/audits", json={"project": "p", "datasets": ["secret_ds"]}).status_code == 403
    )
    assert c.post("/api/audits", json={"project": "p", "buckets": ["other"]}).status_code == 403
    assert c.post("/api/audits", json={"project": "p", "llm": "openai"}).status_code == 403
    assert c.post("/api/audits", content=b"x").status_code == 422
    assert c.get("/api/audits/none").status_code == 404


def test_cli_error_path_prints_no_message(capsys, monkeypatch):
    import pii.cli as cli

    async def boom(*a, **k):
        raise cli.SourceError("secret detail with " + EMAILS[0])

    monkeypatch.setattr(cli, "audit_project", boom)
    assert main(["audit", "p"]) == 3
    assert EMAILS[0] not in capsys.readouterr().err


@pytest.mark.parametrize(
    "name,typ",
    [
        ("is_credit_card", "BOOL"),
        ("is_credit_card", "INTEGER"),
        ("has_email", "BOOLEAN"),
        ("card_type", "STRING"),
        ("email_count", "INT64"),
        ("phone_status", "STRING"),
        ("ssn_flag", "BOOL"),
        ("latitude_ts", "TIMESTAMP"),
        ("address_valid", "BOOL"),
    ],
)
def test_flag_count_and_category_columns_that_mention_pii_are_not_pii(name, typ):
    """Found by auditing a real dataset: a taxi-trips table has `is_credit_card`, a payment-method flag."""
    c = classify_column(name, typ, None)
    assert c.pii_types == [] and c.data_class == "internal"


def test_real_pii_columns_with_matching_types_are_still_found_by_name():
    assert classify_column("email", "STRING", None).pii_types == ["email"]
    assert classify_column("date_of_birth", "DATE", None).pii_types == ["date_of_birth"]
    assert classify_column("phone", "INT64", None).pii_types == ["phone"]
    assert classify_column("created_date", "DATE", None).pii_types == []


def test_name_only_types_that_cannot_be_validated_keep_their_class_when_sampled():
    assert classify_column("full_name", "STRING", ["Alice N", "Bob O"]).pii_types == ["person_name"]
    assert (
        classify_column("street_address", "STRING", ["12 Main St", "9 Elm Ave"]).data_class
        == "confidential"
    )
    assert (
        classify_column("email", "STRING", ["x", "y"]).pii_types == []
    )  # a validated type is disproved by its values


def test_an_unreadable_bucket_policy_is_reported_as_unknown_not_as_private():
    from pii import sources

    class Denied:
        def get(self, url, **kw):
            class R:
                status_code = 403
                text = "denied"

            return R()

    class Public:
        def get(self, url, **kw):
            class R:
                status_code = 200
                text = ""

                def json(self):
                    return {
                        "bindings": [
                            {"role": "roles/storage.objectViewer", "members": ["allUsers"]}
                        ]
                    }

            return R()

    assert sources.bucket_public(Denied(), "b") is None
    assert sources.bucket_public(Public(), "b") is True
