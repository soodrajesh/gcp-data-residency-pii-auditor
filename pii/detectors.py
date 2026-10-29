"""PII detectors. Values are tested against patterns WITH validation (Luhn for cards, area rules for SSNs, mod-97 for IBANs),
counted, and discarded. Only counts and masked examples leave this module."""

from __future__ import annotations

import re
from dataclasses import dataclass

EMAIL = re.compile(r"^[A-Za-z0-9._%+\-]{1,64}@[A-Za-z0-9\-]+(?:\.[A-Za-z0-9\-]+)*\.[A-Za-z]{2,}$")
PHONE = re.compile(
    r"^(?:\+?1[\s.\-]?)?\(?[2-9]\d{2}\)?[\s.\-]?[2-9]\d{2}[\s.\-]?\d{4}$|^\+\d{1,3}[\s.\-]?\d{1,4}[\s.\-]?\d{3,4}[\s.\-]?\d{3,4}$"
)
SSN = re.compile(r"^(\d{3})-?(\d{2})-?(\d{4})$")
CARD = re.compile(r"^(?:\d[ \-]?){13,19}$")
IBAN = re.compile(r"^[A-Z]{2}\d{2}[A-Z0-9]{11,30}$")
IPV4 = re.compile(r"^(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)$")
DATE = re.compile(r"^\d{4}-\d{2}-\d{2}")

# type -> data class
CLASS_OF = {
    "ssn": "restricted",
    "credit_card": "restricted",
    "iban": "restricted",
    "national_id": "restricted",
    "passport": "restricted",
    "email": "confidential",
    "phone": "confidential",
    "ip_address": "confidential",
    "date_of_birth": "confidential",
    "address": "confidential",
    "person_name": "confidential",
    "geo_location": "confidential",
}

# Column-name hints: (pii type, pattern). Name hints alone give "name_only" evidence (low confidence).
NAME_HINTS: list[tuple[str, re.Pattern]] = [
    ("ssn", re.compile(r"\b(ssn|social[_ ]?security|sin_number)\b|(^|_)ssn($|_)", re.I)),
    (
        "credit_card",
        re.compile(r"(card[_ ]?(number|num|no)|(^|_)pan($|_)|credit[_ ]?card|cc[_ ]?num)", re.I),
    ),
    ("iban", re.compile(r"(^|_)iban($|_)", re.I)),
    ("passport", re.compile(r"passport", re.I)),
    (
        "national_id",
        re.compile(
            r"(national[_ ]?id|tax[_ ]?id|(^|_)nino($|_)|aadhaar|(^|_)cpf($|_)|(^|_)tin($|_))", re.I
        ),
    ),
    ("email", re.compile(r"e[_-]?mail", re.I)),
    (
        "phone",
        re.compile(r"(phone|mobile|(^|_)msisdn($|_)|(^|_)tel($|_)|telephone|cell(phone)?)", re.I),
    ),
    (
        "date_of_birth",
        re.compile(r"(date[_ ]?of[_ ]?birth|(^|_)dob($|_)|birth[_ ]?date|birthday)", re.I),
    ),
    (
        "address",
        re.compile(r"(street|address|(^|_)addr($|_)|postal|zip[_ ]?code|(^|_)zip($|_))", re.I),
    ),
    (
        "person_name",
        re.compile(
            r"((^|_)(first|last|full|given|family|sur)[_ ]?name|(^|_)name($|_)|customer_name|patient_name)",
            re.I,
        ),
    ),
    ("ip_address", re.compile(r"(^|_)(ip|ip_addr|ip_address|client_ip|remote_addr)($|_)", re.I)),
    ("geo_location", re.compile(r"(latitude|longitude|(^|_)(lat|lng|lon)($|_)|geo)", re.I)),
]


def luhn(digits: str) -> bool:
    total, alt = 0, False
    for ch in reversed(digits):
        d = int(ch)
        if alt:
            d = d * 2 - 9 if d * 2 > 9 else d * 2
        total += d
        alt = not alt
    return total % 10 == 0


def valid_card(v: str) -> bool:
    if not CARD.match(v):
        return False
    digits = re.sub(r"\D", "", v)
    return 13 <= len(digits) <= 19 and luhn(digits) and digits[0] in "3456" and len(set(digits)) > 1


def valid_ssn(v: str) -> bool:
    m = SSN.match(v)
    if not m:
        return False
    area, group, serial = m.groups()
    return (
        area not in ("000", "666")
        and not area.startswith("9")
        and group != "00"
        and serial != "0000"
    )


def valid_iban(v: str) -> bool:
    s = v.replace(" ", "").upper()
    if not IBAN.match(s):
        return False
    rearranged = s[4:] + s[:4]
    num = "".join(str(int(c, 36)) for c in rearranged)
    return int(num) % 97 == 1


def is_public_ip(v: str) -> bool:
    if not IPV4.match(v):
        return False
    a, b = (int(x) for x in v.split(".")[:2])
    return not (
        a in (10, 127, 0) or (a == 172 and 16 <= b <= 31) or (a == 192 and b == 168) or a >= 224
    )


VALIDATORS = {
    "email": lambda v: bool(EMAIL.match(v)),
    "phone": lambda v: bool(PHONE.match(v.strip())) and sum(c.isdigit() for c in v) >= 10,
    "ssn": valid_ssn,
    "credit_card": valid_card,
    "iban": valid_iban,
    "ip_address": is_public_ip,
}


def detect_value(v: str) -> list[str]:
    """PII types a single value matches (validated)."""
    s = v.strip()
    if not s or len(s) > 64:
        return []
    out = [t for t, fn in VALIDATORS.items() if fn(s)]
    # an SSN-shaped value is not also a phone number; a card number is not a phone number
    if "ssn" in out or "credit_card" in out:
        out = [t for t in out if t != "phone"]
    return out


def name_types(column: str) -> list[str]:
    return [t for t, rx in NAME_HINTS if rx.search(column)]


def mask(pii_type: str, v: str) -> str:
    s = v.strip()
    if pii_type == "email" and "@" in s:
        local, _, dom = s.partition("@")
        return f"{local[:1]}***@{dom[:1]}***.{dom.rsplit('.', 1)[-1]}"
    digits = re.sub(r"\D", "", s)
    if pii_type in ("credit_card", "ssn", "iban", "phone") and len(digits) >= 4:
        return f"{'*' * (len(digits) - 4)}{digits[-4:]}"
    if pii_type == "ip_address":
        return ".".join(s.split(".")[:2]) + ".*.*"
    return s[:1] + "***"


@dataclass
class ColumnStats:
    sampled: int
    matched: dict[str, int]
    examples: dict[str, list[str]]


def scan_values(values: list[str | None]) -> ColumnStats:
    """Count validated matches per PII type; keep at most two masked examples per type; drop the values."""
    matched: dict[str, int] = {}
    examples: dict[str, list[str]] = {}
    n = 0
    for v in values:
        if v is None or v == "":
            continue
        n += 1
        for t in detect_value(str(v)):
            matched[t] = matched.get(t, 0) + 1
            if len(examples.setdefault(t, [])) < 2:
                examples[t].append(mask(t, str(v)))
    return ColumnStats(n, matched, examples)
