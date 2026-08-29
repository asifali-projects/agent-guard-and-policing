"""Pure detectors for sensitive data (PRD §27).

Each detector has a name, a data class it implies, and either a compiled regex
or a callable. Detectors never see or return raw values in full — callers get a
masked sample for evidence.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass

from ..models.enums import DataClassification

# Detectors whose presence should never be allowed to leave the boundary,
# regardless of the organization's data policy.
NEVER_EXFIL = frozenset(
    {
        "aws_access_key",
        "gcp_api_key",
        "openai_key",
        "github_token",
        "slack_token",
        "agentguard_key",
        "private_key",
        "jwt",
        "generic_secret",
        "basic_auth",
    }
)


@dataclass(frozen=True)
class Finding:
    detector: str
    classification: DataClassification
    sample: str  # masked


def _mask(value: str) -> str:
    value = value.strip()
    if len(value) <= 6:
        return "*" * len(value)
    return f"{value[:2]}{'*' * (len(value) - 4)}{value[-2:]}"


def _luhn_ok(digits: str) -> bool:
    nums = [int(d) for d in digits if d.isdigit()]
    if not 13 <= len(nums) <= 19:
        return False
    checksum = 0
    parity = len(nums) % 2
    for i, n in enumerate(nums):
        if i % 2 == parity:
            n *= 2
            if n > 9:
                n -= 9
        checksum += n
    return checksum % 10 == 0


_REGEX_DETECTORS: list[tuple[str, DataClassification, re.Pattern[str]]] = [
    (
        "email",
        DataClassification.confidential,
        re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}"),
    ),
    ("us_ssn", DataClassification.restricted, re.compile(r"(?<!\d)\d{3}-\d{2}-\d{4}(?!\d)")),
    (
        "phone",
        DataClassification.confidential,
        re.compile(r"(?<!\w)(?:\+?\d{1,3}[ .\-]?)?(?:\(\d{3}\)|\d{3})[ .\-]\d{3}[ .\-]\d{4}(?!\d)"),
    ),
    ("iban", DataClassification.restricted, re.compile(r"\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b")),
    (
        "jwt",
        DataClassification.restricted,
        re.compile(r"eyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+"),
    ),
    ("aws_access_key", DataClassification.restricted, re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("gcp_api_key", DataClassification.restricted, re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b")),
    (
        "openai_key",
        DataClassification.restricted,
        re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_\-]{20,}\b"),
    ),
    ("github_token", DataClassification.restricted, re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b")),
    (
        "slack_token",
        DataClassification.restricted,
        re.compile(r"\bxox[baprs]-[0-9A-Za-z\-]{10,}\b"),
    ),
    (
        "agentguard_key",
        DataClassification.restricted,
        re.compile(r"\bag_(?:dev|stg|live)_[a-z0-9]{8}_[A-Za-z0-9_\-]{20,}\b"),
    ),
    (
        "private_key",
        DataClassification.restricted,
        re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----"),
    ),
    ("basic_auth", DataClassification.restricted, re.compile(r"://[^/\s:@]+:[^/\s:@]+@")),
]

_KEY_CONTEXT = re.compile(
    r"(?i)(pass(?:word|wd)|secret|api[_\- ]?key|access[_\- ]?token|client[_\- ]?secret|credential)"
)


def scan_text(text: str, *, key_hint: str | None = None) -> list[Finding]:
    """Scan one string. ``key_hint`` is the dict key it came from, if any."""
    if not text or not isinstance(text, str):
        return []
    findings: list[Finding] = []

    for name, klass, pattern in _REGEX_DETECTORS:
        if pattern.search(text):
            for m in pattern.finditer(text):
                findings.append(Finding(name, klass, _mask(m.group(0))))
                break  # one finding per detector per field is enough

    # Credit card: regex candidate + Luhn.
    for m in re.finditer(r"(?<!\d)(?:\d[ \-]?){13,19}(?!\d)", text):
        if _luhn_ok(m.group(0)):
            findings.append(
                Finding("credit_card", DataClassification.restricted, _mask(m.group(0)))
            )
            break

    # Secret by key name: "password": "hunter2"
    if key_hint and _KEY_CONTEXT.search(key_hint) and len(text.strip()) >= 4:
        if not any(f.detector == "generic_secret" for f in findings):
            findings.append(Finding("generic_secret", DataClassification.restricted, _mask(text)))

    return findings


DETECTORS: tuple[str, ...] = tuple(
    [n for n, _, _ in _REGEX_DETECTORS] + ["credit_card", "generic_secret"]
)


def highest_classification(items: Iterable[Finding]) -> DataClassification | None:
    order = {
        DataClassification.public: 0,
        DataClassification.internal: 1,
        DataClassification.confidential: 2,
        DataClassification.restricted: 3,
    }
    best: DataClassification | None = None
    for f in items:
        if best is None or order[f.classification] > order[best]:
            best = f.classification
    return best
