"""DLP detector unit tests (pure, no DB)."""

from agentguard_api.dlp.detectors import highest_classification, scan_text
from agentguard_api.dlp.service import scan_dict
from agentguard_api.models.enums import DataClassification

VALID_CARD = "4242 4242 4242 4242"  # passes Luhn
BAD_CARD = "4242 4242 4242 4241"  # fails Luhn


def _names(findings):
    return sorted(f.detector for f in findings)


def test_ssn_and_card():
    assert _names(scan_text("SSN 123-45-6789")) == ["us_ssn"]
    assert "credit_card" in _names(scan_text(f"card {VALID_CARD}"))
    assert "credit_card" not in _names(scan_text(f"card {BAD_CARD}"))


def test_keys_and_secrets():
    assert "aws_access_key" in _names(scan_text("AKIAIOSFODNN7EXAMPLE"))
    assert "openai_key" in _names(scan_text("sk-abcdefghijklmnopqrstuvwx"))
    assert "private_key" in _names(scan_text("-----BEGIN RSA PRIVATE KEY-----\nMIIB"))
    assert "jwt" in _names(scan_text("eyJhbGc.eyJzdWI.sig-part_here"))


def test_generic_secret_needs_key_context():
    assert scan_text("hunter2") == []
    assert "generic_secret" in _names(scan_text("hunter2", key_hint="password"))
    assert "generic_secret" in _names(scan_text("abc123xyz", key_hint="client_secret"))


def test_plain_text_no_false_positives():
    assert scan_text("The quick brown fox jumps over the lazy dog.") == []
    assert scan_text("Meeting at 3pm to discuss Q4 revenue targets.") == []


def test_classification_ranking():
    findings = scan_text("email a@b.com and ssn 123-45-6789")
    assert highest_classification(findings) == DataClassification.restricted


def test_scan_dict_reports_paths():
    payload = {
        "user": {"email": "jane@example.com", "notes": "vip client"},
        "items": [{"card": VALID_CARD}],
    }
    findings = scan_dict(payload)
    paths = {f.path for f in findings}
    assert "parameters.user.email" in paths
    assert "parameters.items[0].card" in paths
