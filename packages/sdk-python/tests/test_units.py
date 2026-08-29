import pytest

from agentguard import ConfigurationError
from agentguard.config import resolve
from agentguard.decision import Decision, DecisionResult
from agentguard.redact import redact_params


def test_decision_from_api_defaults():
    r = DecisionResult.from_api({"decision": "DENY"})
    assert r.decision == Decision.DENY
    assert r.risk_score == 0 and not r.allowed


def test_redact_nested_and_list_and_missing():
    params = {
        "user": {"ssn": "123-45-6789", "name": "Jo"},
        "items": [{"card": "4242"}, {"card": "5555"}],
    }
    out = redact_params(
        params,
        ["parameters.user.ssn", "parameters.items[1].card", "parameters.nope.deep"],
    )
    assert out["user"]["ssn"] == "[REDACTED]"
    assert out["user"]["name"] == "Jo"
    assert out["items"][0]["card"] == "4242"
    assert out["items"][1]["card"] == "[REDACTED]"
    # original untouched
    assert params["user"]["ssn"] == "123-45-6789"


def test_config_precedence(monkeypatch, tmp_path):
    cfg_file = tmp_path / "config.toml"
    cfg_file.write_text('api_key = "from_file"\nbase_url = "http://file"\n')
    monkeypatch.setenv("AGENTGUARD_CONFIG", str(cfg_file))
    monkeypatch.delenv("AGENTGUARD_API_KEY", raising=False)

    assert resolve().api_key == "from_file"

    monkeypatch.setenv("AGENTGUARD_API_KEY", "from_env")
    assert resolve().api_key == "from_env"

    assert resolve(api_key="explicit").api_key == "explicit"


def test_config_missing_key(monkeypatch, tmp_path):
    monkeypatch.setenv("AGENTGUARD_CONFIG", str(tmp_path / "none.toml"))
    monkeypatch.delenv("AGENTGUARD_API_KEY", raising=False)
    with pytest.raises(ConfigurationError):
        resolve()
