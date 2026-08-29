import httpx
import pytest

from agentguard import ApprovalRequired, Decision, PolicyDenied, RateLimited
from agentguard.redact import REDACTED


def test_allow_calls_the_function(guard_factory):
    guard = guard_factory()

    @guard.tool
    def add(a, b):
        return a + b

    assert add(2, 3) == 5
    assert guard._handler.calls[0]["tool"] == "add"
    assert guard._handler.calls[0]["parameters"] == {"a": 2, "b": 3}


def test_deny_raises_policy_denied(guard_factory):
    guard = guard_factory({"wire_money": {"decision": "DENY", "reasons": ["policy FIN-1"]}})

    @guard.tool
    def wire_money(amount):
        raise AssertionError("must not run")

    with pytest.raises(PolicyDenied) as ei:
        wire_money(1000)
    assert "FIN-1" in str(ei.value)
    assert ei.value.result.decision == Decision.DENY


def test_approval_raises_with_id(guard_factory):
    guard = guard_factory(
        {
            "pay": {
                "decision": "APPROVAL",
                "approval_request_id": "abc-123",
                "reasons": ["needs sign-off"],
            }
        }
    )

    @guard.tool
    def pay(vendor, amount):
        raise AssertionError("must not run")

    with pytest.raises(ApprovalRequired) as ei:
        pay("acme", 50000)
    assert ei.value.approval_request_id == "abc-123"


def test_redact_rewrites_arguments(guard_factory):
    guard = guard_factory({"send_email": {"decision": "REDACT", "redactions": ["parameters.body"]}})
    seen = {}

    @guard.tool
    def send_email(to, body):
        seen["to"] = to
        seen["body"] = body

    send_email("x@y.com", "my SSN is 123-45-6789")
    assert seen["to"] == "x@y.com"
    assert seen["body"] == REDACTED


def test_rate_limit_raises(guard_factory):
    guard = guard_factory(
        {"search": {"decision": "RATE_LIMIT", "rate_limit": {"retry_after_seconds": 42}}}
    )

    @guard.tool
    def search(q):
        raise AssertionError("must not run")

    with pytest.raises(RateLimited) as ei:
        search("hello")
    assert ei.value.retry_after_seconds == 42


def test_fail_closed_on_unreachable_runtime(guard_factory):
    def boom(request):
        raise httpx.ConnectError("no route")

    session = httpx.Client(transport=httpx.MockTransport(boom), base_url="http://test")
    from agentguard import AgentGuard

    guard = AgentGuard(
        api_key="ag_dev_x_y",
        base_url="http://test",
        agent="TestAgent",
        session=session,
        fail_mode="closed",
    )
    guard._agent_id = "11111111-1111-1111-1111-111111111111"

    @guard.tool
    def t():
        raise AssertionError("must not run")

    with pytest.raises(PolicyDenied):
        t()
    guard.close()


def test_fail_open_allows_when_runtime_down(guard_factory):
    def boom(request):
        raise httpx.ConnectError("no route")

    session = httpx.Client(transport=httpx.MockTransport(boom), base_url="http://test")
    from agentguard import AgentGuard

    guard = AgentGuard(
        api_key="ag_dev_x_y",
        base_url="http://test",
        agent="TestAgent",
        session=session,
        fail_mode="open",
    )
    guard._agent_id = "11111111-1111-1111-1111-111111111111"

    @guard.tool
    def t():
        return "ran"

    assert t() == "ran"
    guard.close()


def test_identity_resolution_uses_existing_agent(guard_factory):
    guard = guard_factory()
    assert guard.agent_id == "11111111-1111-1111-1111-111111111111"


def test_wait_for_approval(guard_factory):
    guard = guard_factory()
    assert guard.wait_for_approval("abc-123", poll_seconds=0.01) == "approved"
