from agentguard_policy import (
    CompiledPolicy,
    Decision,
    EvaluationInput,
    PolicySpec,
    evaluate,
)


def policy(key, rules, *, priority=100, specificity=0, default=None):
    return CompiledPolicy(
        key=key,
        priority=priority,
        specificity=specificity,
        spec=PolicySpec(rules=rules, default_effect=default),
    )


def test_implicit_allow_when_no_policies():
    res = evaluate(EvaluationInput(tool="invoice.read"), [])
    assert res.decision == Decision.allow
    assert res.default_applied


def test_explicit_deny_beats_allow():
    p = policy(
        "FIN-001",
        [
            {"effect": "allow", "actions": ["*"]},
            {"effect": "deny", "actions": ["customer.export"]},
        ],
    )
    res = evaluate(EvaluationInput(tool="customer.export"), [p])
    assert res.decision == Decision.deny
    assert res.matched_policy_keys == ["FIN-001"]


def test_conditional_approval():
    p = policy(
        "FIN-004",
        [
            {
                "effect": "approval",
                "actions": ["payment.create"],
                "when": {
                    "all": [
                        {"field": "parameters.amount", "op": "gt", "value": 5000},
                        {"field": "context.destination", "op": "eq", "value": "external"},
                    ]
                },
                "description": "High-value external payment",
            }
        ],
    )
    below = evaluate(EvaluationInput(tool="payment.create", parameters={"amount": 100}), [p])
    assert below.decision == Decision.allow

    over = evaluate(
        EvaluationInput(
            tool="payment.create",
            parameters={"amount": 48500},
            context={"destination": "external"},
        ),
        [p],
    )
    assert over.decision == Decision.approval
    assert "High-value external payment" in over.reasons[0]


def test_redact_unions_paths():
    p = policy(
        "DLP-1",
        [
            {"effect": "redact", "actions": ["*"], "redactions": ["parameters.ssn"]},
            {
                "effect": "redact",
                "actions": ["*"],
                "redactions": ["parameters.card", "parameters.ssn"],
            },
        ],
    )
    res = evaluate(EvaluationInput(tool="email.send"), [p])
    assert res.decision == Decision.redact
    assert res.redactions == ["parameters.ssn", "parameters.card"]


def test_rate_limit_returns_spec():
    p = policy(
        "RL-1",
        [
            {
                "effect": "rate_limit",
                "actions": ["search.web"],
                "rate_limit": {"max": 100, "window_seconds": 60, "scope": "agent"},
            }
        ],
    )
    res = evaluate(EvaluationInput(tool="search.web"), [p])
    assert res.decision == Decision.rate_limit
    assert res.rate_limit.max == 100 and res.rate_limit.scope == "agent"


def test_precedence_deny_over_approval_over_ratelimit_over_redact_over_allow():
    p = policy(
        "ALL",
        [
            {"effect": "allow", "actions": ["*"]},
            {"effect": "redact", "actions": ["*"], "redactions": ["parameters.x"]},
            {
                "effect": "rate_limit",
                "actions": ["*"],
                "rate_limit": {"max": 1, "window_seconds": 1},
            },
            {"effect": "approval", "actions": ["*"]},
            {"effect": "deny", "actions": ["*"]},
        ],
    )
    assert evaluate(EvaluationInput(tool="t"), [p]).decision == Decision.deny


def test_action_specific_pattern_matching():
    p = policy(
        "P",
        [{"effect": "deny", "actions": ["database.*:write"]}],
    )
    assert (
        evaluate(EvaluationInput(tool="database.users", action="write"), [p]).decision
        == Decision.deny
    )
    assert (
        evaluate(EvaluationInput(tool="database.users", action="read"), [p]).decision
        == Decision.allow
    )


def test_more_specific_default_wins():
    org = policy("ORG", [], specificity=0, default="deny")
    agent = policy("AGENT", [], specificity=2, default="allow")
    res = evaluate(EvaluationInput(tool="anything"), [org, agent])
    assert res.decision == Decision.allow
    assert res.reasons[0].startswith("AGENT")
