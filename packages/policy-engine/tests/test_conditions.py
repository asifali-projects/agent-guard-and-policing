import pytest

from agentguard_policy.conditions import ConditionError, evaluate_condition, validate_condition

NS = {
    "parameters": {"amount": 6000, "records": 12, "to": "x@evil.com"},
    "context": {"destination": "external"},
    "data": {"classification": "confidential"},
}


@pytest.mark.parametrize(
    ("node", "expected"),
    [
        (None, True),
        ({}, True),
        ({"field": "parameters.amount", "op": "gt", "value": 5000}, True),
        ({"field": "parameters.amount", "op": "lt", "value": 5000}, False),
        ({"field": "context.destination", "op": "eq", "value": "external"}, True),
        ({"field": "parameters.missing", "op": "exists", "value": True}, False),
        ({"field": "parameters.amount", "op": "exists", "value": True}, True),
        (
            {"field": "data.classification", "op": "in", "value": ["confidential", "restricted"]},
            True,
        ),
        ({"field": "parameters.to", "op": "endswith", "value": "evil.com"}, True),
        ({"field": "parameters.to", "op": "matches", "value": r".+@evil\.com$"}, True),
    ],
)
def test_leaf_ops(node, expected):
    assert evaluate_condition(node, NS) is expected


def test_boolean_combinators():
    node = {
        "all": [
            {"field": "parameters.amount", "op": "gt", "value": 5000},
            {
                "any": [
                    {"field": "context.destination", "op": "eq", "value": "external"},
                    {"field": "parameters.records", "op": "gt", "value": 100},
                ]
            },
            {"not": {"field": "data.classification", "op": "eq", "value": "public"}},
        ]
    }
    assert evaluate_condition(node, NS) is True


def test_missing_field_is_not_a_crash():
    assert evaluate_condition({"field": "a.b.c", "op": "eq", "value": 1}, NS) is False
    assert evaluate_condition({"field": "a.b.c", "op": "ne", "value": 1}, NS) is True


def test_invalid_trees_rejected():
    with pytest.raises(ConditionError):
        validate_condition({"field": "x"})  # no op
    with pytest.raises(ConditionError):
        validate_condition({"field": "x", "op": "spaceship", "value": 1})
    with pytest.raises(ConditionError):
        validate_condition({"all": "not-a-list"})
