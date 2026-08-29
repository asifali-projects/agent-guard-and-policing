"""The deterministic evaluation function (PRD §24–25).

    evaluate(input, policies) -> DecisionResult

Total and side-effect free: the same inputs always yield the same result, and no
exception is raised for well-formed policies. Stateful obligations (rate-limit
counters, approval lookup) are resolved by the runtime layer, not here.
"""

from __future__ import annotations

from .conditions import evaluate_condition
from .spec import CompiledPolicy, PolicyRule
from .types import PRECEDENCE, Decision, DecisionResult, Effect, EvaluationInput, MatchedRule


def _namespace(inp: EvaluationInput) -> dict:
    return {
        "tool": inp.tool,
        "action": inp.action,
        "environment": inp.environment,
        "parameters": inp.parameters or {},
        "context": inp.context or {},
        "agent": {"id": inp.agent_id, "trust_level": inp.agent_trust_level},
        "data": {"classification": inp.data_classification},
    }


def _iter_matches(inp: EvaluationInput, policies: list[CompiledPolicy]):
    ns = _namespace(inp)
    ordered = sorted(policies, key=lambda p: p.sort_key)
    for policy in ordered:
        for idx, rule in enumerate(policy.spec.rules):
            if not rule.matches_action(inp.tool, inp.action):
                continue
            if not evaluate_condition(rule.when, ns):
                continue
            yield policy, idx, rule


def _rule_reason(policy: CompiledPolicy, idx: int, rule: PolicyRule) -> str:
    label = rule.description or f"{rule.effect.value} {', '.join(rule.actions)}"
    return f"{policy.key}#{idx}: {label}"


def evaluate(inp: EvaluationInput, policies: list[CompiledPolicy]) -> DecisionResult:
    matched: list[MatchedRule] = []
    by_effect: dict[Effect, list[tuple[CompiledPolicy, int, PolicyRule]]] = {e: [] for e in Effect}

    for policy, idx, rule in _iter_matches(inp, policies):
        by_effect[rule.effect].append((policy, idx, rule))
        matched.append(
            MatchedRule(
                policy_key=policy.key,
                rule_index=idx,
                effect=rule.effect,
                reason=_rule_reason(policy, idx, rule),
            )
        )

    for effect in PRECEDENCE:
        hits = by_effect[effect]
        if not hits:
            continue
        reasons = [_rule_reason(p, i, r) for p, i, r in hits]
        if effect == Effect.redact:
            redactions: list[str] = []
            for _, _, r in hits:
                for path in r.redactions:
                    if path not in redactions:
                        redactions.append(path)
            return DecisionResult(
                decision=Decision.redact, reasons=reasons, matched=matched, redactions=redactions
            )
        if effect == Effect.rate_limit:
            return DecisionResult(
                decision=Decision.rate_limit,
                reasons=reasons,
                matched=matched,
                rate_limit=hits[0][2].rate_limit,
            )
        return DecisionResult(decision=Decision(effect.value), reasons=reasons, matched=matched)

    # No rule matched — fall back to the most specific default_effect, else allow.
    for policy in sorted(policies, key=lambda p: p.sort_key):
        if policy.spec.default_effect is not None:
            return DecisionResult(
                decision=Decision(policy.spec.default_effect.value),
                reasons=[f"{policy.key}: default_effect={policy.spec.default_effect.value}"],
                matched=matched,
                default_applied=True,
            )
    return DecisionResult(
        decision=Decision.allow,
        reasons=["no policy matched; implicit allow"],
        matched=matched,
        default_applied=True,
    )
