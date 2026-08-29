"""AgentGuard deterministic policy engine (PRD §23–25).

Pure functions only — no I/O, no LLM, no database. The runtime layer loads
policies and applies stateful checks (rate-limit counters, approval lookup);
this package decides *what the policy says*.
"""

from .conditions import ConditionError, evaluate_condition
from .engine import evaluate
from .spec import CompiledPolicy, PolicyRule, PolicySpec, RateLimitSpec
from .types import Decision, DecisionResult, Effect, EvaluationInput, MatchedRule

__all__ = [
    "CompiledPolicy",
    "ConditionError",
    "Decision",
    "DecisionResult",
    "Effect",
    "EvaluationInput",
    "MatchedRule",
    "PolicyRule",
    "PolicySpec",
    "RateLimitSpec",
    "evaluate",
    "evaluate_condition",
]

__version__ = "0.0.0"
