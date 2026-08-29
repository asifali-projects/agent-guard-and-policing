"""The `AgentGuard` facade — identity, tool interception, enforcement (PRD §37)."""

from __future__ import annotations

import functools
import inspect
import time
import uuid
from collections.abc import Callable
from typing import Any, TypeVar

import httpx

from . import config as _config
from .client import Client
from .decision import Decision, DecisionResult
from .exceptions import (
    ApprovalRequired,
    ConfigurationError,
    PolicyDenied,
    RateLimited,
    RuntimeUnavailable,
)
from .redact import redact_params

F = TypeVar("F", bound=Callable[..., Any])


class AgentGuard:
    def __init__(
        self,
        *,
        api_key: str | None = None,
        base_url: str | None = None,
        agent: str | None = None,
        environment: str | None = None,
        fail_mode: str | None = None,
        timeout: float | None = None,
        session: httpx.Client | None = None,
        auto_register: bool = True,
    ) -> None:
        self.config = _config.resolve(
            api_key=api_key,
            base_url=base_url,
            agent=agent,
            environment=environment,
            fail_mode=fail_mode,
            timeout=timeout,
        )
        self._client = Client(
            api_key=self.config.api_key,
            base_url=self.config.base_url,
            timeout=self.config.timeout,
            session=session,
        )
        self._auto_register = auto_register
        self._agent_id: str | None = None

    # --- lifecycle -------------------------------------------------------

    def close(self) -> None:
        self._client.close()

    def __enter__(self) -> AgentGuard:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    @property
    def client(self) -> Client:
        return self._client

    # --- identity -----------------------------------------------------

    @property
    def agent_id(self) -> str:
        if self._agent_id is None:
            if not self.config.agent:
                raise ConfigurationError(
                    "no agent — pass agent= to AgentGuard() or set AGENTGUARD_AGENT"
                )
            self._agent_id = self._client.resolve_agent_id(
                name=self.config.agent, environment=self.config.environment
            )
        return self._agent_id

    def protect(self, agent: Any = None, *, tools: list[Callable] | None = None) -> Any:
        """Register the agent and, if discoverable, wrap its tools (PRD §38)."""
        _ = self.agent_id  # force identity resolution / registration
        candidates = tools
        if candidates is None and agent is not None:
            candidates = list(getattr(agent, "tools", []) or [])
        if candidates:
            wrapped = [self.tool(fn) if callable(fn) else fn for fn in candidates]
            if agent is not None and hasattr(agent, "tools"):
                try:
                    agent.tools = wrapped
                except (AttributeError, TypeError):
                    pass
        if agent is not None:
            agent.agentguard = self  # type: ignore[attr-defined]
        return agent

    # --- evaluation -------------------------------------------------

    def evaluate(
        self,
        tool: str,
        parameters: dict | None = None,
        *,
        action: str = "execute",
        context: dict | None = None,
        request_id: str | None = None,
        data_classification: str | None = None,
    ) -> DecisionResult:
        """Ask the runtime what to do. Never raises for a normal decision;
        raises ``RuntimeUnavailable`` only when fail_mode='closed' and the API
        is unreachable."""
        rid = request_id or uuid.uuid4().hex
        try:
            return self._client.evaluate(
                agent_id=self.agent_id,
                tool=tool,
                action=action,
                parameters=parameters or {},
                context=context or {},
                request_id=rid,
                data_classification=data_classification,
            )
        except RuntimeUnavailable:
            if self.config.fail_mode == "open":
                return DecisionResult(
                    decision=Decision.ALLOW,
                    risk_score=0,
                    risk_severity="info",
                    request_id=rid,
                    reasons=["runtime unavailable — fail-open"],
                    fail_mode="fail_open",
                )
            raise

    def check(
        self,
        tool: str,
        parameters: dict | None = None,
        *,
        action: str = "execute",
        context: dict | None = None,
        request_id: str | None = None,
    ) -> tuple[DecisionResult, dict]:
        """Evaluate and enforce. Returns ``(result, effective_parameters)`` on
        ALLOW / REDACT; raises otherwise."""
        params = parameters or {}
        try:
            result = self.evaluate(
                tool, params, action=action, context=context, request_id=request_id
            )
        except RuntimeUnavailable as exc:
            raise PolicyDenied(
                f"runtime unavailable (fail-closed): {exc}", _unavailable(exc)
            ) from exc

        if result.decision == Decision.ALLOW:
            return result, params
        if result.decision == Decision.REDACT:
            return result, redact_params(params, result.redactions)
        if result.decision == Decision.APPROVAL:
            raise ApprovalRequired("; ".join(result.reasons) or "approval required", result)
        if result.decision == Decision.RATE_LIMIT:
            raise RateLimited("; ".join(result.reasons) or "rate limited", result)
        raise PolicyDenied("; ".join(result.reasons) or "denied", result)

    # --- tool decorator ---------------------------------------------

    def tool(
        self,
        func: F | None = None,
        *,
        name: str | None = None,
        action: str = "execute",
    ) -> F | Callable[[F], F]:
        def decorate(fn: F) -> F:
            tool_name = name or fn.__name__
            sig = inspect.signature(fn)

            @functools.wraps(fn)
            def wrapper(*args: Any, **kwargs: Any) -> Any:
                bound = sig.bind_partial(*args, **kwargs)
                params = _serialisable(dict(bound.arguments))
                result, effective = self.check(tool_name, params, action=action)
                if result.decision == Decision.REDACT:
                    new_bound = sig.bind_partial(**effective)
                    return fn(*new_bound.args, **new_bound.kwargs)
                return fn(*args, **kwargs)

            wrapper.agentguard_tool = tool_name  # type: ignore[attr-defined]
            return wrapper  # type: ignore[return-value]

        return decorate if func is None else decorate(func)

    # --- approvals -------------------------------------------------

    def wait_for_approval(
        self, approval_request_id: str, *, poll_seconds: float = 2.0, timeout: float = 300.0
    ) -> str:
        """Block until an approval is decided. Returns its final status."""
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            row = self._client.get(f"/v1/approvals/{approval_request_id}")
            if row["status"] != "pending":
                return row["status"]
            time.sleep(poll_seconds)
        return "timeout"


def _serialisable(arguments: dict) -> dict:
    out: dict = {}
    for k, v in arguments.items():
        if isinstance(v, (str, int, float, bool, type(None), list, dict)):
            out[k] = v
        else:
            out[k] = repr(v)
    return out


def _unavailable(exc: Exception) -> DecisionResult:
    return DecisionResult(
        decision=Decision.DENY,
        risk_score=100,
        risk_severity="critical",
        request_id="",
        reasons=[f"runtime unavailable: {exc}"],
        fail_mode="fail_closed",
    )
