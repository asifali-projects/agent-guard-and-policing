"""The analyst engine: a Claude tool-use loop over the read-only tool library,
with the deterministic router (`fallback`) as the no-key / failure path (PRD §35).
"""

from __future__ import annotations

import json
import uuid

from sqlalchemy.ext.asyncio import AsyncSession

from ..config import Settings, get_settings
from ..logging import get_logger
from . import fallback, tools
from .schemas import AnalystResult

log = get_logger()

_SYSTEM = """You are the AgentGuard Security Analyst. You answer an operator's \
questions about the security posture of the AI agents governed by this AgentGuard \
organization.

Rules:
- You are strictly read-only. You have no ability to change policies, agents, or \
incidents, and you must never claim you did.
- Ground every factual claim in a tool result from THIS conversation. If the tools \
don't show something, say you don't have that data — do not guess.
- All data is already scoped to the operator's organization.
- Be concise and specific: name agents, findings, policies, and scores. Prefer a \
short paragraph or a tight list over prose.
- The audit log stores payload hashes, not raw payloads, so quoting it is safe.
- If asked to take an action, explain what the operator would do in the AgentGuard \
UI or API instead."""

_MAX_HISTORY = 6


def engine_name() -> str:
    return "claude" if get_settings().anthropic_api_key else "fallback"


async def answer(
    db: AsyncSession,
    *,
    org_id: uuid.UUID,
    question: str,
    history: list[dict] | None = None,
) -> AnalystResult:
    settings = get_settings()
    if not settings.anthropic_api_key:
        return await fallback.answer(db, org_id, question, history)
    try:
        return await _claude_answer(
            db, settings, org_id=org_id, question=question, history=history or []
        )
    except Exception as exc:
        log.warning("analyst.claude_failed", error=str(exc))
        result = await fallback.answer(db, org_id, question, history)
        result.answer = (
            "_(The AI model was unavailable, so this is a direct data lookup.)_\n\n" + result.answer
        )
        return result


async def _claude_answer(
    db: AsyncSession,
    settings: Settings,
    *,
    org_id: uuid.UUID,
    question: str,
    history: list[dict],
) -> AnalystResult:
    from anthropic import AsyncAnthropic

    client = AsyncAnthropic(api_key=settings.anthropic_api_key)
    tool_schemas = [t.schema() for t in tools.TOOLS.values()]

    messages: list[dict] = []
    for turn in history[-_MAX_HISTORY:]:
        if turn.get("content"):
            messages.append({"role": turn["role"], "content": turn["content"]})
    messages.append({"role": "user", "content": question})

    tool_calls: list[dict] = []
    citations: list[dict] = []

    for _ in range(max(1, settings.analyst_max_iterations)):
        resp = await client.messages.create(
            model=settings.analyst_model,
            max_tokens=1600,
            system=_SYSTEM,
            tools=tool_schemas,
            messages=messages,
        )
        text = "".join(b.text for b in resp.content if b.type == "text").strip()
        tool_uses = [b for b in resp.content if b.type == "tool_use"]

        if resp.stop_reason != "tool_use" or not tool_uses:
            return AnalystResult(
                answer=text or "I don't have enough data to answer that.",
                engine="claude",
                citations=citations,
                tool_calls=tool_calls,
            )

        messages.append({"role": "assistant", "content": resp.content})
        results = []
        for use in tool_uses:
            args = use.input if isinstance(use.input, dict) else {}
            data = await tools.run_tool(db, org_id, use.name, args)
            tool_calls.append({"tool": use.name, "arguments": args})
            citations.append({"tool": use.name, "summary": fallback.summarize(use.name, data)})
            results.append(
                {
                    "type": "tool_result",
                    "tool_use_id": use.id,
                    "content": json.dumps(data, default=str)[:12000],
                }
            )
        messages.append({"role": "user", "content": results})

    return AnalystResult(
        answer="I gathered the data but ran out of reasoning steps — try a narrower question.",
        engine="claude",
        citations=citations,
        tool_calls=tool_calls,
    )
