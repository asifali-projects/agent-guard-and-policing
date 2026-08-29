"""Deterministic intent router — the analyst without an LLM (PRD §35).

Used when no ``ANTHROPIC_API_KEY`` is configured, and as a guaranteed-available
path in tests. Maps a question to one or two read-only tools and templates a
plain-language answer from the result.
"""

from __future__ import annotations

import re
import uuid

from sqlalchemy.ext.asyncio import AsyncSession

from . import tools
from .schemas import AnalystResult

SUGGESTIONS = [
    "What's our overall security posture?",
    "Which agents are the riskiest right now?",
    "Show me the open critical findings.",
    "Why was the last action blocked?",
    "What incidents are still open?",
    "Has anything tried to exfiltrate sensitive data this week?",
]


def _fmt_overview(d: dict) -> str:
    f = d.get("open_findings", {})
    return (
        f"Security score is **{d['security_score']}/100**. "
        f"{d['agents']} agents, {d['tools']} tools, {d['mcp_servers']} MCP servers. "
        f"Open findings: {f.get('critical', 0)} critical, {f.get('high', 0)} high, "
        f"{f.get('medium', 0)} medium. "
        f"{d['open_incidents']} open incidents, {d['open_threats']} open threats, "
        f"{d['approvals_pending']} approvals pending. "
        f"Last 24h: {d['runtime_actions_24h']} runtime actions, "
        f"{d['runtime_blocked_24h']} blocked."
    )


def _fmt_rows(rows: list[dict], cols: list[str], empty: str) -> str:
    if not rows:
        return empty
    lines = []
    for r in rows[:10]:
        parts = [f"{c}={r.get(c)}" for c in cols if r.get(c) is not None]
        lines.append("- " + ", ".join(parts))
    return "\n".join(lines)


async def answer(
    db: AsyncSession, org_id: uuid.UUID, question: str, history: list[dict] | None = None
) -> AnalystResult:
    q = question.lower().strip()
    calls: list[dict] = []
    cites: list[dict] = []

    async def call(name: str, **args) -> dict:
        result = await tools.run_tool(db, org_id, name, args)
        calls.append({"tool": name, "arguments": args})
        cites.append({"tool": name, "summary": summarize(name, result)})
        return result

    # explain a blocked/failed decision
    if re.search(r"why .*(block|deny|denied|refus|fail)|explain .*decision|what happened", q):
        d = await call("explain_decision")
        if d.get("error"):
            text = "I couldn't find a recent blocked or non-allow runtime decision to explain."
        else:
            pol = d.get("matched_policy") or {}
            text = (
                f"The most recent non-allow decision was **{d.get('decision')}** on tool "
                f"`{d.get('tool')}` for agent **{d.get('agent')}** at {d.get('occurred_at')}. "
                f"Risk score was {d.get('risk_score')}."
            )
            if pol:
                text += f" It matched policy `{pol.get('key')}` ({pol.get('name')})."
        return AnalystResult(text, "fallback", cites, calls)

    # riskiest agents
    if re.search(r"riski|most risk|highest risk|dangerous|weakest", q):
        d = await call("top_risky_agents", limit=10)
        text = "Agents by risk score (highest first):\n" + _fmt_rows(
            d.get("agents", []), ["name", "risk_score", "status", "open_findings"], "No agents yet."
        )
        return AnalystResult(text, "fallback", cites, calls)

    # findings
    if re.search(r"finding|vulnerab|weakness|cve", q):
        sev = _first_match(q, ["critical", "high", "medium", "low"])
        d = await call("list_findings", severity=sev)
        text = f"Open findings{' (' + sev + ')' if sev else ''}:\n" + _fmt_rows(
            d.get("findings", []),
            ["severity", "title", "agent", "status"],
            "No matching open findings — nice.",
        )
        return AnalystResult(text, "fallback", cites, calls)

    # incidents
    if "incident" in q:
        d = await call("list_incidents")
        text = "Incidents:\n" + _fmt_rows(
            d.get("incidents", []),
            ["key", "severity", "status", "agent", "title"],
            "No incidents on record.",
        )
        return AnalystResult(text, "fallback", cites, calls)

    # threats / anomalies / injection
    if re.search(r"threat|anomal|injection|suspicious", q):
        d = await call("list_threats")
        text = "Detected threats:\n" + _fmt_rows(
            d.get("threats", []),
            ["severity", "kind", "status", "agent"],
            "No threats detected.",
        )
        return AnalystResult(text, "fallback", cites, calls)

    # data exfiltration / DLP / PII
    if re.search(r"pii|sensitive|dlp|leak|exfil|redact|data loss", q):
        denied = await call("search_audit", decision="deny", hours=168)
        redacted = await call("search_audit", decision="redact", hours=168)
        text = (
            f"In the last 7 days: {len(denied.get('events', []))} actions were blocked and "
            f"{len(redacted.get('events', []))} had data redacted. Most recent:\n"
            + _fmt_rows(
                (denied.get("events", []) + redacted.get("events", []))[:10],
                ["occurred_at", "agent", "tool", "decision"],
                "Nothing blocked or redacted recently.",
            )
        )
        return AnalystResult(text, "fallback", cites, calls)

    # blocked / audit activity
    if re.search(r"block|denied|audit|recent activity|what.*(doing|happening)", q):
        d = await call("search_audit", decision="deny" if "block" in q or "denied" in q else None)
        text = f"Recent audit activity ({d.get('window_hours')}h window):\n" + _fmt_rows(
            d.get("events", []),
            ["occurred_at", "action", "agent", "tool", "decision"],
            "No matching audit events.",
        )
        return AnalystResult(text, "fallback", cites, calls)

    # a named agent?
    named = await _find_named_agent(db, org_id, question)
    if named is not None or re.search(r"\bagent\b|\bagents\b|inventory", q):
        if named is not None:
            d = await call("get_agent", name=named)
            if not d.get("error"):
                text = (
                    f"**{d['name']}** ({d['environment']}, {d['framework']}) — status "
                    f"{d['status']}, risk {d['risk_score']}. "
                    f"{d['open_findings']} open findings, {len(d['recent_incidents'])} recent "
                    f"incidents, {d['assessments_run']} assessments run."
                )
                return AnalystResult(text, "fallback", cites, calls)
        d = await call("list_agents", limit=50)
        text = "Agents:\n" + _fmt_rows(
            d.get("agents", []),
            ["name", "environment", "status", "risk_score"],
            "No agents registered yet.",
        )
        return AnalystResult(text, "fallback", cites, calls)

    # default: portfolio overview
    d = await call("security_overview")
    return AnalystResult(
        _fmt_overview(d) + "\n\nTry asking about riskiest agents, open findings, or incidents.",
        "fallback",
        cites,
        calls,
    )


def _first_match(text: str, options: list[str]) -> str | None:
    return next((o for o in options if o in text), None)


def summarize(name: str, result: dict) -> str:
    if result.get("error"):
        return result["error"]
    if name == "security_overview":
        return f"security score {result.get('security_score')}"
    for key in ("agents", "findings", "incidents", "threats", "events"):
        if isinstance(result.get(key), list):
            return f"{name}: {len(result[key])} {key}"
    return name


async def _find_named_agent(db: AsyncSession, org_id: uuid.UUID, question: str) -> str | None:
    from sqlalchemy import func, select

    from ..models import Agent

    names = (await db.scalars(select(Agent.name).where(Agent.organization_id == org_id))).all()
    low = question.lower()
    for name in names:
        if name and name.lower() in low:
            return name
    # single Titlecase / hyphenated token fallback
    for token in re.findall(r"[A-Za-z][A-Za-z0-9_-]{2,}", question):
        hit = await db.scalar(
            select(Agent.name).where(
                Agent.organization_id == org_id, func.lower(Agent.name) == token.lower()
            )
        )
        if hit:
            return hit
    return None
