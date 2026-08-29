"""Best-effort emission of runtime decisions to ClickHouse (PRD §45).

Never blocks or fails the decision: any error (ClickHouse down, timeout) is
swallowed. Kafka-fronted ingestion is wired in Step 8.
"""

from __future__ import annotations

import json
from typing import Any

import httpx

from ..config import get_settings
from ..logging import get_logger

log = get_logger("runtime.emit")


async def emit_decision(row: dict[str, Any]) -> None:
    settings = get_settings()
    url = f"http://{settings.clickhouse_host}:{settings.clickhouse_port}/"
    query = "INSERT INTO agentguard_events.runtime_decisions FORMAT JSONEachRow"
    try:
        async with httpx.AsyncClient(timeout=1.5) as client:
            resp = await client.post(
                url,
                params={"query": query},
                auth=("agentguard", "agentguard"),
                content=json.dumps(row),
            )
            if resp.status_code != 200:
                log.warning("emit.rejected", status=resp.status_code, body=resp.text[:200])
    except Exception as exc:
        log.warning("emit.failed", error=str(exc))
