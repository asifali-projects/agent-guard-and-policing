"""Apply the ClickHouse event-store schema.

    python -m agentguard_api.events.migrate

Idempotent: every statement is ``CREATE ... IF NOT EXISTS``. This is a bootstrap
step, not a versioned migration system — event tables change rarely and are
altered explicitly.
"""

from __future__ import annotations

import sys
from pathlib import Path

import httpx

from agentguard_api.config import get_settings

SCHEMA = Path(__file__).with_name("clickhouse_schema.sql")


def _statements(sql: str) -> list[str]:
    # Strip full-line `--` comments, then split on `;`.
    lines = [ln for ln in sql.splitlines() if not ln.lstrip().startswith("--")]
    return [s.strip() for s in "\n".join(lines).split(";") if s.strip()]


def run() -> int:
    settings = get_settings()
    base = f"http://{settings.clickhouse_host}:{settings.clickhouse_port}/"
    auth = ("agentguard", "agentguard")
    statements = _statements(SCHEMA.read_text(encoding="utf-8"))

    with httpx.Client(timeout=10.0) as client:
        for stmt in statements:
            resp = client.post(base, params={"query": stmt}, auth=auth)
            if resp.status_code != 200:
                print(f"FAILED:\n{stmt}\n-> {resp.status_code} {resp.text}", file=sys.stderr)
                return 1
            label = " ".join(stmt.split()[:4])
            print(f"ok  {label}")
    print(f"applied {len(statements)} statements")
    return 0


if __name__ == "__main__":
    raise SystemExit(run())
