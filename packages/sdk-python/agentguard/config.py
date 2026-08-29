"""Resolve SDK configuration from explicit args, env vars, then a config file.

Config file: ``~/.agentguard/config.toml`` (or ``$AGENTGUARD_CONFIG``)

    api_key = "ag_live_..."
    base_url = "https://api.agentguard.example"
    agent = "FinanceAgent"
    environment = "production"
"""

from __future__ import annotations

import os
import tomllib
from dataclasses import dataclass
from pathlib import Path

from .exceptions import ConfigurationError

DEFAULT_BASE_URL = "http://localhost:8010"


def config_path() -> Path:
    override = os.environ.get("AGENTGUARD_CONFIG")
    if override:
        return Path(override)
    return Path.home() / ".agentguard" / "config.toml"


def _load_file() -> dict:
    path = config_path()
    if not path.is_file():
        return {}
    try:
        return tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError) as exc:
        raise ConfigurationError(f"could not read {path}: {exc}") from exc


@dataclass(frozen=True)
class Config:
    api_key: str
    base_url: str
    agent: str | None
    environment: str
    fail_mode: str  # "closed" | "open"
    timeout: float


def resolve(
    *,
    api_key: str | None = None,
    base_url: str | None = None,
    agent: str | None = None,
    environment: str | None = None,
    fail_mode: str | None = None,
    timeout: float | None = None,
    require_api_key: bool = True,
) -> Config:
    file = _load_file()

    api_key = api_key or os.environ.get("AGENTGUARD_API_KEY") or file.get("api_key")
    if require_api_key and not api_key:
        raise ConfigurationError(
            "no API key — pass api_key=, set AGENTGUARD_API_KEY, or run `agentguard login`"
        )

    base_url = (
        base_url
        or os.environ.get("AGENTGUARD_BASE_URL")
        or file.get("base_url")
        or DEFAULT_BASE_URL
    ).rstrip("/")
    agent = agent or os.environ.get("AGENTGUARD_AGENT") or file.get("agent")
    environment = (
        environment
        or os.environ.get("AGENTGUARD_ENVIRONMENT")
        or file.get("environment")
        or "production"
    )
    fail_mode = (
        fail_mode or os.environ.get("AGENTGUARD_FAIL_MODE") or file.get("fail_mode") or "closed"
    ).lower()
    if fail_mode not in {"closed", "open"}:
        raise ConfigurationError("fail_mode must be 'closed' or 'open'")
    timeout = timeout if timeout is not None else float(os.environ.get("AGENTGUARD_TIMEOUT", "5.0"))

    return Config(
        api_key=api_key or "",
        base_url=base_url,
        agent=agent,
        environment=environment,
        fail_mode=fail_mode,
        timeout=timeout,
    )


def save(data: dict) -> Path:
    path = config_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    lines = [f'{k} = "{v}"' for k, v in data.items() if v is not None]
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    path.chmod(0o600)
    return path
