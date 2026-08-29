"""Thin synchronous HTTP client for the AgentGuard API."""

from __future__ import annotations

from typing import Any

import httpx

from .decision import DecisionResult
from .exceptions import AgentGuardError, RuntimeUnavailable

_USER_AGENT = "agentguard-python/0.0.0"


class Client:
    def __init__(
        self,
        *,
        api_key: str,
        base_url: str,
        timeout: float = 5.0,
        session: httpx.Client | None = None,
    ) -> None:
        self._owns_session = session is None
        self._http = session or httpx.Client(
            base_url=base_url,
            timeout=timeout,
            headers={"Authorization": f"Bearer {api_key}", "User-Agent": _USER_AGENT},
        )

    def close(self) -> None:
        if self._owns_session:
            self._http.close()

    def __enter__(self) -> Client:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    # --- runtime -----------------------------------------------------------

    def evaluate(
        self,
        *,
        agent_id: str,
        tool: str,
        action: str = "execute",
        parameters: dict | None = None,
        context: dict | None = None,
        request_id: str | None = None,
        data_classification: str | None = None,
    ) -> DecisionResult:
        payload = {
            "agent_id": agent_id,
            "tool": tool,
            "action": action,
            "parameters": parameters or {},
            "context": context or {},
        }
        if request_id:
            payload["request_id"] = request_id
        if data_classification:
            payload["data_classification"] = data_classification
        try:
            resp = self._http.post("/v1/runtime/evaluate", json=payload)
        except httpx.HTTPError as exc:
            raise RuntimeUnavailable(f"runtime unreachable: {exc}") from exc
        return DecisionResult.from_api(_json(resp))

    # --- control plane --------------------------------------------------

    def get(self, path: str, **params: Any) -> Any:
        return _json(self._request("GET", path, params=params or None))

    def post(self, path: str, json: dict | None = None) -> Any:
        return _json(self._request("POST", path, json=json))

    def _request(self, method: str, path: str, **kw: Any) -> httpx.Response:
        try:
            return self._http.request(method, path, **kw)
        except httpx.HTTPError as exc:
            raise RuntimeUnavailable(f"{method} {path} failed: {exc}") from exc

    # --- identity -----------------------------------------------------

    def resolve_agent_id(self, *, name: str, environment: str) -> str:
        agents = self.get("/v1/agents")
        for a in agents:
            if a["name"] == name and a["environment"] == environment:
                return a["id"]
        created = self.post("/v1/agents", json={"name": name, "environment": environment})
        return created["id"]


def _json(resp: httpx.Response) -> Any:
    if resp.status_code >= 400:
        detail: Any
        try:
            detail = resp.json().get("detail", resp.text)
        except ValueError:
            detail = resp.text
        raise AgentGuardError(f"HTTP {resp.status_code}: {detail}")
    if resp.status_code == 204 or not resp.content:
        return None
    return resp.json()
