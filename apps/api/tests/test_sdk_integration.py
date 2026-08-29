"""End-to-end: the real `agentguard` SDK driving a live API server."""

from __future__ import annotations

import socket
import subprocess
import sys
import time
import uuid

import httpx
import pytest

agentguard = pytest.importorskip("agentguard")
from agentguard import AgentGuard, PolicyDenied  # noqa: E402


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture(scope="session")
def live_server(_database_url: str):
    import os

    port = _free_port()
    env = {**os.environ, "DATABASE_URL": _database_url, "AGENTGUARD_ENV": "test"}
    proc = subprocess.Popen(
        [
            sys.executable,
            "-m",
            "uvicorn",
            "agentguard_api.main:app",
            "--port",
            str(port),
            "--log-level",
            "warning",
        ],
        env=env,
        cwd=str(__import__("pathlib").Path(__file__).resolve().parents[1]),
    )
    base = f"http://127.0.0.1:{port}"
    deadline = time.time() + 30
    try:
        while time.time() < deadline:
            try:
                if httpx.get(f"{base}/healthz", timeout=1).status_code == 200:
                    break
            except httpx.HTTPError:
                time.sleep(0.3)
        else:
            proc.terminate()
            pytest.fail("live server did not start")
        yield base
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()


def _bootstrap(base: str) -> tuple[str, str]:
    """Register an org, return (api_key, base_url)."""
    email = f"sdk-{uuid.uuid4().hex[:10]}@example.com"
    reg = httpx.post(
        f"{base}/v1/auth/register",
        json={
            "email": email,
            "password": "correct horse battery staple",
            "organization_name": "SDK Co",
        },
        timeout=10,
    ).json()
    token = reg["access_token"]
    org = reg["organization_id"]
    key = httpx.post(
        f"{base}/v1/organizations/{org}/api-keys",
        headers={"Authorization": f"Bearer {token}"},
        json={
            "name": "sdk",
            "environment": "production",
            "scopes": ["runtime.evaluate", "agent.read", "agent.manage", "policy.manage"],
        },
        timeout=10,
    ).json()
    return key["key"], token, org


def test_sdk_allow_and_deny_end_to_end(live_server):
    api_key, token, org = _bootstrap(live_server)
    guard = AgentGuard(
        api_key=api_key, base_url=live_server, agent="SdkAgent", environment="production"
    )

    calls = []

    @guard.tool
    def export_customers(records: int):
        calls.append(records)
        return f"exported {records}"

    assert export_customers(5) == "exported 5"
    assert calls == [5]

    # bind a deny policy for this tool, then the same call is blocked
    pol = httpx.post(
        f"{live_server}/v1/policies",
        headers={"Authorization": f"Bearer {token}"},
        json={
            "key": "SDK-DENY",
            "name": "no export",
            "spec": {"rules": [{"effect": "deny", "actions": ["export_customers"]}]},
        },
        timeout=10,
    ).json()
    httpx.post(
        f"{live_server}/v1/policies/{pol['id']}/bindings",
        headers={"Authorization": f"Bearer {token}"},
        json={"scope_type": "organization"},
        timeout=10,
    )

    with pytest.raises(PolicyDenied):
        export_customers(5)

    guard.close()


def test_sdk_dlp_blocks_secret(live_server):
    api_key, token, org = _bootstrap(live_server)
    guard = AgentGuard(
        api_key=api_key, base_url=live_server, agent="SdkAgent2", environment="production"
    )

    @guard.tool
    def push_config(blob: str):
        raise AssertionError("must not run — contains a private key")

    with pytest.raises(PolicyDenied):
        push_config("-----BEGIN RSA PRIVATE KEY-----\nMIIBstuff")

    guard.close()
