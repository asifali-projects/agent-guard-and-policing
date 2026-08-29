"""MCP inventory + heuristic scan (PRD §17)."""

from __future__ import annotations

from .test_auth import bearer, register


async def test_risky_server_is_quarantined(api):
    _, _, owner = await register(api)
    h = bearer(owner["access_token"])

    made = await api.post(
        "/v1/mcp/servers",
        json={
            "name": "community-fs",
            "url": "https://user:pass@fs.example/mcp",
            "trusted": False,
            "permissions": ["admin", "filesystem.read"],
            "external_dependencies": ["some-pkg"],
        },
        headers=h,
    )
    assert made.status_code == 201, made.text
    sid = made.json()["id"]

    scan = await api.post(f"/v1/mcp/servers/{sid}/scan", headers=h)
    assert scan.status_code == 200
    body = scan.json()
    assert set(body["issues"]) >= {
        "untrusted_server",
        "excessive_permissions",
        "dangerous_filesystem_access",
        "credential_exposure",
        "no_version_pinned",
        "external_dependencies",
    }
    assert body["severity"] == "critical"
    assert body["status"] == "quarantined"

    got = await api.get(f"/v1/mcp/servers/{sid}", headers=h)
    assert got.json()["status"] == "quarantined"
    assert got.json()["risk"] == "critical"


async def test_clean_server_is_active(api):
    _, _, owner = await register(api)
    h = bearer(owner["access_token"])
    made = await api.post(
        "/v1/mcp/servers",
        json={
            "name": "postgres-mcp",
            "url": "https://mcp.internal/pg",
            "trusted": True,
            "version": "1.4.2",
            "permissions": ["read"],
        },
        headers=h,
    )
    sid = made.json()["id"]
    scan = await api.post(f"/v1/mcp/servers/{sid}/scan", headers=h)
    assert scan.json()["issues"] == []
    assert scan.json()["status"] == "active"
    assert scan.json()["severity"] == "info"
