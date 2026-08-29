"""Multi-region data residency — region discovery, org pinning, the residency
guard (PRD §76)."""

from __future__ import annotations

from agentguard_api.config import get_settings

from .test_auth import bearer, register


async def test_regions_discovery_is_public(api):
    resp = await api.get("/v1/regions")
    assert resp.status_code == 200
    body = resp.json()
    assert body["current"] == "us"
    us = next(r for r in body["regions"] if r["code"] == "us")
    assert us["current"] is True
    assert us["api_url"].startswith("http")


async def test_registration_pins_the_org_to_this_region(api):
    _, _, tok = await register(api)
    me = await api.get("/v1/auth/me", headers=bearer(tok["access_token"]))
    assert me.status_code == 200
    body = me.json()
    assert body["region"] == "us"
    assert body["active_region"] == "us"
    assert body["memberships"][0]["region"] == "us"


async def test_registration_accepts_the_matching_region(api):
    resp = await api.post(
        "/v1/auth/register",
        json={
            "email": "match@example.com",
            "password": "correct horse battery",
            "organization_name": "Match Co",
            "region": "us",
        },
    )
    assert resp.status_code == 201


async def test_registration_rejects_a_foreign_region(api):
    resp = await api.post(
        "/v1/auth/register",
        json={
            "email": "eu@example.com",
            "password": "correct horse battery",
            "organization_name": "EU Co",
            "region": "eu",
        },
    )
    assert resp.status_code == 421
    assert resp.headers["x-agentguard-region"] == "eu"


async def test_create_org_region_must_match_deployment(api):
    _, _, tok = await register(api)
    h = bearer(tok["access_token"])

    bad = await api.post(
        "/v1/organizations", json={"name": "Foreign Org", "region": "apac"}, headers=h
    )
    assert bad.status_code == 421

    ok = await api.post("/v1/organizations", json={"name": "Home Org", "region": "us"}, headers=h)
    assert ok.status_code == 201
    assert ok.json()["region"] == "us"


async def test_org_region_is_immutable(api):
    _, _, tok = await register(api)
    org = tok["organization_id"]
    h = bearer(tok["access_token"])

    patched = await api.patch(
        f"/v1/organizations/{org}", json={"name": "Renamed", "region": "eu"}, headers=h
    )
    assert patched.status_code == 200
    assert patched.json()["region"] == "us"  # region field ignored


async def test_residency_guard_blocks_out_of_region_orgs(api, monkeypatch):
    _, _, tok = await register(api)
    h = bearer(tok["access_token"])
    assert (await api.get("/v1/auth/me", headers=h)).status_code == 200

    # The org is homed in "us"; pretend this deployment now serves "eu".
    monkeypatch.setattr(get_settings(), "region", "eu")

    blocked = await api.get("/v1/auth/me", headers=h)
    assert blocked.status_code == 421
    assert blocked.headers["x-agentguard-region"] == "us"
    assert "x-agentguard-region-url" in blocked.headers

    # discovery still works without a principal
    assert (await api.get("/v1/regions")).json()["current"] == "eu"

    # a new registration in this deployment is now homed in "eu"
    resp = await api.post(
        "/v1/auth/register",
        json={
            "email": "now-eu@example.com",
            "password": "correct horse battery",
            "organization_name": "Now EU",
        },
    )
    assert resp.status_code == 201
    me = await api.get("/v1/auth/me", headers=bearer(resp.json()["access_token"]))
    assert me.json()["region"] == "eu"
    assert me.json()["active_region"] == "eu"
