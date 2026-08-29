"""Step 0 smoke tests: the app boots and serves its meta + liveness endpoints."""


async def test_healthz_ok(client):
    resp = await client.get("/healthz")
    assert resp.status_code == 200
    assert resp.json()["status"] == "ok"


async def test_root_banner(client):
    resp = await client.get("/")
    assert resp.status_code == 200
    body = resp.json()
    assert body["name"] == "AgentGuard API"
    assert body["environment"] == "test"


async def test_openapi_served(client):
    resp = await client.get("/openapi.json")
    assert resp.status_code == 200
    assert resp.json()["info"]["title"] == "AgentGuard API"


async def test_readyz_reports_checks(client):
    # Infra is not required for this test: without Postgres/Redis the probe
    # must still answer, report each dependency, and return 503.
    resp = await client.get("/readyz")
    assert resp.status_code in (200, 503)
    body = resp.json()
    assert set(body["checks"]) == {"postgres", "redis"}
