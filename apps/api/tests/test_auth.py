"""Auth flow tests against a real throwaway Postgres database."""

from __future__ import annotations

import uuid

import pyotp


def _email() -> str:
    return f"user-{uuid.uuid4().hex[:10]}@example.com"


async def register(api, *, email=None, org=None, password="correct horse battery"):
    email = email or _email()
    resp = await api.post(
        "/v1/auth/register",
        json={
            "email": email,
            "password": password,
            "full_name": "Test User",
            "organization_name": org or f"Org {uuid.uuid4().hex[:6]}",
        },
    )
    assert resp.status_code == 201, resp.text
    return email, password, resp.json()


def bearer(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


async def test_register_returns_tokens_and_me(api):
    email, _, tok = await register(api)
    assert tok["access_token"] and tok["refresh_token"]
    assert tok["organization_id"]

    me = await api.get("/v1/auth/me", headers=bearer(tok["access_token"]))
    assert me.status_code == 200
    body = me.json()
    assert body["email"] == email
    assert body["memberships"][0]["role"] == "owner"
    assert "org.manage" in body["permissions"]


async def test_duplicate_registration_conflicts(api):
    email, pw, _ = await register(api)
    resp = await api.post(
        "/v1/auth/register",
        json={
            "email": email,
            "password": pw,
            "organization_name": "Another",
        },
    )
    assert resp.status_code == 409


async def test_login_wrong_password_401(api):
    email, _, _ = await register(api)
    resp = await api.post("/v1/auth/login", json={"email": email, "password": "nope"})
    assert resp.status_code == 401


async def test_refresh_rotation_invalidates_old_token(api):
    _, _, tok = await register(api)
    old_refresh = tok["refresh_token"]

    r1 = await api.post("/v1/auth/refresh", json={"refresh_token": old_refresh})
    assert r1.status_code == 200
    new_refresh = r1.json()["refresh_token"]
    assert new_refresh != old_refresh

    # reusing the old (now rotated) token is rejected...
    r2 = await api.post("/v1/auth/refresh", json={"refresh_token": old_refresh})
    assert r2.status_code == 401
    # ...and triggers revocation of the whole family, including the new token
    r3 = await api.post("/v1/auth/refresh", json={"refresh_token": new_refresh})
    assert r3.status_code == 401


async def test_logout_revokes_session(api):
    _, _, tok = await register(api)
    headers = bearer(tok["access_token"])
    assert (await api.get("/v1/auth/me", headers=headers)).status_code == 200

    out = await api.post("/v1/auth/logout", json={}, headers=headers)
    assert out.status_code == 204

    assert (await api.get("/v1/auth/me", headers=headers)).status_code == 401


async def test_mfa_enrollment_and_challenge(api):
    email, pw, tok = await register(api)
    headers = bearer(tok["access_token"])

    enroll = await api.post("/v1/auth/mfa/enroll", headers=headers)
    assert enroll.status_code == 200
    secret = enroll.json()["secret"]
    totp = pyotp.TOTP(secret)

    act = await api.post("/v1/auth/mfa/activate", json={"code": totp.now()}, headers=headers)
    assert act.status_code == 204

    # next login is now a two-step challenge
    login = await api.post("/v1/auth/login", json={"email": email, "password": pw})
    assert login.status_code == 200
    assert login.json().get("mfa_required") is True
    mfa_token = login.json()["mfa_token"]

    bad = await api.post("/v1/auth/mfa/verify", json={"mfa_token": mfa_token, "code": "000000"})
    assert bad.status_code == 401

    good = await api.post("/v1/auth/mfa/verify", json={"mfa_token": mfa_token, "code": totp.now()})
    assert good.status_code == 200
    assert good.json()["access_token"]


async def test_tenant_isolation_on_org_read(api):
    _, _, a = await register(api)
    _, _, b = await register(api)
    b_org = b["organization_id"]

    # user A's token must not read user B's organization
    resp = await api.get(f"/v1/organizations/{b_org}", headers=bearer(a["access_token"]))
    assert resp.status_code == 403

    ok = await api.get(
        f"/v1/organizations/{a['organization_id']}", headers=bearer(a["access_token"])
    )
    assert ok.status_code == 200


async def test_unauthenticated_is_401(api):
    assert (await api.get("/v1/auth/me")).status_code == 401
    assert (await api.get("/v1/organizations")).status_code == 401
