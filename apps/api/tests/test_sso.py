"""Enterprise SSO — OIDC callback, SAML ACS, domain discovery, JIT provisioning,
enforced-SSO password block, SP metadata (PRD §9, §51)."""

from __future__ import annotations

import base64
import datetime as dt
import uuid
from urllib.parse import parse_qs, urlsplit

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from lxml import etree
from signxml import XMLSigner

from agentguard_api.sso import saml as saml_mod

from .test_auth import bearer, register

API_BASE = "http://localhost:8010"
WEB_BASE = "http://localhost:3010"


def _oidc_config() -> dict:
    return {
        "issuer": "https://idp.example",
        "client_id": "ag-client",
        "client_secret": "super-secret-value",
        "authorization_endpoint": "https://idp.example/authorize",
        "token_endpoint": "https://idp.example/token",
        "jwks_uri": "https://idp.example/jwks",
    }


async def _create_conn(api, token, org_id, body) -> dict:
    resp = await api.post(f"/v1/organizations/{org_id}/sso", json=body, headers=bearer(token))
    assert resp.status_code == 201, resp.text
    return resp.json()


def _fragment_tokens(location: str) -> dict:
    frag = urlsplit(location).fragment
    return {k: v[0] for k, v in parse_qs(frag).items()}


# --- admin CRUD ------------------------------------------------------------


async def test_connection_crud_redacts_secrets(api):
    _, _, tok = await register(api)
    org = tok["organization_id"]
    conn = await _create_conn(
        api,
        tok["access_token"],
        org,
        {
            "name": "Okta",
            "protocol": "oidc",
            "domains": ["Acme.example"],
            "config": _oidc_config(),
        },
    )
    assert conn["config"]["client_secret"] == "********"
    assert conn["domains"] == ["acme.example"]  # normalized to lowercase

    got = await api.get(
        f"/v1/organizations/{org}/sso/{conn['id']}", headers=bearer(tok["access_token"])
    )
    assert got.status_code == 200
    assert got.json()["config"]["client_secret"] == "********"

    patched = await api.patch(
        f"/v1/organizations/{org}/sso/{conn['id']}",
        json={"enabled": False, "config": {"client_secret": "********"}},
        headers=bearer(tok["access_token"]),
    )
    assert patched.status_code == 200
    assert patched.json()["enabled"] is False

    deleted = await api.delete(
        f"/v1/organizations/{org}/sso/{conn['id']}", headers=bearer(tok["access_token"])
    )
    assert deleted.status_code == 204


async def test_connection_crud_requires_org_manage(api):
    _, _, tok = await register(api)
    other_org = uuid.uuid4()
    resp = await api.get(f"/v1/organizations/{other_org}/sso", headers=bearer(tok["access_token"]))
    assert resp.status_code == 403


# --- discovery + OIDC sign-in --------------------------------------------


async def test_discover_and_oidc_jit_provisioning(api, monkeypatch):
    _, _, tok = await register(api)
    org = tok["organization_id"]
    conn = await _create_conn(
        api,
        tok["access_token"],
        org,
        {
            "name": "Entra",
            "protocol": "oidc",
            "domains": ["oidc-corp.example"],
            "config": _oidc_config(),
        },
    )
    cid = conn["id"]

    disc = await api.post("/v1/auth/sso/discover", json={"email": "newcomer@oidc-corp.example"})
    assert disc.status_code == 200
    body = disc.json()
    assert body["sso"] is True
    assert body["connection_id"] == cid
    assert body["protocol"] == "oidc"

    # unknown domain -> no SSO
    none = await api.post("/v1/auth/sso/discover", json={"email": "x@random.example"})
    assert none.json()["sso"] is False

    login = await api.get(f"/v1/auth/sso/{cid}/login")
    assert login.status_code == 307
    loc = login.headers["location"]
    assert loc.startswith("https://idp.example/authorize")
    state = parse_qs(urlsplit(loc).query)["state"][0]

    from agentguard_api.sso import oidc as oidc_mod

    async def fake_exchange(conn, *, code, redirect_uri):
        assert code == "auth-code-123"
        return oidc_mod.OidcProfile(
            subject="oidc-subject-1",
            email="jit.user@oidc-corp.example",
            name="JIT User",
            raw={"sub": "oidc-subject-1"},
        )

    monkeypatch.setattr(oidc_mod, "exchange", fake_exchange)

    cb = await api.get(
        f"/v1/auth/sso/{cid}/callback", params={"code": "auth-code-123", "state": state}
    )
    assert cb.status_code == 303
    dest = cb.headers["location"]
    assert dest.startswith(f"{WEB_BASE}/sso/callback#")
    tokens = _fragment_tokens(dest)
    assert tokens["organization_id"] == org

    me = await api.get("/v1/auth/me", headers=bearer(tokens["access_token"]))
    assert me.status_code == 200
    assert me.json()["email"] == "jit.user@oidc-corp.example"
    assert me.json()["memberships"][0]["role"] == "developer"


async def test_oidc_callback_bad_state_rejected(api):
    _, _, tok = await register(api)
    org = tok["organization_id"]
    conn = await _create_conn(
        api,
        tok["access_token"],
        org,
        {"name": "E2", "protocol": "oidc", "domains": ["s.example"], "config": _oidc_config()},
    )
    cb = await api.get(
        f"/v1/auth/sso/{conn['id']}/callback", params={"code": "c", "state": "not-a-jwt"}
    )
    assert cb.status_code == 400


# --- enforced SSO blocks password login ---------------------------------


async def test_enforced_sso_blocks_password_login(api):
    _, _, tok = await register(api)
    org = tok["organization_id"]
    await _create_conn(
        api,
        tok["access_token"],
        org,
        {
            "name": "Locked",
            "protocol": "oidc",
            "domains": ["locked.example"],
            "enforced": True,
            "config": _oidc_config(),
        },
    )
    resp = await api.post(
        "/v1/auth/login", json={"email": "someone@locked.example", "password": "whatever-long"}
    )
    assert resp.status_code == 401
    assert "sso" in resp.json()["detail"].lower()


# --- SAML ---------------------------------------------------------------


def _keypair() -> tuple[bytes, str]:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test-idp")])
    now = dt.datetime.now(dt.UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(days=1))
        .not_valid_after(now + dt.timedelta(days=365))
        .sign(key, hashes.SHA256())
    )
    key_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode()
    return key_pem, cert_pem


def _signed_saml_response(cid: str, key_pem: bytes, cert_pem: str, *, email: str) -> str:
    now = dt.datetime.now(dt.UTC)
    fmt = "%Y-%m-%dT%H:%M:%SZ"
    aud = saml_mod.sp_entity_id(API_BASE, cid)
    nb = (now - dt.timedelta(minutes=5)).strftime(fmt)
    na = (now + dt.timedelta(minutes=10)).strftime(fmt)
    iat = now.strftime(fmt)
    success = "urn:oasis:names:tc:SAML:2.0:status:Success"
    parts = [
        '<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"',
        ' xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"',
        f' ID="_r{uuid.uuid4().hex}" Version="2.0" IssueInstant="{iat}">',
        "<saml:Issuer>https://idp.example/metadata</saml:Issuer>",
        f'<samlp:Status><samlp:StatusCode Value="{success}"/></samlp:Status>',
        f'<saml:Assertion ID="_a{uuid.uuid4().hex}" Version="2.0" IssueInstant="{iat}">',
        "<saml:Issuer>https://idp.example/metadata</saml:Issuer>",
        f"<saml:Subject><saml:NameID>{email}</saml:NameID></saml:Subject>",
        f'<saml:Conditions NotBefore="{nb}" NotOnOrAfter="{na}">',
        f"<saml:AudienceRestriction><saml:Audience>{aud}</saml:Audience>",
        "</saml:AudienceRestriction></saml:Conditions>",
        "<saml:AttributeStatement>",
        f'<saml:Attribute Name="email"><saml:AttributeValue>{email}'
        "</saml:AttributeValue></saml:Attribute>",
        '<saml:Attribute Name="name"><saml:AttributeValue>SAML Person'
        "</saml:AttributeValue></saml:Attribute>",
        "</saml:AttributeStatement></saml:Assertion></samlp:Response>",
    ]
    root = etree.fromstring("".join(parts).encode())
    signed = XMLSigner(signature_algorithm="rsa-sha256", digest_algorithm="sha256").sign(
        root, key=key_pem, cert=cert_pem
    )
    return base64.b64encode(etree.tostring(signed)).decode()


async def test_saml_acs_flow_and_metadata(api):
    _, _, tok = await register(api)
    org = tok["organization_id"]
    key_pem, cert_pem = _keypair()
    conn = await _create_conn(
        api,
        tok["access_token"],
        org,
        {
            "name": "ADFS",
            "protocol": "saml",
            "domains": ["corp-saml.example"],
            "config": {
                "idp_entity_id": "https://idp.example/metadata",
                "idp_sso_url": "https://idp.example/sso",
                "idp_x509_cert": cert_pem,
            },
        },
    )
    cid = conn["id"]

    meta = await api.get(
        f"/v1/organizations/{org}/sso/{cid}/metadata", headers=bearer(tok["access_token"])
    )
    assert meta.status_code == 200
    assert "AssertionConsumerService" in meta.text
    assert f"/v1/auth/sso/{cid}/acs" in meta.text

    login = await api.get(f"/v1/auth/sso/{cid}/login")
    assert login.status_code == 307
    q = parse_qs(urlsplit(login.headers["location"]).query)
    assert "SAMLRequest" in q
    relay_state = q["RelayState"][0]

    saml_response = _signed_saml_response(
        cid, key_pem, cert_pem, email="saml.person@corp-saml.example"
    )
    acs = await api.post(
        f"/v1/auth/sso/{cid}/acs",
        data={"SAMLResponse": saml_response, "RelayState": relay_state},
    )
    assert acs.status_code == 303, acs.text
    dest = acs.headers["location"]
    assert dest.startswith(f"{WEB_BASE}/sso/callback#")
    tokens = _fragment_tokens(dest)

    me = await api.get("/v1/auth/me", headers=bearer(tokens["access_token"]))
    assert me.status_code == 200
    assert me.json()["email"] == "saml.person@corp-saml.example"
    assert me.json()["memberships"][0]["role"] == "developer"


async def test_saml_acs_rejects_bad_signature(api):
    _, _, tok = await register(api)
    org = tok["organization_id"]
    _, real_cert = _keypair()
    attacker_key, attacker_cert = _keypair()  # not the cert the connection trusts
    conn = await _create_conn(
        api,
        tok["access_token"],
        org,
        {
            "name": "ADFS2",
            "protocol": "saml",
            "domains": ["evil-saml.example"],
            "config": {
                "idp_entity_id": "https://idp.example/metadata",
                "idp_sso_url": "https://idp.example/sso",
                "idp_x509_cert": real_cert,
            },
        },
    )
    cid = conn["id"]
    forged = _signed_saml_response(
        cid, attacker_key, attacker_cert, email="intruder@evil-saml.example"
    )
    acs = await api.post(f"/v1/auth/sso/{cid}/acs", data={"SAMLResponse": forged})
    assert acs.status_code == 303
    assert "sso_error" in acs.headers["location"]


@pytest.mark.parametrize("proto", ["oidc", "saml"])
async def test_login_unknown_connection_404(api, proto):
    resp = await api.get(f"/v1/auth/sso/{uuid.uuid4()}/login")
    assert resp.status_code == 404
