# Enterprise SSO — SAML 2.0 & OIDC (Step 10)

Covers PRD §9 (federated login) and §51 (enterprise auth methods).

Two IdP protocols, one connection model, domain-based routing, and just-in-time
provisioning. No system libraries: SAML signature verification runs on
[`signxml`](https://pypi.org/project/signxml/) (pure Python — `lxml` +
`cryptography`), so the Docker image and Windows dev boxes need nothing extra.

## The connection model

`sso_connections` (migration `1adba2d08ffa`) — one row per configured IdP:

| Column | Notes |
|--------|-------|
| `organization_id` | tenant that owns the connection |
| `name` | unique per org (e.g. "Okta", "Entra ID") |
| `protocol` | `oidc` \| `saml` |
| `enabled` | disabled connections are invisible to the sign-in flow |
| `enforced` | members on `domains` **cannot** use a password (see below) |
| `domains` | email domains this connection claims, lowercased |
| `default_role` | membership role granted to JIT-provisioned users |
| `config` | JSONB — protocol-specific (secrets **must be encrypted at rest in production**, same story as `users.mfa_secret`) |

`config` keys:

- **OIDC** — `issuer`, `client_id`, `client_secret`, plus
  `authorization_endpoint` / `token_endpoint` / `jwks_uri` (auto-filled from the
  issuer's `/.well-known/openid-configuration` on create/update), `scopes`.
- **SAML** — `idp_entity_id`, `idp_sso_url`, `idp_x509_cert` (PEM or bare
  base64).

## Sign-in flow

```
POST /v1/auth/sso/discover      { email }        -> { sso, enforced, connection_id, protocol, login_url }
GET  /v1/auth/sso/{cid}/login                     -> 307 to the IdP (state / RelayState = signed 10-min JWT)
GET  /v1/auth/sso/{cid}/callback ?code&state      -> OIDC: code exchange + id_token check
POST /v1/auth/sso/{cid}/acs      SAMLResponse     -> SAML: signed-assertion verification
```

`login` and the callbacks end with a 303 to
`${AGENTGUARD_WEB_BASE_URL}/sso/callback#access_token=…&refresh_token=…&organization_id=…`.
The web app reads the fragment (never sent to a server), persists the session,
and hard-navigates to the dashboard. Failures redirect to `/login?sso_error=…`.

### OIDC verification

`id_token` is verified against the issuer's JWKS: matching `kid`, RS/ES
signature, `aud == client_id`, `iss == issuer`, `exp`, and a required `sub`.
The subject is taken from `sub`; email/name from the `id_token` claims.

### SAML verification

`signxml.XMLVerifier` checks the enveloped signature against
`idp_x509_cert` (chain building skipped — the configured cert is the trust
anchor). Then: a signature must cover the `Assertion` (directly, or a parent
`Response`), `Conditions/@NotBefore…NotOnOrAfter` must be current, and any
`AudienceRestriction` must contain the SP entity ID. The SP entity ID / ACS URL
are derived from `AGENTGUARD_OAUTH_REDIRECT_BASE` —
`GET /v1/organizations/{id}/sso/{cid}/metadata` emits the matching SP metadata
XML for the IdP administrator.

## Just-in-time provisioning

`sso/service.provision` links the IdP subject to a stable
`external_identities` row (`provider = "sso:<connection_id>"`), creates the
`users` row on first sign-in (no password), and ensures a `memberships` row in
the connection's org with `default_role`. Every SSO login writes an
`auth.sso_login` audit event.

## Enforced SSO

When a connection is `enforced`, `auth.service.authenticate` rejects password
login for any address in its `domains` with `401 "SSO is required for this
domain"` — before password verification. Registration and existing sessions are
unaffected; this only closes the password door.

## Admin API (`org.manage`)

```
GET    /v1/organizations/{id}/sso
POST   /v1/organizations/{id}/sso
GET    /v1/organizations/{id}/sso/{cid}
PATCH  /v1/organizations/{id}/sso/{cid}
DELETE /v1/organizations/{id}/sso/{cid}
GET    /v1/organizations/{id}/sso/{cid}/metadata   (SAML SP metadata XML)
```

Secrets (`client_secret`, `sp_private_key`) are redacted to `********` in every
response; sending the redacted sentinel back in a `PATCH` keeps the stored
value. Web UI: **Administration → Single Sign-On**, plus the "Single sign-on"
button on the login screen.

## Configuration

| Env var | Default | Purpose |
|---------|---------|---------|
| `AGENTGUARD_OAUTH_REDIRECT_BASE` | `http://localhost:8010` | API base — OIDC `redirect_uri`, SAML entity ID / ACS URL |
| `AGENTGUARD_WEB_BASE_URL` | `http://localhost:3010` | where the browser lands with the session fragment |

## Deferred

SCIM provisioning (Step 11), SP-signed AuthnRequests, SAML Single Logout,
encrypted `config` at rest, IdP-initiated login replay protection
(`InResponseTo` / one-time assertion IDs).
