# Authentication, Tenancy & RBAC (Step 2)

Covers PRD §9 (login), §49 (tenant isolation), §50 (roles), §51 (auth methods,
sessions), §52 (API keys).

## Principals

Every request resolves to a **Principal** carrying an `organization_id` and a
`permissions` set. Two kinds:

| Kind | Credential | How permissions are derived |
|------|-----------|-----------------------------|
| `user` | `Authorization: Bearer <JWT access token>` | membership role in the token's org → built-in role grant |
| `api_key` | `Authorization: Bearer ag_…` or `X-API-Key: ag_…` | the key's `scopes` (defaults to `runtime.evaluate`) |

`require_permission("agent.read", …)` is the FastAPI dependency that gates an
endpoint. It also rejects a request whose token is MFA-pending or has no active
organization.

## Sessions (PRD §51)

- **Access token** — JWT, HS256, 15 min, stateless. Claims: `sub`, `sid` (session
  id), `org`, `mfa`.
- **Refresh token** — opaque 32-byte random string; only its SHA-256 is stored in
  `sessions`. 30 days.
- **Rotation** — every `/v1/auth/refresh` revokes the presented token and issues a
  new one, chained via `previous_session_id`.
- **Reuse detection** — presenting an already-rotated refresh token revokes the
  entire session family (and is committed even though the request 401s).
- **Device tracking** — `user_agent` + `ip_address` recorded per session;
  `GET /v1/auth/sessions` lists them, `DELETE …/{id}` revokes one, `logout` with
  `all_sessions` revokes all.

## MFA (TOTP)

`enroll` → `activate` (with a code) turns it on. Afterwards `login` returns
`{"mfa_required": true, "mfa_token": …}` instead of tokens; `POST /v1/auth/mfa/verify`
exchanges `mfa_token` + code for a real session. The TOTP secret lives on
`users.mfa_secret` and **must be encrypted at rest in production** (PRD §75).

## OAuth (PRD §9)

Google and Microsoft, enabled per-provider when the client id + secret are
configured. `GET /v1/auth/oauth/{provider}/authorize` → provider →
`…/callback` links an `external_identities` row and issues a session. State is a
signed 10-minute JWT (no server-side state).

## Tenancy (PRD §49)

Every tenant-scoped row has `organization_id`. A user's token is scoped to **one**
organization; `POST /v1/auth/organizations/{id}/switch` mints a token for another
org they belong to. Endpoints double-check `principal.organization_id` against the
path `organization_id` and 403 on mismatch.

## Roles & permissions (PRD §50)

Built-in roles and their grants live in
`apps/api/agentguard_api/rbac/catalog.py` (the source of truth);
`python -m agentguard_api.rbac.seed` mirrors them into the `permissions` /
`roles` / `role_permissions` tables so custom roles can reuse the vocabulary.

| Role | Summary |
|------|---------|
| `owner` | everything |
| `admin` | everything except `org.billing` |
| `security_admin` | policies, findings, incidents, threats, approvals, data security, agents/tools/MCP manage |
| `security_analyst` | read-only + analytics + audit |
| `developer` | agents, tools, MCP, red-team runs, own API keys, integrations, `runtime.evaluate` |
| `auditor` | read-only + audit + analytics |
| `billing_admin` | `org.read`, `org.billing` only |

Full permission list (31 codes): see `catalog.PERMISSIONS`.

### API keys (PRD §52)

`ag_<env>_<publicid>_<secret>` — `env` ∈ `dev|stg|live`. Only the Argon2 hash of
`<secret>` is stored; the full key is shown once. A key's `scopes` cannot exceed
the permissions of the user who created it. Supports expiry, IP allowlist,
`last_used_at`, `usage_count`, and revoke.

## Audit (PRD §33)

`agentguard_api.audit_log.record()` appends a hash-chained `audit_events` row
(per-org `pg_advisory_xact_lock` serialises writers). `verify_chain()` recomputes
and validates a chain. Login, registration, org/member changes and API-key
lifecycle are recorded.

## Endpoints

```
POST   /v1/auth/register
POST   /v1/auth/login                     -> tokens | mfa challenge
POST   /v1/auth/refresh
POST   /v1/auth/logout
GET    /v1/auth/me
GET    /v1/auth/sessions
DELETE /v1/auth/sessions/{id}
POST   /v1/auth/mfa/{enroll,activate,verify,disable}
POST   /v1/auth/organizations/{id}/switch
GET    /v1/auth/oauth/providers
GET    /v1/auth/oauth/{provider}/{authorize,callback}

GET    /v1/organizations
POST   /v1/organizations
GET    /v1/organizations/{id}
PATCH  /v1/organizations/{id}
GET    /v1/organizations/{id}/members
POST   /v1/organizations/{id}/members
PATCH  /v1/organizations/{id}/members/{user_id}
DELETE /v1/organizations/{id}/members/{user_id}

GET    /v1/organizations/{id}/api-keys
POST   /v1/organizations/{id}/api-keys
DELETE /v1/organizations/{id}/api-keys/{key_id}
```

## Deferred to later steps

Real invitation emails (Step 9 notifications), SAML/OIDC enterprise SSO (Step 10),
SCIM provisioning (Step 11), MFA recovery codes, per-key rotation endpoint,
encrypted MFA secret storage.
