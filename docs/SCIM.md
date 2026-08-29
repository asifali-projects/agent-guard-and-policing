# SCIM 2.0 Provisioning (Step 11)

Covers PRD §51 — automated user lifecycle driven by the customer's IdP
(Okta, Microsoft Entra ID, OneLogin, …). Implements the slice of RFC 7643 /
7644 that those IdPs actually exercise.

## Model

`scim_configs` (one per org) · `scim_users` · `scim_groups` ·
`scim_group_members` — migration `fad64b1fdf15`.

| Table | Holds |
|-------|-------|
| `scim_configs` | `enabled`, `token_hash` (sha-256 of the bearer token — plaintext shown once), `default_role`, `last_request_at` |
| `scim_users` | link to the local `users` row, `external_id`, `user_name`, `active`, last payload (`raw`) |
| `scim_groups` | `display_name`, `external_id`, `mapped_role` (see below) |
| `scim_group_members` | group ↔ scim_user association |

The SCIM resources are the IdP's *view*. The actual access grant is still an
ordinary `memberships` row, which `scim.service.sync_membership` creates,
re-roles, or deletes as the IdP activates / deactivates / regroups the user.
An `owner` membership is never touched by SCIM.

## Endpoints — `/scim/v2` (RFC 7644)

```
GET    /ServiceProviderConfig  /ResourceTypes  /Schemas
GET    /Users     ?filter=userName eq "x" | externalId eq "x"   &startIndex &count
POST   /Users            (201 + Location)
GET    /Users/{id}
PUT    /Users/{id}
PATCH  /Users/{id}       (PatchOp — path-based and path-less operations)
DELETE /Users/{id}       (204)
GET/POST/GET/PUT/PATCH/DELETE  /Groups[/{id}]
```

- **Auth** — `Authorization: Bearer <scim token>`; every route resolves it to a
  `ScimConfig` (constant lookup by token hash, `enabled` only). No user JWT or
  API key.
- **Errors** — RFC 7644 error schema
  (`urn:ietf:params:scim:api:messages:2.0:Error` with `status` / `scimType` /
  `detail`), emitted by the app-level `ScimError` handler.
- **Filtering** — `eq` on `userName` / `externalId` (Users) and
  `displayName` / `externalId` (Groups). That is all IdP reconciliation needs;
  anything else is `400 invalidFilter`.
- **Deactivation** — `active:false` (via `PUT` or `PATCH`) deletes the
  membership and revokes the user's sessions in that org; `active:true`
  re-provisions. `DELETE` removes the SCIM resource entirely (the underlying
  `users` row survives — it may belong to other orgs).

## Group → role mapping

A group whose `displayName` resolves to a built-in role becomes role-mapped.
Accepted spellings (case-insensitive), e.g. for `security_admin`:

```
security_admin   security-admin   "Security Admin"
agentguard:security_admin   "AgentGuard Security Admin"
```

A user's effective role = the **most privileged** role among their mapped
groups, else `scim_configs.default_role`. SCIM never assigns `owner`
(a group that maps to it is treated as `admin`). Role recomputation runs
whenever a user's `active` flag or group set changes.

## Admin API — `/v1/organizations/{id}/scim` (`org.manage`)

```
GET    /v1/organizations/{id}/scim              status + counts + base URL
PUT    /v1/organizations/{id}/scim              { enabled, default_role }
POST   /v1/organizations/{id}/scim/rotate-token → { token, scim_base_url }  (once)
DELETE /v1/organizations/{id}/scim/token        revoke + disable
```

Web UI: the SCIM panel on **Administration → SSO & SCIM** (base URL, token
rotation, default role, live user/group counts, last-request time).

## Deferred

`PATCH` filter expressions inside `path` (`members[value eq "x"]` is handled;
richer paths are not), ETag concurrency, `/Bulk`, sorting, `$ref` resolution,
encrypted `raw` payload storage.
