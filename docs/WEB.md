# Web Dashboard (Step 7)

Covers PRD §8 (information architecture), §11 (dashboard), §12–14 (agents),
§22 (findings), §23 (policies), §27 (data security), §29 (approvals),
§33 (audit).

`apps/web` — Next.js 14 (App Router), TypeScript, Tailwind, TanStack Query.

## Structure

```
app/
├── layout.tsx        <Providers> = QueryClient + AuthProvider
├── login/            sign in / create account (MFA accounts use the CLI)
└── (app)/            authenticated shell — AppShell + Sidebar (PRD §8)
    ├── page.tsx           Dashboard — "Am I safe?"
    ├── agents/            inventory + [id] detail (Overview / Security posture /
    │                      Findings / Red Team / Activity tabs)
    ├── tools/  mcp/       inventory + MCP scan
    ├── red-team/          launch assessments, results
    ├── findings/          list + finding modal with the §22 actions
    ├── approvals/         approve / reject
    ├── policies/          list + create (JSON spec) + Validate
    ├── data-security/     DLP scan + data policies
    ├── audit/             event table + chain-verify badge
    ├── api-keys/          create (scoped) + reveal-once + revoke
    └── team/              members + role change
lib/
├── api.ts       fetch wrapper; transparent access-token refresh on 401
├── auth.tsx     AuthProvider — tokens in localStorage, /v1/auth/me, can(perm)
├── providers.tsx
├── types.ts     API response shapes
└── format.ts    time / severity / decision / risk helpers
components/  Sidebar, AppShell, ui.tsx (PageHeader, StatCard, Table, Modal,
             SeverityBadge, DecisionBadge, RiskScore, …)
```

RBAC is reflected in the UI: action buttons render only when
`can("<permission>")` from the current membership role.

## Supporting API changes

- `GET /v1/dashboard/summary` (PRD §11) — security score, asset counts, open
  findings by severity, 24 h runtime actions / blocks, pending approvals, top
  risky agents. `analytics.read`.
- CORS middleware — `AGENTGUARD_CORS_ORIGINS` (default `http://localhost:3010`).

## Run

```powershell
.\tasks.ps1 infra-up
.\tasks.ps1 api-dev        # :8010
.\tasks.ps1 web-dev        # :3010
```

## Verified end to end (browser)

register → dashboard → create agent → run red-team → agent security-posture
breakdown → dashboard reflects 17 findings / score 0 → open a finding →
**Create policy** (`RT-TOOL-PARAMETER_MANIPULATION`) → **Retest** → resolved.

## Deferred

Agent graph / blast radius (§31–32), AI security analyst chat (§35), org
switcher, billing screens, SSO / SCIM settings, live-updating counters,
policy binding editor UI, pagination controls.
