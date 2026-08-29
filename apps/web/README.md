# apps/web

AgentGuard dashboard. Next.js 14 (App Router), TypeScript, Tailwind,
TanStack Query.

## Run locally

```powershell
# from the repo root — the API must be running (tasks.ps1 api-dev)
.\tasks.ps1 web-install
.\tasks.ps1 web-dev        # http://localhost:3010
```

Set `NEXT_PUBLIC_API_BASE_URL` (defaults to `http://localhost:8010`).

## Layout

```
app/
├── layout.tsx           root — <Providers> (React Query + Auth)
├── login/page.tsx       sign in / create account
└── (app)/               authenticated shell (sidebar per PRD §8)
    ├── page.tsx              Dashboard — "Am I safe?" (§11)
    ├── agents/               inventory (§12) + [id] detail tabs (§13–14)
    ├── tools/  mcp/          inventory (§16–17)
    ├── red-team/             assessments (§18)
    ├── findings/             findings + §22 actions
    ├── approvals/            human approval center (§29)
    ├── policies/             policy list + create + validate (§23)
    ├── data-security/        DLP scan + data policies (§27)
    ├── audit/                audit log + chain verify (§33)
    ├── api-keys/  team/      developer + administration
components/  Sidebar, AppShell, ui.tsx (primitives)
lib/         api.ts (fetch + token refresh), auth.tsx, providers.tsx, types.ts, format.ts
```

Auth: JWT access + refresh tokens in `localStorage`; `lib/api.ts` transparently
refreshes on 401. MFA-enabled accounts sign in via the CLI.

## Status

Step 7 scaffold covers the core PRD screens. Deferred: agent graph / blast
radius (§31–32), AI security analyst chat (§35), org switching UI, billing,
SSO/SCIM settings.
