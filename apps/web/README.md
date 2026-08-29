# apps/web

AgentGuard dashboard. Next.js 14 (App Router), React, TypeScript.

## Run locally

```powershell
# from the repo root
.\tasks.ps1 web-install
.\tasks.ps1 web-dev        # http://localhost:3010
```

Set `NEXT_PUBLIC_API_BASE_URL` (defaults to `http://localhost:8010`).

## Status

Step 0 scaffold — a single page that checks it can reach the API. The real
information architecture (PRD §8) lands in Step 7:

```
Dashboard
Security   → Agents · Tools · MCP Servers · Security Posture · Red Team · Threats · Incidents · Approvals
Governance → Policies · Identities · Data Security · Compliance
Observability → Activity · Agent Graph · Risk · Audit Logs
Developer  → Projects · CI/CD · API Keys · SDKs · Integrations
Administration → Team · SSO · Organizations · Settings · Billing
```
