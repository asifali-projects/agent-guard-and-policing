# ADR 0002 — Multi-region data residency by isolated deployments

- **Status:** accepted
- **Date:** 2026-08-29
- **Context step:** 14

## Context

PRD §76 requires data residency across US / EU / Middle East / APAC: "Each
region: Control Plane + Data Plane + Event Store. Customer chooses data
residency." §86 lists it as an Enterprise-tier capability.

Options considered:

1. **One global database, `region` column, row-level filtering.** Simple to
   build, but the data physically lives in one place — it does not satisfy
   residency/sovereignty requirements (GDPR, data-localisation laws). Rejected.
2. **One control plane, per-region data planes.** The API is global but reads
   each org's data from a region-specific database. Adds a routing layer,
   connection fan-out, and a global component that still touches every region's
   metadata. Complex; the "global" tier is a compliance grey area.
3. **Fully isolated per-region deployments.** Each region is a complete,
   independent AgentGuard stack. An org lives entirely in one region.

## Decision

**Option 3.** One deployment serves exactly one region (`AGENTGUARD_REGION`).
The application never crosses regions:

- `Organization.region` is set at creation to the deployment's region and is
  immutable.
- `regions.assert_servable()` returns `421 Misdirected Request` (with the
  correct regional URL in headers) for any org not homed here — enforced in
  `get_principal` and at org creation.
- `GET /v1/regions` is a public discovery endpoint so clients route themselves.
- The customer chooses residency by signing up at the region's URL; the
  dashboard's region picker redirects the browser accordingly.

## Consequences

- **Strong isolation** — a region's Postgres/Redis/ClickHouse/Redpanda/MinIO and
  its `AGENTGUARD_SECRET_KEY` are entirely separate. A breach or outage in one
  region cannot reach another.
- **No global component** to reason about for compliance.
- **Trade-off: no global identity.** The same email in two regions is two
  separate accounts. A global directory (linked accounts, cross-region SSO) is
  explicitly deferred; if required later it is an additive service, not a
  redesign.
- **Trade-off: org migration between regions** is an offline data-export/import,
  not a runtime feature.
- Operationally, "add a region" = stand up the stack + run migrations/seed +
  extend the `AGENTGUARD_REGIONS` map + DNS. No application change.
