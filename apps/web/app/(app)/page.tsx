"use client";

import { useQuery } from "@tanstack/react-query";
import Link from "next/link";

import { PageHeader, RiskScore, StatCard, Spinner, ErrorBox } from "@/components/ui";
import { api } from "@/lib/api";
import { num } from "@/lib/format";
import type { DashboardSummary } from "@/lib/types";

export default function DashboardPage() {
  const q = useQuery({
    queryKey: ["dashboard"],
    queryFn: () => api<DashboardSummary>("/v1/dashboard/summary"),
  });

  if (q.isLoading) return <Spinner />;
  if (q.error) return <ErrorBox error={q.error} />;
  const d = q.data!;
  const score = d.security_score;
  const scoreTone = score >= 80 ? "ok" : score >= 50 ? "warn" : "bad";

  return (
    <>
      <PageHeader title="Am I safe?" subtitle="Organization security posture" />

      <div className="grid gap-4 md:grid-cols-4">
        <div className="card md:row-span-2 flex flex-col items-center justify-center">
          <div className="text-xs uppercase tracking-wide text-muted">Security score</div>
          <div
            className={`mt-2 text-6xl font-black tabular-nums ${
              scoreTone === "ok" ? "text-ok" : scoreTone === "warn" ? "text-warn" : "text-bad"
            }`}
          >
            {score}
          </div>
          <div className="text-sm text-muted">/ 100</div>
        </div>
        <StatCard label="Agents" value={num(d.assets.agents)} />
        <StatCard label="MCP servers" value={num(d.assets.mcp_servers)} />
        <StatCard label="Tools" value={num(d.assets.tools)} />
        <StatCard label="Critical threats" value={num(d.threats.critical)} tone="bad" />
        <StatCard label="High threats" value={num(d.threats.high)} tone="warn" />
        <StatCard label="Medium threats" value={num(d.threats.medium)} />
      </div>

      <div className="mt-4 grid gap-4 md:grid-cols-3">
        <StatCard label="Runtime actions (24h)" value={num(d.runtime.actions_24h)} />
        <StatCard label="Blocked (24h)" value={num(d.runtime.blocked_24h)} tone="bad" />
        <StatCard
          label="Approvals pending"
          value={num(d.runtime.approvals_pending)}
          tone={d.runtime.approvals_pending ? "warn" : undefined}
        />
      </div>

      <div className="mt-6">
        <h2 className="mb-2 text-sm font-semibold text-muted">Top risky agents</h2>
        {d.top_risky_agents.length === 0 ? (
          <div className="card text-sm text-muted">No agents connected yet.</div>
        ) : (
          <div className="card divide-y divide-border p-0">
            {d.top_risky_agents.map((a) => (
              <Link
                key={a.id}
                href={`/agents/${a.id}`}
                className="flex items-center justify-between px-4 py-2.5 hover:bg-panel2"
              >
                <span>{a.name}</span>
                <span className="flex items-center gap-4 text-sm text-muted">
                  <span>{a.open_findings} findings</span>
                  <RiskScore score={a.risk_score} />
                </span>
              </Link>
            ))}
          </div>
        )}
      </div>
    </>
  );
}
