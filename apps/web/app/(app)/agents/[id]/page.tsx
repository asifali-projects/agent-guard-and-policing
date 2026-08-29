"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import Link from "next/link";
import { useParams } from "next/navigation";
import { useState } from "react";

import { DecisionBadge, ErrorBox, PageHeader, RiskScore, SeverityBadge, Spinner } from "@/components/ui";
import { api } from "@/lib/api";
import { useAuth } from "@/lib/auth";
import { dateTime, timeAgo } from "@/lib/format";
import type { Agent, Assessment, AuditEvent, Finding, RiskAssessment } from "@/lib/types";

const TABS = ["Overview", "Security", "Findings", "Red Team", "Graph", "Activity"] as const;
type Tab = (typeof TABS)[number];

interface GraphData {
  nodes: { id: string; type: string; label: string; meta: Record<string, unknown> }[];
  edges: { source: string; target: string; kind: string }[];
}
interface Blast {
  agent: string;
  tools: number;
  databases: number;
  apis: number;
  mcp_servers: number;
  external_destinations: string[];
  data_classifications: string[];
  potential_impact: string;
}

export default function AgentDetailPage() {
  const { id } = useParams<{ id: string }>();
  const { can } = useAuth();
  const qc = useQueryClient();
  const [tab, setTab] = useState<Tab>("Overview");

  const agent = useQuery({ queryKey: ["agent", id], queryFn: () => api<Agent>(`/v1/agents/${id}`) });

  const runAssessment = useMutation({
    mutationFn: () =>
      api<Assessment>("/v1/redteam/assessments", {
        method: "POST",
        body: { agent_id: id, profile: "standard" },
      }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["assessments", id] });
      qc.invalidateQueries({ queryKey: ["findings", id] });
      qc.invalidateQueries({ queryKey: ["agent", id] });
    },
  });

  if (agent.isLoading) return <Spinner />;
  if (agent.error) return <ErrorBox error={agent.error} />;
  const a = agent.data!;

  return (
    <>
      <PageHeader
        title={a.name}
        subtitle={`${a.identity ?? "—"} · ${a.framework} · ${a.environment}`}
        actions={
          can("redteam.run") ? (
            <button className="btn btn-primary" disabled={runAssessment.isPending} onClick={() => runAssessment.mutate()}>
              {runAssessment.isPending ? "Running…" : "Run red-team"}
            </button>
          ) : null
        }
      />

      <div className="mb-4 flex gap-1 border-b border-border text-sm">
        {TABS.map((t) => (
          <button
            key={t}
            className={`px-3 py-2 ${tab === t ? "border-b-2 border-accent text-fg" : "text-muted"}`}
            onClick={() => setTab(t)}
          >
            {t}
          </button>
        ))}
      </div>

      {tab === "Overview" && <Overview a={a} />}
      {tab === "Security" && <SecurityPosture agentId={id} />}
      {tab === "Findings" && <FindingsTab agentId={id} />}
      {tab === "Red Team" && <AssessmentsTab agentId={id} />}
      {tab === "Graph" && <GraphTab agentId={id} />}
      {tab === "Activity" && <ActivityTab agentId={id} />}
    </>
  );
}

function Overview({ a }: { a: Agent }) {
  const fields: [string, React.ReactNode][] = [
    ["Risk score", <RiskScore key="r" score={a.risk_score} />],
    ["Status", a.status],
    ["Owner team", a.owner_team ?? "—"],
    ["Model", a.model ?? "—"],
    ["Kind", a.kind],
    ["Fail mode", a.fail_mode],
    ["Tags", a.tags.join(", ") || "—"],
    ["Created", dateTime(a.created_at)],
  ];
  return (
    <div className="grid gap-3 md:grid-cols-2">
      {fields.map(([k, v]) => (
        <div key={k} className="card flex items-center justify-between">
          <span className="text-sm text-muted">{k}</span>
          <span className="text-sm">{v}</span>
        </div>
      ))}
      {a.description && <div className="card md:col-span-2 text-sm text-muted">{a.description}</div>}
    </div>
  );
}

function SecurityPosture({ agentId }: { agentId: string }) {
  const q = useQuery({
    queryKey: ["posture", agentId],
    queryFn: () =>
      api<RiskAssessment>("/v1/risk/score", {
        method: "POST",
        body: { agent_id: agentId, tool: "generic.action", parameters: {}, context: {} },
      }),
  });
  if (q.isLoading) return <Spinner />;
  if (q.error) return <ErrorBox error={q.error} />;
  const r = q.data!;
  return (
    <div>
      <div className="card mb-3 flex items-center justify-between">
        <div>
          <div className="text-xs uppercase text-muted">Composite risk (baseline action)</div>
          <div className="text-3xl font-bold">
            <RiskScore score={r.risk_score} />
          </div>
        </div>
        <div className="text-right text-sm">
          <SeverityBadge severity={r.severity} />
          <div className="mt-1 text-muted">recommends {r.decision}</div>
        </div>
      </div>
      <div className="card divide-y divide-border p-0">
        {r.factors.map((f) => (
          <div key={f.name} className="flex items-center gap-3 px-4 py-2.5">
            <span className="w-28 text-sm capitalize">{f.name}</span>
            <div className="h-2 flex-1 overflow-hidden rounded bg-panel2">
              <div className="h-full bg-accent" style={{ width: `${f.score}%` }} />
            </div>
            <span className="w-8 text-right text-sm tabular-nums">{f.score}</span>
            <span className="hidden w-64 truncate text-xs text-muted md:block">{f.detail}</span>
          </div>
        ))}
      </div>
    </div>
  );
}

function FindingsTab({ agentId }: { agentId: string }) {
  const q = useQuery({
    queryKey: ["findings", agentId],
    queryFn: () => api<Finding[]>("/v1/redteam/findings", { query: { agent_id: agentId } }),
  });
  if (q.isLoading) return <Spinner />;
  if (q.error) return <ErrorBox error={q.error} />;
  if (!q.data?.length) return <div className="card text-sm text-muted">No findings.</div>;
  return (
    <div className="card divide-y divide-border p-0">
      {q.data.map((f) => (
        <Link key={f.id} href={`/findings?id=${f.id}`} className="flex items-center justify-between px-4 py-2.5 hover:bg-panel2">
          <span className="flex items-center gap-2">
            <SeverityBadge severity={f.severity} />
            {f.title}
          </span>
          <span className="text-xs text-muted">{f.status}</span>
        </Link>
      ))}
    </div>
  );
}

function AssessmentsTab({ agentId }: { agentId: string }) {
  const q = useQuery({
    queryKey: ["assessments", agentId],
    queryFn: () => api<Assessment[]>("/v1/redteam/assessments", { query: { agent_id: agentId } }),
  });
  if (q.isLoading) return <Spinner />;
  if (q.error) return <ErrorBox error={q.error} />;
  if (!q.data?.length) return <div className="card text-sm text-muted">No assessments run.</div>;
  return (
    <div className="card divide-y divide-border p-0">
      {q.data.map((s) => (
        <div key={s.id} className="flex items-center justify-between px-4 py-2.5 text-sm">
          <span>
            {s.profile} · {timeAgo(s.created_at)}
          </span>
          <span className="text-muted">
            {s.summary.passed ?? 0}/{s.summary.total ?? 0} defended · {s.summary.findings ?? 0} findings
          </span>
        </div>
      ))}
    </div>
  );
}

function GraphTab({ agentId }: { agentId: string }) {
  const graph = useQuery({
    queryKey: ["graph", agentId],
    queryFn: () => api<GraphData>(`/v1/agents/${agentId}/graph`),
  });
  const blast = useQuery({
    queryKey: ["blast", agentId],
    queryFn: () => api<Blast>(`/v1/agents/${agentId}/blast-radius`),
  });
  if (graph.isLoading || blast.isLoading) return <Spinner />;
  if (graph.error) return <ErrorBox error={graph.error} />;
  const b = blast.data!;
  const byType = (t: string) => graph.data!.nodes.filter((n) => n.type === t);

  return (
    <div className="grid gap-4 md:grid-cols-2">
      <div className="card">
        <div className="text-xs uppercase text-muted">Blast radius (PRD §32)</div>
        <div className="mt-1 text-2xl font-bold">
          Potential impact:{" "}
          <span className={b.potential_impact === "CRITICAL" ? "text-crit" : b.potential_impact === "HIGH" ? "text-bad" : "text-warn"}>
            {b.potential_impact}
          </span>
        </div>
        <ul className="mt-2 space-y-1 text-sm text-muted">
          <li>Tools reachable: {b.tools}</li>
          <li>Databases: {b.databases} · APIs: {b.apis}</li>
          <li>MCP servers: {b.mcp_servers}</li>
          <li>External destinations: {b.external_destinations.join(", ") || "none"}</li>
          <li>Data classes handled: {b.data_classifications.join(", ") || "none"}</li>
        </ul>
      </div>
      <div className="card">
        <div className="text-xs uppercase text-muted">Reachability (PRD §31)</div>
        {(["tool", "destination", "data", "mcp"] as const).map((t) => (
          <div key={t} className="mt-2">
            <div className="text-xs font-semibold capitalize text-muted">{t}s</div>
            <div className="flex flex-wrap gap-1">
              {byType(t).length === 0 && <span className="text-xs text-muted">—</span>}
              {byType(t).map((n) => (
                <span key={n.id} className="rounded bg-panel2 px-1.5 py-0.5 text-xs">
                  {n.label}
                </span>
              ))}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}

function ActivityTab({ agentId }: { agentId: string }) {
  const q = useQuery({
    queryKey: ["activity", agentId],
    queryFn: () =>
      api<{ items: AuditEvent[] }>("/v1/audit/events", { query: { agent_id: agentId, limit: 50 } }),
  });
  if (q.isLoading) return <Spinner />;
  if (q.error) return <ErrorBox error={q.error} />;
  const items = q.data?.items ?? [];
  if (!items.length) return <div className="card text-sm text-muted">No recorded activity.</div>;
  return (
    <div className="card divide-y divide-border p-0">
      {items.map((e) => (
        <div key={e.id} className="flex items-center justify-between px-4 py-2 text-sm">
          <span className="flex items-center gap-2">
            <DecisionBadge decision={e.decision} />
            {e.action}
            {e.tool && <span className="text-muted">· {e.tool}</span>}
          </span>
          <span className="text-xs text-muted">{timeAgo(e.occurred_at)}</span>
        </div>
      ))}
    </div>
  );
}
