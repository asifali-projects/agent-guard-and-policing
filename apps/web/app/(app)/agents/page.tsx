"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useRouter } from "next/navigation";
import { useState } from "react";

import { DecisionBadge, ErrorBox, Modal, PageHeader, RiskScore, Row, Spinner, Table } from "@/components/ui";
import { api } from "@/lib/api";
import { useAuth } from "@/lib/auth";
import { timeAgo } from "@/lib/format";
import type { Agent } from "@/lib/types";

export default function AgentsPage() {
  const { can } = useAuth();
  const router = useRouter();
  const qc = useQueryClient();
  const [creating, setCreating] = useState(false);
  const [envFilter, setEnvFilter] = useState("");

  const q = useQuery({ queryKey: ["agents"], queryFn: () => api<Agent[]>("/v1/agents") });

  const create = useMutation({
    mutationFn: (body: Record<string, unknown>) => api<Agent>("/v1/agents", { method: "POST", body }),
    onSuccess: (a) => {
      qc.invalidateQueries({ queryKey: ["agents"] });
      setCreating(false);
      router.push(`/agents/${a.id}`);
    },
  });

  if (q.isLoading) return <Spinner />;
  if (q.error) return <ErrorBox error={q.error} />;
  const rows = (q.data ?? []).filter((a) => !envFilter || a.environment === envFilter);

  return (
    <>
      <PageHeader
        title="Agents"
        subtitle={`${q.data?.length ?? 0} in inventory`}
        actions={
          can("agent.manage") ? (
            <button className="btn btn-primary" onClick={() => setCreating(true)}>
              Register agent
            </button>
          ) : null
        }
      />

      <div className="mb-3 flex gap-2 text-sm">
        <select className="input max-w-[12rem]" value={envFilter} onChange={(e) => setEnvFilter(e.target.value)}>
          <option value="">All environments</option>
          <option value="development">development</option>
          <option value="staging">staging</option>
          <option value="production">production</option>
        </select>
      </div>

      {rows.length === 0 ? (
        <div className="card text-sm text-muted">No agents.</div>
      ) : (
        <Table>
          <thead>
            <tr className="bg-panel2">
              <th className="th">Agent</th>
              <th className="th">Owner</th>
              <th className="th">Framework</th>
              <th className="th">Env</th>
              <th className="th">Fail mode</th>
              <th className="th">Risk</th>
              <th className="th">Updated</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((a) => (
              <Row key={a.id} onClick={() => router.push(`/agents/${a.id}`)}>
                <td className="td font-medium">{a.name}</td>
                <td className="td text-muted">{a.owner_team ?? "—"}</td>
                <td className="td text-muted">{a.framework}</td>
                <td className="td text-muted">{a.environment}</td>
                <td className="td">
                  <DecisionBadge decision={a.fail_mode === "fail_open" ? "ALLOW" : "DENY"} />
                </td>
                <td className="td">
                  <RiskScore score={a.risk_score} />
                </td>
                <td className="td text-muted">{timeAgo(a.updated_at)}</td>
              </Row>
            ))}
          </tbody>
        </Table>
      )}

      {creating && (
        <Modal title="Register agent" onClose={() => setCreating(false)}>
          <form
            className="flex flex-col gap-3"
            onSubmit={(e) => {
              e.preventDefault();
              const f = new FormData(e.currentTarget);
              create.mutate({
                name: f.get("name"),
                framework: f.get("framework"),
                environment: f.get("environment"),
                owner_team: f.get("owner_team") || null,
                fail_mode: f.get("fail_mode"),
              });
            }}
          >
            <div>
              <label className="label">Name</label>
              <input className="input" name="name" required />
            </div>
            <div className="grid grid-cols-2 gap-3">
              <div>
                <label className="label">Framework</label>
                <select className="input" name="framework" defaultValue="custom">
                  {["openai", "langgraph", "langchain", "crewai", "semantic_kernel", "mcp", "custom"].map((x) => (
                    <option key={x}>{x}</option>
                  ))}
                </select>
              </div>
              <div>
                <label className="label">Environment</label>
                <select className="input" name="environment" defaultValue="production">
                  <option>development</option>
                  <option>staging</option>
                  <option>production</option>
                </select>
              </div>
            </div>
            <div className="grid grid-cols-2 gap-3">
              <div>
                <label className="label">Owner team</label>
                <input className="input" name="owner_team" />
              </div>
              <div>
                <label className="label">Fail mode</label>
                <select className="input" name="fail_mode" defaultValue="fail_closed">
                  <option value="fail_closed">fail closed</option>
                  <option value="fail_open">fail open</option>
                  <option value="fail_safe">fail safe</option>
                </select>
              </div>
            </div>
            {create.error && <div className="text-sm text-bad">{(create.error as Error).message}</div>}
            <button className="btn btn-primary justify-center" disabled={create.isPending}>
              Create
            </button>
          </form>
        </Modal>
      )}
    </>
  );
}
