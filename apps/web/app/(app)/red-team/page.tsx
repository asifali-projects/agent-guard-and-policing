"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import Link from "next/link";
import { useState } from "react";

import { ErrorBox, PageHeader, Spinner } from "@/components/ui";
import { api } from "@/lib/api";
import { useAuth } from "@/lib/auth";
import { timeAgo } from "@/lib/format";
import type { Agent, Assessment } from "@/lib/types";

export default function RedTeamPage() {
  const { can } = useAuth();
  const qc = useQueryClient();
  const [agentId, setAgentId] = useState("");
  const [profile, setProfile] = useState("standard");

  const agents = useQuery({ queryKey: ["agents"], queryFn: () => api<Agent[]>("/v1/agents") });
  const list = useQuery({
    queryKey: ["assessments"],
    queryFn: () => api<Assessment[]>("/v1/redteam/assessments"),
  });

  const run = useMutation({
    mutationFn: () =>
      api<Assessment>("/v1/redteam/assessments", {
        method: "POST",
        body: { agent_id: agentId, profile },
      }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["assessments"] });
      qc.invalidateQueries({ queryKey: ["findings"] });
    },
  });

  const nameOf = (id: string) => agents.data?.find((a) => a.id === id)?.name ?? id.slice(0, 8);

  return (
    <>
      <PageHeader title="Red Team" subtitle="Continuous adversarial testing (PRD §18)" />

      {can("redteam.run") && (
        <div className="card mb-4 flex flex-wrap items-end gap-3">
          <div>
            <label className="label">Target agent</label>
            <select className="input min-w-[14rem]" value={agentId} onChange={(e) => setAgentId(e.target.value)}>
              <option value="">Select…</option>
              {agents.data?.map((a) => (
                <option key={a.id} value={a.id}>
                  {a.name} ({a.environment})
                </option>
              ))}
            </select>
          </div>
          <div>
            <label className="label">Profile</label>
            <select className="input" value={profile} onChange={(e) => setProfile(e.target.value)}>
              {["quick", "standard", "deep", "enterprise"].map((p) => (
                <option key={p}>{p}</option>
              ))}
            </select>
          </div>
          <button className="btn btn-primary" disabled={!agentId || run.isPending} onClick={() => run.mutate()}>
            {run.isPending ? "Running…" : "Run assessment"}
          </button>
          {run.error && <span className="text-sm text-bad">{(run.error as Error).message}</span>}
        </div>
      )}

      {list.isLoading ? (
        <Spinner />
      ) : list.error ? (
        <ErrorBox error={list.error} />
      ) : !list.data?.length ? (
        <div className="card text-sm text-muted">No assessments yet.</div>
      ) : (
        <div className="card divide-y divide-border p-0">
          {list.data.map((s) => {
            const sev = s.summary.by_severity ?? {};
            return (
              <div key={s.id} className="flex items-center justify-between px-4 py-3 text-sm">
                <div>
                  <Link href={`/agents/${s.agent_id}`} className="link">
                    {nameOf(s.agent_id)}
                  </Link>
                  <span className="ml-2 text-muted">
                    {s.profile} · {s.status} · {timeAgo(s.created_at)}
                  </span>
                </div>
                <div className="flex items-center gap-3 text-muted">
                  <span>
                    {s.summary.passed ?? 0}/{s.summary.total ?? 0} defended
                  </span>
                  {(sev.critical || 0) > 0 && <span className="text-crit">{sev.critical} crit</span>}
                  {(sev.high || 0) > 0 && <span className="text-bad">{sev.high} high</span>}
                </div>
              </div>
            );
          })}
        </div>
      )}
    </>
  );
}
