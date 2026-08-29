"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";

import { ErrorBox, Modal, PageHeader, SeverityBadge, Spinner } from "@/components/ui";
import { api } from "@/lib/api";
import { useAuth } from "@/lib/auth";
import { dateTime, timeAgo } from "@/lib/format";
import type { Severity } from "@/lib/types";

interface Incident {
  id: string;
  key: string;
  title: string;
  severity: Severity;
  status: string;
  agent_id: string | null;
  summary: string | null;
  opened_at: string;
}
interface IncidentEvent {
  id: string;
  kind: string;
  actor_id: string | null;
  message: string | null;
  created_at: string;
}
interface IncidentDetail extends Incident {
  events: IncidentEvent[];
}

const NEXT: Record<string, string[]> = {
  detected: ["investigating", "contained", "closed"],
  investigating: ["contained", "resolved", "closed"],
  contained: ["resolved", "closed"],
  resolved: ["closed", "investigating"],
  closed: [],
};

export default function IncidentsPage() {
  const { can } = useAuth();
  const [openId, setOpenId] = useState<string | null>(null);
  const [statusFilter, setStatusFilter] = useState("");

  const q = useQuery({
    queryKey: ["incidents", statusFilter],
    queryFn: () => api<Incident[]>("/v1/incidents", { query: { status: statusFilter || undefined } }),
  });

  return (
    <>
      <PageHeader title="Incidents" subtitle="Incident response (PRD §30)" />
      <div className="mb-3">
        <select className="input max-w-[12rem]" value={statusFilter} onChange={(e) => setStatusFilter(e.target.value)}>
          <option value="">all statuses</option>
          {Object.keys(NEXT).map((s) => (
            <option key={s}>{s}</option>
          ))}
        </select>
      </div>

      {q.isLoading ? (
        <Spinner />
      ) : q.error ? (
        <ErrorBox error={q.error} />
      ) : !q.data?.length ? (
        <div className="card text-sm text-muted">No incidents.</div>
      ) : (
        <div className="card divide-y divide-border p-0">
          {q.data.map((i) => (
            <button
              key={i.id}
              className="flex w-full items-center justify-between px-4 py-2.5 text-left hover:bg-panel2"
              onClick={() => setOpenId(i.id)}
            >
              <span className="flex items-center gap-2">
                <SeverityBadge severity={i.severity} />
                <span className="font-mono text-xs text-muted">{i.key}</span>
                <span>{i.title}</span>
              </span>
              <span className="flex items-center gap-3 text-xs text-muted">
                <span className="rounded bg-panel2 px-1.5 py-0.5">{i.status}</span>
                {timeAgo(i.opened_at)}
              </span>
            </button>
          ))}
        </div>
      )}

      {openId && <IncidentModal id={openId} canManage={can("incident.manage")} onClose={() => setOpenId(null)} />}
    </>
  );
}

function IncidentModal({ id, canManage, onClose }: { id: string; canManage: boolean; onClose: () => void }) {
  const qc = useQueryClient();
  const [tool, setTool] = useState("");
  const q = useQuery({ queryKey: ["incident", id], queryFn: () => api<IncidentDetail>(`/v1/incidents/${id}`) });

  const invalidate = () => {
    qc.invalidateQueries({ queryKey: ["incident", id] });
    qc.invalidateQueries({ queryKey: ["incidents"] });
  };
  const transition = useMutation({
    mutationFn: (status: string) =>
      api(`/v1/incidents/${id}/transition`, { method: "POST", body: { status } }),
    onSuccess: invalidate,
  });
  const action = useMutation({
    mutationFn: (body: Record<string, unknown>) =>
      api(`/v1/incidents/${id}/actions`, { method: "POST", body }),
    onSuccess: invalidate,
  });

  if (q.isLoading) return <Modal title="Incident" onClose={onClose}><Spinner /></Modal>;
  const i = q.data!;

  return (
    <Modal title={`${i.key} — ${i.title}`} onClose={onClose} wide>
      <div className="flex items-center gap-3 text-sm">
        <SeverityBadge severity={i.severity} />
        <span className="rounded bg-panel2 px-2 py-0.5 text-xs">{i.status}</span>
        <span className="text-muted">opened {dateTime(i.opened_at)}</span>
      </div>
      {i.summary && <p className="mt-2 text-sm text-muted">{i.summary}</p>}

      {canManage && (
        <div className="mt-4 space-y-3">
          <div className="flex flex-wrap gap-2">
            {NEXT[i.status]?.map((s) => (
              <button key={s} className="btn" disabled={transition.isPending} onClick={() => transition.mutate(s)}>
                → {s}
              </button>
            ))}
          </div>
          <div className="flex flex-wrap items-center gap-2">
            <button className="btn btn-danger" disabled={action.isPending} onClick={() => action.mutate({ action: "pause_agent" })}>
              Pause agent
            </button>
            <button className="btn" disabled={action.isPending} onClick={() => action.mutate({ action: "resume_agent" })}>
              Resume agent
            </button>
            <button className="btn" disabled={action.isPending} onClick={() => action.mutate({ action: "notify_security" })}>
              Notify security
            </button>
            <input
              className="input max-w-[10rem]"
              placeholder="tool.name"
              value={tool}
              onChange={(e) => setTool(e.target.value)}
            />
            <button className="btn btn-danger" disabled={!tool || action.isPending} onClick={() => action.mutate({ action: "block_tool", tool })}>
              Block tool
            </button>
          </div>
        </div>
      )}

      <h3 className="mt-4 text-xs font-semibold uppercase text-muted">Timeline</h3>
      <div className="mt-1 space-y-1 text-sm">
        {i.events.map((e) => (
          <div key={e.id} className="flex items-start gap-2">
            <span className="text-xs text-muted">{dateTime(e.created_at)}</span>
            <span className="text-muted">·</span>
            <span>{e.message}</span>
          </div>
        ))}
      </div>
    </Modal>
  );
}
