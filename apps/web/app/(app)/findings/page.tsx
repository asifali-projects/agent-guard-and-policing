"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useSearchParams } from "next/navigation";
import { Suspense, useState } from "react";

import { ErrorBox, Modal, PageHeader, SeverityBadge, Spinner } from "@/components/ui";
import { api } from "@/lib/api";
import { useAuth } from "@/lib/auth";
import { dateTime } from "@/lib/format";
import type { Finding } from "@/lib/types";

const STATUSES = ["", "open", "triaged", "retest", "suppressed", "false_positive", "resolved"];

function FindingsInner() {
  const { can } = useAuth();
  const params = useSearchParams();
  const [statusFilter, setStatusFilter] = useState("open");
  const [openId, setOpenId] = useState<string | null>(params.get("id"));

  const q = useQuery({
    queryKey: ["findings", "list", statusFilter],
    queryFn: () =>
      api<Finding[]>("/v1/redteam/findings", { query: { status: statusFilter || undefined } }),
  });

  return (
    <>
      <PageHeader title="Findings" subtitle="Red-team findings & remediation (PRD §22)" />
      <div className="mb-3">
        <select className="input max-w-[14rem]" value={statusFilter} onChange={(e) => setStatusFilter(e.target.value)}>
          {STATUSES.map((s) => (
            <option key={s} value={s}>
              {s || "all statuses"}
            </option>
          ))}
        </select>
      </div>

      {q.isLoading ? (
        <Spinner />
      ) : q.error ? (
        <ErrorBox error={q.error} />
      ) : !q.data?.length ? (
        <div className="card text-sm text-muted">No findings.</div>
      ) : (
        <div className="card divide-y divide-border p-0">
          {q.data.map((f) => (
            <button
              key={f.id}
              className="flex w-full items-center justify-between px-4 py-2.5 text-left hover:bg-panel2"
              onClick={() => setOpenId(f.id)}
            >
              <span className="flex items-center gap-2">
                <SeverityBadge severity={f.severity} />
                <span>{f.title}</span>
                <span className="text-xs text-muted">· {f.category}</span>
              </span>
              <span className="text-xs text-muted">{f.status}</span>
            </button>
          ))}
        </div>
      )}

      {openId && <FindingModal id={openId} canManage={can("finding.manage")} onClose={() => setOpenId(null)} />}
    </>
  );
}

function FindingModal({ id, canManage, onClose }: { id: string; canManage: boolean; onClose: () => void }) {
  const qc = useQueryClient();
  const [msg, setMsg] = useState<string | null>(null);
  const q = useQuery({ queryKey: ["finding", id], queryFn: () => api<Finding>(`/v1/redteam/findings/${id}`) });

  const act = useMutation({
    mutationFn: ({ path, body }: { path: string; body?: unknown }) =>
      api(`/v1/redteam/findings/${id}/${path}`, { method: "POST", body }),
    onSuccess: (res: unknown, vars) => {
      qc.invalidateQueries({ queryKey: ["finding", id] });
      qc.invalidateQueries({ queryKey: ["findings"] });
      if (vars.path === "policy") setMsg(`Created policy ${(res as { key: string }).key}`);
      else if (vars.path === "incident") setMsg(`Opened ${(res as { key: string }).key}`);
      else if (vars.path === "retest") setMsg(`Retest: ${(res as { status: string }).status}`);
      else setMsg("done");
    },
    onError: (e) => setMsg((e as Error).message),
  });

  if (q.isLoading) return <Modal title="Finding" onClose={onClose}><Spinner /></Modal>;
  const f = q.data!;

  return (
    <Modal title={f.title} onClose={onClose} wide>
      <div className="flex flex-wrap items-center gap-3 text-sm">
        <SeverityBadge severity={f.severity} />
        <span className="text-muted">{f.category}</span>
        <span className="rounded bg-panel2 px-1.5 py-0.5 text-xs">{f.status}</span>
        {f.risk_score != null && <span className="text-muted">risk {f.risk_score}</span>}
      </div>
      {f.recommendation && (
        <p className="mt-3 rounded-lg border border-border bg-panel2 p-3 text-sm">{f.recommendation}</p>
      )}
      {f.resolution_note && <p className="mt-2 text-xs text-muted">Note: {f.resolution_note}</p>}
      <p className="mt-2 text-xs text-muted">Opened {dateTime(f.created_at)}</p>

      {canManage && (
        <div className="mt-4 flex flex-wrap gap-2">
          <button className="btn btn-primary" disabled={act.isPending} onClick={() => act.mutate({ path: "policy" })}>
            Create policy
          </button>
          <button className="btn" disabled={act.isPending} onClick={() => act.mutate({ path: "retest" })}>
            Retest
          </button>
          <button className="btn" disabled={act.isPending} onClick={() => act.mutate({ path: "incident" })}>
            Create incident
          </button>
          <button
            className="btn"
            disabled={act.isPending}
            onClick={() => act.mutate({ path: "suppress", body: { reason: "reviewed — accepted risk" } })}
          >
            Suppress
          </button>
          <button className="btn btn-danger" disabled={act.isPending} onClick={() => act.mutate({ path: "false-positive" })}>
            False positive
          </button>
        </div>
      )}
      {msg && <p className="mt-3 text-sm text-accent">{msg}</p>}
    </Modal>
  );
}

export default function FindingsPage() {
  return (
    <Suspense fallback={<Spinner />}>
      <FindingsInner />
    </Suspense>
  );
}
