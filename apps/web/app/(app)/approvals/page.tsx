"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";

import { ErrorBox, PageHeader, SeverityBadge, Spinner } from "@/components/ui";
import { api } from "@/lib/api";
import { useAuth } from "@/lib/auth";
import { dateTime } from "@/lib/format";
import type { Approval } from "@/lib/types";

export default function ApprovalsPage() {
  const { can } = useAuth();
  const qc = useQueryClient();
  const [status, setStatus] = useState("pending");

  const q = useQuery({
    queryKey: ["approvals", status],
    queryFn: () => api<Approval[]>("/v1/approvals", { query: { status: status || undefined } }),
  });

  const decide = useMutation({
    mutationFn: ({ id, action }: { id: string; action: "approve" | "reject" }) =>
      api(`/v1/approvals/${id}/${action}`, { method: "POST", body: {} }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["approvals"] }),
  });

  return (
    <>
      <PageHeader title="Approvals" subtitle="Human approval center (PRD §29)" />
      <div className="mb-3">
        <select className="input max-w-[12rem]" value={status} onChange={(e) => setStatus(e.target.value)}>
          {["pending", "approved", "rejected", "expired", ""].map((s) => (
            <option key={s} value={s}>
              {s || "all"}
            </option>
          ))}
        </select>
      </div>

      {q.isLoading ? (
        <Spinner />
      ) : q.error ? (
        <ErrorBox error={q.error} />
      ) : !q.data?.length ? (
        <div className="card text-sm text-muted">Nothing here.</div>
      ) : (
        <div className="grid gap-3">
          {q.data.map((a) => (
            <div key={a.id} className="card">
              <div className="flex items-start justify-between">
                <div>
                  <div className="flex items-center gap-2 font-medium">
                    <SeverityBadge severity={a.severity} />
                    {a.action}
                  </div>
                  <div className="mt-1 text-xs text-muted">
                    {a.reason ?? "—"} · risk {a.risk_score ?? "—"} · requested {dateTime(a.requested_at)}
                  </div>
                </div>
                {a.status === "pending" && can("approval.decide") && (
                  <div className="flex gap-2">
                    <button
                      className="btn btn-primary"
                      disabled={decide.isPending}
                      onClick={() => decide.mutate({ id: a.id, action: "approve" })}
                    >
                      Approve
                    </button>
                    <button
                      className="btn btn-danger"
                      disabled={decide.isPending}
                      onClick={() => decide.mutate({ id: a.id, action: "reject" })}
                    >
                      Reject
                    </button>
                  </div>
                )}
                {a.status !== "pending" && (
                  <span className="rounded bg-panel2 px-2 py-1 text-xs">{a.status}</span>
                )}
              </div>
              <pre className="mt-3 overflow-x-auto rounded-lg bg-panel2 p-2 text-xs text-muted">
                {JSON.stringify(a.parameters, null, 2)}
              </pre>
            </div>
          ))}
        </div>
      )}
    </>
  );
}
