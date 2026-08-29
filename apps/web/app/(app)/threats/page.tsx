"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";

import { ErrorBox, PageHeader, SeverityBadge, Spinner } from "@/components/ui";
import { api } from "@/lib/api";
import { useAuth } from "@/lib/auth";
import { timeAgo } from "@/lib/format";
import type { Severity } from "@/lib/types";

interface Threat {
  id: string;
  agent_id: string | null;
  kind: string;
  severity: Severity;
  risk_score: number | null;
  status: string;
  description: string | null;
  context: { signals?: string[] };
  detected_at: string;
  incident_id: string | null;
}

export default function ThreatsPage() {
  const { can } = useAuth();
  const qc = useQueryClient();
  const q = useQuery({ queryKey: ["threats"], queryFn: () => api<Threat[]>("/v1/threats") });

  const resolve = useMutation({
    mutationFn: (id: string) => api(`/v1/threats/${id}/resolve`, { method: "POST", body: {} }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["threats"] }),
  });

  return (
    <>
      <PageHeader title="Threats" subtitle="Behavioral & detection signals (PRD §28)" />
      {q.isLoading ? (
        <Spinner />
      ) : q.error ? (
        <ErrorBox error={q.error} />
      ) : !q.data?.length ? (
        <div className="card text-sm text-muted">No threats detected.</div>
      ) : (
        <div className="grid gap-3">
          {q.data.map((t) => (
            <div key={t.id} className="card">
              <div className="flex items-start justify-between">
                <div>
                  <div className="flex items-center gap-2 font-medium">
                    <SeverityBadge severity={t.severity} />
                    {t.kind}
                    <span className="text-xs text-muted">risk {t.risk_score ?? "—"}</span>
                  </div>
                  <div className="mt-1 text-sm text-muted">{t.description}</div>
                  {t.context.signals && (
                    <ul className="mt-1 list-disc pl-5 text-xs text-muted">
                      {t.context.signals.map((s, i) => (
                        <li key={i}>{s}</li>
                      ))}
                    </ul>
                  )}
                  <div className="mt-1 text-xs text-muted">
                    {timeAgo(t.detected_at)}
                    {t.incident_id && <span className="ml-2 text-warn">→ incident opened</span>}
                  </div>
                </div>
                {t.status === "open" && can("incident.manage") && (
                  <button className="btn" disabled={resolve.isPending} onClick={() => resolve.mutate(t.id)}>
                    Resolve
                  </button>
                )}
                {t.status !== "open" && <span className="text-xs text-muted">{t.status}</span>}
              </div>
            </div>
          ))}
        </div>
      )}
    </>
  );
}
