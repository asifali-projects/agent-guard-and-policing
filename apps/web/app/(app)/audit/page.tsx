"use client";

import { useQuery } from "@tanstack/react-query";
import { useState } from "react";

import { DecisionBadge, ErrorBox, PageHeader, Row, Spinner, Table } from "@/components/ui";
import { api, API_BASE, tokens } from "@/lib/api";
import { dateTime } from "@/lib/format";
import type { AuditEvent } from "@/lib/types";

async function downloadCsv() {
  const res = await fetch(`${API_BASE}/v1/audit/events.csv`, {
    headers: { Authorization: `Bearer ${tokens.access}` },
  });
  const blob = await res.blob();
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = "agentguard-audit.csv";
  a.click();
  URL.revokeObjectURL(url);
}

export default function AuditPage() {
  const [decision, setDecision] = useState("");

  const events = useQuery({
    queryKey: ["audit", decision],
    queryFn: () =>
      api<{ items: AuditEvent[] }>("/v1/audit/events", {
        query: { limit: 100, decision: decision || undefined },
      }),
  });
  const chain = useQuery({
    queryKey: ["audit-verify"],
    queryFn: () => api<{ intact: boolean; event_count: number }>("/v1/audit/verify"),
  });

  return (
    <>
      <PageHeader
        title="Audit Log"
        subtitle="Append-only, tamper-evident (PRD §33)"
        actions={
          <div className="flex items-center gap-2">
            {chain.data && (
              <span
                className={`rounded px-2 py-1 text-xs ${
                  chain.data.intact ? "bg-ok/15 text-ok" : "bg-bad/15 text-bad"
                }`}
              >
                chain {chain.data.intact ? "intact" : "BROKEN"} · {chain.data.event_count} events
              </span>
            )}
            <button className="btn" onClick={downloadCsv}>
              Export CSV
            </button>
          </div>
        }
      />
      <div className="mb-3">
        <select className="input max-w-[12rem]" value={decision} onChange={(e) => setDecision(e.target.value)}>
          <option value="">all decisions</option>
          {["allow", "deny", "approval", "redact", "rate_limit"].map((d) => (
            <option key={d}>{d}</option>
          ))}
        </select>
      </div>

      {events.isLoading ? (
        <Spinner />
      ) : events.error ? (
        <ErrorBox error={events.error} />
      ) : (
        <Table>
          <thead>
            <tr className="bg-panel2">
              <th className="th">Time</th>
              <th className="th">Action</th>
              <th className="th">Actor</th>
              <th className="th">Tool</th>
              <th className="th">Decision</th>
              <th className="th">Risk</th>
              <th className="th">Policy</th>
            </tr>
          </thead>
          <tbody>
            {(events.data?.items ?? []).map((e) => (
              <Row key={e.id}>
                <td className="td text-muted">{dateTime(e.occurred_at)}</td>
                <td className="td">{e.action}</td>
                <td className="td text-muted">{e.actor_id ?? e.actor_type}</td>
                <td className="td text-muted">{e.tool ?? "—"}</td>
                <td className="td">
                  <DecisionBadge decision={e.decision} />
                </td>
                <td className="td tabular-nums">{e.risk_score ?? "—"}</td>
                <td className="td font-mono text-xs text-muted">{e.policy_key ?? "—"}</td>
              </Row>
            ))}
          </tbody>
        </Table>
      )}
    </>
  );
}
