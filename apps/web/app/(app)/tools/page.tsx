"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";

import { ErrorBox, Modal, PageHeader, Row, SeverityBadge, Spinner, Table } from "@/components/ui";
import { api } from "@/lib/api";
import { useAuth } from "@/lib/auth";
import type { Tool } from "@/lib/types";

export default function ToolsPage() {
  const { can } = useAuth();
  const qc = useQueryClient();
  const [creating, setCreating] = useState(false);

  const q = useQuery({ queryKey: ["tools"], queryFn: () => api<Tool[]>("/v1/tools") });

  const create = useMutation({
    mutationFn: (body: Record<string, unknown>) => api("/v1/tools", { method: "POST", body }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["tools"] });
      setCreating(false);
    },
  });

  return (
    <>
      <PageHeader
        title="Tools"
        subtitle="Tool inventory (PRD §16)"
        actions={
          can("tool.manage") ? (
            <button className="btn btn-primary" onClick={() => setCreating(true)}>
              Add tool
            </button>
          ) : null
        }
      />
      {q.isLoading ? (
        <Spinner />
      ) : q.error ? (
        <ErrorBox error={q.error} />
      ) : !q.data?.length ? (
        <div className="card text-sm text-muted">No tools inventoried.</div>
      ) : (
        <Table>
          <thead>
            <tr className="bg-panel2">
              <th className="th">Tool</th>
              <th className="th">Permissions</th>
              <th className="th">Destination</th>
              <th className="th">Owner</th>
              <th className="th">Risk</th>
            </tr>
          </thead>
          <tbody>
            {q.data.map((t) => (
              <Row key={t.id}>
                <td className="td font-mono text-xs">{t.name}</td>
                <td className="td text-muted">{t.permissions.join(", ") || "—"}</td>
                <td className="td text-muted">{t.destination ?? "—"}</td>
                <td className="td text-muted">{t.owner_team ?? "—"}</td>
                <td className="td">
                  <SeverityBadge severity={t.risk} />
                </td>
              </Row>
            ))}
          </tbody>
        </Table>
      )}

      {creating && (
        <Modal title="Add tool" onClose={() => setCreating(false)}>
          <form
            className="flex flex-col gap-3"
            onSubmit={(e) => {
              e.preventDefault();
              const f = new FormData(e.currentTarget);
              create.mutate({
                name: f.get("name"),
                risk: f.get("risk"),
                destination: f.get("destination") || null,
                permissions: String(f.get("permissions") || "")
                  .split(",")
                  .map((s) => s.trim())
                  .filter(Boolean),
              });
            }}
          >
            <div>
              <label className="label">Name</label>
              <input className="input font-mono" name="name" required placeholder="payment.create" />
            </div>
            <div className="grid grid-cols-2 gap-3">
              <div>
                <label className="label">Risk</label>
                <select className="input" name="risk" defaultValue="low">
                  {["info", "low", "medium", "high", "critical"].map((x) => (
                    <option key={x}>{x}</option>
                  ))}
                </select>
              </div>
              <div>
                <label className="label">Destination</label>
                <input className="input" name="destination" placeholder="external" />
              </div>
            </div>
            <div>
              <label className="label">Permissions (comma-separated)</label>
              <input className="input" name="permissions" placeholder="read, write" />
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
