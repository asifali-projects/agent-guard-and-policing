"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";

import { ErrorBox, Modal, PageHeader, Row, Spinner, Table } from "@/components/ui";
import { api } from "@/lib/api";
import { useAuth } from "@/lib/auth";
import { timeAgo } from "@/lib/format";
import type { ApiKey } from "@/lib/types";

const SCOPES = [
  "runtime.evaluate",
  "agent.read",
  "agent.manage",
  "redteam.run",
  "redteam.read",
  "finding.read",
  "policy.read",
  "audit.read",
  "mcp.read",
];

export default function ApiKeysPage() {
  const { me, can } = useAuth();
  const org = me?.active_organization_id;
  const qc = useQueryClient();
  const [creating, setCreating] = useState(false);
  const [revealed, setRevealed] = useState<string | null>(null);

  const q = useQuery({
    queryKey: ["api-keys"],
    queryFn: () => api<ApiKey[]>(`/v1/organizations/${org}/api-keys`),
    enabled: !!org,
  });

  const create = useMutation({
    mutationFn: (body: Record<string, unknown>) =>
      api<{ key: string }>(`/v1/organizations/${org}/api-keys`, { method: "POST", body }),
    onSuccess: (r) => {
      qc.invalidateQueries({ queryKey: ["api-keys"] });
      setCreating(false);
      setRevealed(r.key);
    },
  });

  const revoke = useMutation({
    mutationFn: (id: string) => api(`/v1/organizations/${org}/api-keys/${id}`, { method: "DELETE" }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["api-keys"] }),
  });

  return (
    <>
      <PageHeader
        title="API Keys"
        subtitle="PRD §52"
        actions={
          can("apikey.manage") ? (
            <button className="btn btn-primary" onClick={() => setCreating(true)}>
              New key
            </button>
          ) : null
        }
      />

      {revealed && (
        <div className="card mb-4 border-accent/50">
          <div className="text-xs text-muted">Copy this key now — it is shown once.</div>
          <code className="mt-1 block break-all text-sm">{revealed}</code>
          <button className="btn mt-2" onClick={() => setRevealed(null)}>
            Done
          </button>
        </div>
      )}

      {q.isLoading ? (
        <Spinner />
      ) : q.error ? (
        <ErrorBox error={q.error} />
      ) : !q.data?.length ? (
        <div className="card text-sm text-muted">No API keys.</div>
      ) : (
        <Table>
          <thead>
            <tr className="bg-panel2">
              <th className="th">Name</th>
              <th className="th">Prefix</th>
              <th className="th">Env</th>
              <th className="th">Scopes</th>
              <th className="th">Last used</th>
              <th className="th"></th>
            </tr>
          </thead>
          <tbody>
            {q.data.map((k) => (
              <Row key={k.id}>
                <td className="td">{k.name}</td>
                <td className="td font-mono text-xs">{k.prefix}</td>
                <td className="td text-muted">{k.environment}</td>
                <td className="td text-xs text-muted">{k.scopes.join(", ")}</td>
                <td className="td text-muted">{k.last_used_at ? timeAgo(k.last_used_at) : "never"}</td>
                <td className="td text-right">
                  {k.revoked_at ? (
                    <span className="text-xs text-muted">revoked</span>
                  ) : (
                    can("apikey.manage") && (
                      <button className="btn btn-danger" onClick={() => revoke.mutate(k.id)}>
                        Revoke
                      </button>
                    )
                  )}
                </td>
              </Row>
            ))}
          </tbody>
        </Table>
      )}

      {creating && (
        <Modal title="New API key" onClose={() => setCreating(false)}>
          <form
            className="flex flex-col gap-3"
            onSubmit={(e) => {
              e.preventDefault();
              const f = new FormData(e.currentTarget);
              create.mutate({
                name: f.get("name"),
                environment: f.get("environment"),
                scopes: f.getAll("scopes"),
              });
            }}
          >
            <div>
              <label className="label">Name</label>
              <input className="input" name="name" required />
            </div>
            <div>
              <label className="label">Environment</label>
              <select className="input" name="environment" defaultValue="production">
                <option>development</option>
                <option>staging</option>
                <option>production</option>
              </select>
            </div>
            <div>
              <label className="label">Scopes (cannot exceed your own permissions)</label>
              <div className="grid grid-cols-2 gap-1 text-xs">
                {SCOPES.map((s) => (
                  <label key={s} className="flex items-center gap-1.5">
                    <input type="checkbox" name="scopes" value={s} defaultChecked={s === "runtime.evaluate"} />
                    {s}
                  </label>
                ))}
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
