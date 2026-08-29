"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";

import { ErrorBox, PageHeader, Row, Spinner, Table } from "@/components/ui";
import { api } from "@/lib/api";
import { useAuth } from "@/lib/auth";
import { timeAgo } from "@/lib/format";

interface Integration {
  id: string;
  provider: string;
  category: string;
  enabled: boolean;
  status: string;
}
interface Webhook {
  id: string;
  url: string;
  events: string[];
  enabled: boolean;
  last_delivery_at: string | null;
  failure_count: number;
}

const EVENTS = [
  "agent.action.blocked",
  "agent.action.approval_required",
  "threat.detected",
  "incident.created",
  "incident.updated",
  "redteam.completed",
  "agent.registered",
];

export default function IntegrationsPage() {
  const { can } = useAuth();
  const qc = useQueryClient();
  const manage = can("integration.manage");

  const catalog = useQuery({
    queryKey: ["catalog"],
    queryFn: () => api<Record<string, string[]>>("/v1/integrations/catalog"),
  });
  const integrations = useQuery({
    queryKey: ["integrations"],
    queryFn: () => api<Integration[]>("/v1/integrations"),
  });
  const webhooks = useQuery({ queryKey: ["webhooks"], queryFn: () => api<Webhook[]>("/v1/webhooks") });

  const addInteg = useMutation({
    mutationFn: (body: Record<string, unknown>) =>
      api("/v1/integrations", { method: "POST", body }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["integrations"] }),
  });
  const delInteg = useMutation({
    mutationFn: (id: string) => api(`/v1/integrations/${id}`, { method: "DELETE" }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["integrations"] }),
  });
  const addHook = useMutation({
    mutationFn: (body: Record<string, unknown>) => api("/v1/webhooks", { method: "POST", body }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["webhooks"] }),
  });
  const testHook = useMutation({
    mutationFn: (id: string) => api(`/v1/webhooks/${id}/test`, { method: "POST", body: {} }),
  });
  const delHook = useMutation({
    mutationFn: (id: string) => api(`/v1/webhooks/${id}`, { method: "DELETE" }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["webhooks"] }),
  });

  const [checked, setChecked] = useState<Set<string>>(new Set(["threat.detected", "incident.created"]));

  return (
    <>
      <PageHeader title="Integrations" subtitle="Notifications, SIEM, DevOps (PRD §62)" />

      <h2 className="mb-2 text-sm font-semibold text-muted">Connected integrations</h2>
      {integrations.isLoading ? (
        <Spinner />
      ) : integrations.error ? (
        <ErrorBox error={integrations.error} />
      ) : (
        <Table>
          <thead>
            <tr className="bg-panel2">
              <th className="th">Provider</th>
              <th className="th">Category</th>
              <th className="th">Status</th>
              <th className="th"></th>
            </tr>
          </thead>
          <tbody>
            {(integrations.data ?? []).length === 0 && (
              <Row>
                <td className="td text-muted" colSpan={4}>
                  None connected.
                </td>
              </Row>
            )}
            {(integrations.data ?? []).map((i) => (
              <Row key={i.id}>
                <td className="td capitalize">{i.provider.replace(/_/g, " ")}</td>
                <td className="td text-muted">{i.category}</td>
                <td className="td text-muted">{i.status}</td>
                <td className="td text-right">
                  {manage && (
                    <button className="btn btn-danger" onClick={() => delInteg.mutate(i.id)}>
                      Disconnect
                    </button>
                  )}
                </td>
              </Row>
            ))}
          </tbody>
        </Table>
      )}

      {manage && catalog.data && (
        <form
          className="card mt-3 flex flex-wrap items-end gap-3"
          onSubmit={(e) => {
            e.preventDefault();
            const f = new FormData(e.currentTarget);
            const provider = String(f.get("provider"));
            const cfgKey =
              provider === "slack" || provider === "teams"
                ? "webhook_url"
                : provider === "pagerduty"
                  ? "routing_key"
                  : "url";
            addInteg.mutate({ provider, config: { [cfgKey]: f.get("value") } });
            e.currentTarget.reset();
          }}
        >
          <div>
            <label className="label">Provider</label>
            <select className="input" name="provider">
              {Object.values(catalog.data)
                .flat()
                .map((p) => (
                  <option key={p}>{p}</option>
                ))}
            </select>
          </div>
          <div className="flex-1">
            <label className="label">Webhook URL / routing key</label>
            <input className="input" name="value" required />
          </div>
          <button className="btn btn-primary" disabled={addInteg.isPending}>
            Connect
          </button>
          {addInteg.error && <span className="text-sm text-bad">{(addInteg.error as Error).message}</span>}
        </form>
      )}

      <h2 className="mb-2 mt-6 text-sm font-semibold text-muted">Webhooks</h2>
      {webhooks.isLoading ? (
        <Spinner />
      ) : (
        <Table>
          <thead>
            <tr className="bg-panel2">
              <th className="th">URL</th>
              <th className="th">Events</th>
              <th className="th">Last delivery</th>
              <th className="th">Failures</th>
              <th className="th"></th>
            </tr>
          </thead>
          <tbody>
            {(webhooks.data ?? []).length === 0 && (
              <Row>
                <td className="td text-muted" colSpan={5}>
                  No webhooks.
                </td>
              </Row>
            )}
            {(webhooks.data ?? []).map((w) => (
              <Row key={w.id}>
                <td className="td max-w-xs truncate font-mono text-xs">{w.url}</td>
                <td className="td text-xs text-muted">{w.events.join(", ") || "all"}</td>
                <td className="td text-muted">{w.last_delivery_at ? timeAgo(w.last_delivery_at) : "never"}</td>
                <td className="td">{w.failure_count}</td>
                <td className="td text-right">
                  {manage && (
                    <span className="flex justify-end gap-2">
                      <button className="btn" onClick={() => testHook.mutate(w.id)}>
                        Test
                      </button>
                      <button className="btn btn-danger" onClick={() => delHook.mutate(w.id)}>
                        Delete
                      </button>
                    </span>
                  )}
                </td>
              </Row>
            ))}
          </tbody>
        </Table>
      )}

      {manage && (
        <form
          className="card mt-3 flex flex-col gap-3"
          onSubmit={(e) => {
            e.preventDefault();
            const f = new FormData(e.currentTarget);
            addHook.mutate({
              url: f.get("url"),
              secret: f.get("secret") || null,
              events: [...checked],
            });
            e.currentTarget.reset();
          }}
        >
          <div className="flex flex-wrap items-end gap-3">
            <div className="flex-1">
              <label className="label">Endpoint URL</label>
              <input className="input" name="url" required />
            </div>
            <div>
              <label className="label">Signing secret</label>
              <input className="input" name="secret" placeholder="optional" />
            </div>
          </div>
          <div className="grid grid-cols-2 gap-1 text-xs md:grid-cols-3">
            {EVENTS.map((ev) => (
              <label key={ev} className="flex items-center gap-1.5">
                <input
                  type="checkbox"
                  checked={checked.has(ev)}
                  onChange={(e) => {
                    const next = new Set(checked);
                    e.target.checked ? next.add(ev) : next.delete(ev);
                    setChecked(next);
                  }}
                />
                {ev}
              </label>
            ))}
          </div>
          <button className="btn btn-primary self-start" disabled={addHook.isPending}>
            Add webhook
          </button>
          {addHook.error && <span className="text-sm text-bad">{(addHook.error as Error).message}</span>}
        </form>
      )}
    </>
  );
}
