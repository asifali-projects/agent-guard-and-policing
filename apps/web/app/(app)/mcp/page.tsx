"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";

import { ErrorBox, Modal, PageHeader, Row, SeverityBadge, Spinner, Table } from "@/components/ui";
import { api } from "@/lib/api";
import { useAuth } from "@/lib/auth";
import { timeAgo } from "@/lib/format";
import type { McpServer } from "@/lib/types";

export default function McpPage() {
  const { can } = useAuth();
  const qc = useQueryClient();
  const [creating, setCreating] = useState(false);

  const q = useQuery({ queryKey: ["mcp"], queryFn: () => api<McpServer[]>("/v1/mcp/servers") });

  const scan = useMutation({
    mutationFn: (id: string) => api(`/v1/mcp/servers/${id}/scan`, { method: "POST", body: {} }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["mcp"] }),
  });

  const create = useMutation({
    mutationFn: (body: Record<string, unknown>) => api("/v1/mcp/servers", { method: "POST", body }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["mcp"] });
      setCreating(false);
    },
  });

  return (
    <>
      <PageHeader
        title="MCP Servers"
        subtitle="MCP security (PRD §17)"
        actions={
          can("mcp.manage") ? (
            <button className="btn btn-primary" onClick={() => setCreating(true)}>
              Register server
            </button>
          ) : null
        }
      />
      {q.isLoading ? (
        <Spinner />
      ) : q.error ? (
        <ErrorBox error={q.error} />
      ) : !q.data?.length ? (
        <div className="card text-sm text-muted">No MCP servers registered.</div>
      ) : (
        <Table>
          <thead>
            <tr className="bg-panel2">
              <th className="th">Server</th>
              <th className="th">Status</th>
              <th className="th">Risk</th>
              <th className="th">Trusted</th>
              <th className="th">Last scan</th>
              <th className="th"></th>
            </tr>
          </thead>
          <tbody>
            {q.data.map((s) => (
              <Row key={s.id}>
                <td className="td font-medium">{s.name}</td>
                <td className="td text-muted">{s.status}</td>
                <td className="td">
                  <SeverityBadge severity={s.risk} />
                </td>
                <td className="td">{s.trusted ? "yes" : "no"}</td>
                <td className="td text-muted">{s.last_scan_at ? timeAgo(s.last_scan_at) : "never"}</td>
                <td className="td text-right">
                  {can("mcp.manage") && (
                    <button className="btn" disabled={scan.isPending} onClick={() => scan.mutate(s.id)}>
                      Scan
                    </button>
                  )}
                </td>
              </Row>
            ))}
          </tbody>
        </Table>
      )}

      {creating && (
        <Modal title="Register MCP server" onClose={() => setCreating(false)}>
          <form
            className="flex flex-col gap-3"
            onSubmit={(e) => {
              e.preventDefault();
              const f = new FormData(e.currentTarget);
              create.mutate({
                name: f.get("name"),
                url: f.get("url") || null,
                version: f.get("version") || null,
                trusted: f.get("trusted") === "on",
                permissions: String(f.get("permissions") || "")
                  .split(",")
                  .map((s) => s.trim())
                  .filter(Boolean),
              });
            }}
          >
            <div>
              <label className="label">Name</label>
              <input className="input" name="name" required />
            </div>
            <div className="grid grid-cols-2 gap-3">
              <div>
                <label className="label">URL</label>
                <input className="input" name="url" />
              </div>
              <div>
                <label className="label">Version</label>
                <input className="input" name="version" />
              </div>
            </div>
            <div>
              <label className="label">Permissions (comma-separated)</label>
              <input className="input" name="permissions" placeholder="read, filesystem.read" />
            </div>
            <label className="flex items-center gap-2 text-sm">
              <input type="checkbox" name="trusted" /> Trusted server
            </label>
            {create.error && <div className="text-sm text-bad">{(create.error as Error).message}</div>}
            <button className="btn btn-primary justify-center" disabled={create.isPending}>
              Register
            </button>
          </form>
        </Modal>
      )}
    </>
  );
}
