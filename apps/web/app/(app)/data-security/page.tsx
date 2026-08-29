"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";

import { ErrorBox, PageHeader, Row, SeverityBadge, Spinner, Table } from "@/components/ui";
import { api } from "@/lib/api";
import { useAuth } from "@/lib/auth";
import type { Severity } from "@/lib/types";

interface DataPolicy {
  id: string;
  name: string;
  classification: string;
  action: string;
  enabled: boolean;
}
interface ScanResult {
  classification: string | null;
  action: string;
  findings: { path: string; detector: string; classification: Severity; sample: string }[];
  redaction_paths: string[];
}

export default function DataSecurityPage() {
  const { can } = useAuth();
  const qc = useQueryClient();
  const [text, setText] = useState('{"customer": {"ssn": "123-45-6789", "email": "a@b.com"}}');

  const policies = useQuery({
    queryKey: ["data-policies"],
    queryFn: () => api<DataPolicy[]>("/v1/data-security/policies"),
  });

  const scan = useMutation({
    mutationFn: () =>
      api<ScanResult>("/v1/data-security/scan", {
        method: "POST",
        body: (() => {
          try {
            return { payload: JSON.parse(text) };
          } catch {
            return { text };
          }
        })(),
      }),
  });

  const addPolicy = useMutation({
    mutationFn: (body: Record<string, unknown>) =>
      api("/v1/data-security/policies", { method: "POST", body }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["data-policies"] }),
  });

  return (
    <>
      <PageHeader title="Data Security" subtitle="DLP classification & policies (PRD §27)" />

      <div className="card mb-4">
        <label className="label">Scan a payload</label>
        <textarea className="input h-24 font-mono text-xs" value={text} onChange={(e) => setText(e.target.value)} />
        <button className="btn btn-primary mt-2" disabled={scan.isPending} onClick={() => scan.mutate()}>
          Scan
        </button>
        {scan.data && (
          <div className="mt-3 text-sm">
            <div>
              classification: <strong>{scan.data.classification ?? "none"}</strong> · resolved action:{" "}
              <strong>{scan.data.action}</strong>
            </div>
            <ul className="mt-2 space-y-1 text-xs text-muted">
              {scan.data.findings.map((f, i) => (
                <li key={i}>
                  {f.path} — {f.detector} ({f.classification}) → <code>{f.sample}</code>
                </li>
              ))}
            </ul>
          </div>
        )}
        {scan.error && <p className="mt-2 text-sm text-bad">{(scan.error as Error).message}</p>}
      </div>

      <h2 className="mb-2 text-sm font-semibold text-muted">Data policies</h2>
      {policies.isLoading ? (
        <Spinner />
      ) : policies.error ? (
        <ErrorBox error={policies.error} />
      ) : (
        <Table>
          <thead>
            <tr className="bg-panel2">
              <th className="th">Name</th>
              <th className="th">Classification</th>
              <th className="th">Action</th>
              <th className="th">Enabled</th>
            </tr>
          </thead>
          <tbody>
            {(policies.data ?? []).length === 0 && (
              <Row>
                <td className="td text-muted" colSpan={4}>
                  Using built-in defaults (restricted→block, confidential→redact).
                </td>
              </Row>
            )}
            {(policies.data ?? []).map((p) => (
              <Row key={p.id}>
                <td className="td">{p.name}</td>
                <td className="td">
                  <SeverityBadge severity={p.classification as Severity} />
                </td>
                <td className="td">{p.action}</td>
                <td className="td">{p.enabled ? "yes" : "no"}</td>
              </Row>
            ))}
          </tbody>
        </Table>
      )}

      {can("data.manage") && (
        <form
          className="card mt-4 flex flex-wrap items-end gap-3"
          onSubmit={(e) => {
            e.preventDefault();
            const f = new FormData(e.currentTarget);
            addPolicy.mutate({
              name: f.get("name"),
              classification: f.get("classification"),
              action: f.get("action"),
            });
            e.currentTarget.reset();
          }}
        >
          <div>
            <label className="label">Name</label>
            <input className="input" name="name" required />
          </div>
          <div>
            <label className="label">Classification</label>
            <select className="input" name="classification">
              {["public", "internal", "confidential", "restricted"].map((x) => (
                <option key={x}>{x}</option>
              ))}
            </select>
          </div>
          <div>
            <label className="label">Action</label>
            <select className="input" name="action">
              {["allow", "redact", "approval", "block"].map((x) => (
                <option key={x}>{x}</option>
              ))}
            </select>
          </div>
          <button className="btn btn-primary" disabled={addPolicy.isPending}>
            Add
          </button>
        </form>
      )}
    </>
  );
}
