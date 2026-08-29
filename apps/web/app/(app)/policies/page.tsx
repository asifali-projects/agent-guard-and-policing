"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";

import { ErrorBox, Modal, PageHeader, Row, Spinner, Table } from "@/components/ui";
import { api } from "@/lib/api";
import { useAuth } from "@/lib/auth";
import type { Policy } from "@/lib/types";

const SAMPLE = JSON.stringify(
  {
    rules: [
      {
        effect: "approval",
        actions: ["payment.create"],
        when: { field: "parameters.amount", op: "gt", value: 5000 },
      },
    ],
    default_effect: "allow",
  },
  null,
  2,
);

export default function PoliciesPage() {
  const { can } = useAuth();
  const qc = useQueryClient();
  const [creating, setCreating] = useState(false);

  const q = useQuery({ queryKey: ["policies"], queryFn: () => api<Policy[]>("/v1/policies") });

  return (
    <>
      <PageHeader
        title="Policies"
        subtitle="Deterministic authorization (PRD §23)"
        actions={
          can("policy.manage") ? (
            <button className="btn btn-primary" onClick={() => setCreating(true)}>
              New policy
            </button>
          ) : null
        }
      />

      {q.isLoading ? (
        <Spinner />
      ) : q.error ? (
        <ErrorBox error={q.error} />
      ) : !q.data?.length ? (
        <div className="card text-sm text-muted">No policies. Runtime falls back to implicit allow.</div>
      ) : (
        <Table>
          <thead>
            <tr className="bg-panel2">
              <th className="th">Key</th>
              <th className="th">Name</th>
              <th className="th">Rules</th>
              <th className="th">Priority</th>
              <th className="th">Enabled</th>
              <th className="th">v</th>
            </tr>
          </thead>
          <tbody>
            {q.data.map((p) => (
              <Row key={p.id}>
                <td className="td font-mono text-xs">{p.key}</td>
                <td className="td">{p.name}</td>
                <td className="td text-muted">
                  {Array.isArray((p.spec as { rules?: unknown[] })?.rules)
                    ? (p.spec as { rules: unknown[] }).rules.length
                    : 0}
                </td>
                <td className="td text-muted">{p.priority}</td>
                <td className="td">{p.enabled ? "yes" : "no"}</td>
                <td className="td text-muted">{p.version}</td>
              </Row>
            ))}
          </tbody>
        </Table>
      )}

      {creating && <CreatePolicy qc={qc} onClose={() => setCreating(false)} />}
    </>
  );
}

function CreatePolicy({ qc, onClose }: { qc: ReturnType<typeof useQueryClient>; onClose: () => void }) {
  const [key, setKey] = useState("");
  const [name, setName] = useState("");
  const [spec, setSpec] = useState(SAMPLE);
  const [validation, setValidation] = useState<string | null>(null);

  const validate = useMutation({
    mutationFn: () => api<{ valid: boolean; errors: string[]; rule_count: number }>("/v1/policies/validate", {
      method: "POST",
      body: { spec: JSON.parse(spec) },
    }),
    onSuccess: (r) => setValidation(r.valid ? `valid — ${r.rule_count} rule(s)` : r.errors.join("; ")),
    onError: (e) => setValidation((e as Error).message),
  });

  const create = useMutation({
    mutationFn: () =>
      api("/v1/policies", { method: "POST", body: { key, name, spec: JSON.parse(spec) } }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["policies"] });
      onClose();
    },
    onError: (e) => setValidation((e as Error).message),
  });

  return (
    <Modal title="New policy" onClose={onClose} wide>
      <div className="grid grid-cols-2 gap-3">
        <div>
          <label className="label">Key</label>
          <input className="input font-mono" value={key} onChange={(e) => setKey(e.target.value)} placeholder="FIN-004" />
        </div>
        <div>
          <label className="label">Name</label>
          <input className="input" value={name} onChange={(e) => setName(e.target.value)} />
        </div>
      </div>
      <label className="label mt-3">Spec (JSON)</label>
      <textarea
        className="input h-64 font-mono text-xs"
        value={spec}
        onChange={(e) => setSpec(e.target.value)}
        spellCheck={false}
      />
      {validation && <p className="mt-2 text-sm text-accent">{validation}</p>}
      <div className="mt-3 flex gap-2">
        <button className="btn" disabled={validate.isPending} onClick={() => validate.mutate()}>
          Validate
        </button>
        <button
          className="btn btn-primary"
          disabled={create.isPending || !key || !name}
          onClick={() => create.mutate()}
        >
          Create
        </button>
      </div>
    </Modal>
  );
}
