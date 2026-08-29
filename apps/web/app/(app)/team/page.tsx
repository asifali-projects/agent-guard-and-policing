"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";

import { ErrorBox, PageHeader, Row, Spinner, Table } from "@/components/ui";
import { api } from "@/lib/api";
import { useAuth } from "@/lib/auth";
import type { Member } from "@/lib/types";

const ROLES = [
  "owner",
  "admin",
  "security_admin",
  "security_analyst",
  "developer",
  "auditor",
  "billing_admin",
];

export default function TeamPage() {
  const { me, can } = useAuth();
  const org = me?.active_organization_id;
  const qc = useQueryClient();

  const q = useQuery({
    queryKey: ["members"],
    queryFn: () => api<Member[]>(`/v1/organizations/${org}/members`),
    enabled: !!org,
  });

  const add = useMutation({
    mutationFn: (body: Record<string, unknown>) =>
      api(`/v1/organizations/${org}/members`, { method: "POST", body }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["members"] }),
  });

  const setRole = useMutation({
    mutationFn: ({ userId, role }: { userId: string; role: string }) =>
      api(`/v1/organizations/${org}/members/${userId}`, { method: "PATCH", body: { role } }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["members"] }),
  });

  return (
    <>
      <PageHeader title="Team" subtitle="Members & roles (PRD §50)" />

      {q.isLoading ? (
        <Spinner />
      ) : q.error ? (
        <ErrorBox error={q.error} />
      ) : (
        <Table>
          <thead>
            <tr className="bg-panel2">
              <th className="th">Email</th>
              <th className="th">Role</th>
              <th className="th">Active</th>
            </tr>
          </thead>
          <tbody>
            {(q.data ?? []).map((m) => (
              <Row key={m.user_id}>
                <td className="td">{m.email}</td>
                <td className="td">
                  {can("member.manage") ? (
                    <select
                      className="input max-w-[12rem]"
                      value={m.role}
                      onChange={(e) => setRole.mutate({ userId: m.user_id, role: e.target.value })}
                    >
                      {ROLES.map((r) => (
                        <option key={r}>{r}</option>
                      ))}
                    </select>
                  ) : (
                    m.role
                  )}
                </td>
                <td className="td text-muted">{m.is_active ? "yes" : "invited"}</td>
              </Row>
            ))}
          </tbody>
        </Table>
      )}

      {can("member.manage") && (
        <form
          className="card mt-4 flex flex-wrap items-end gap-3"
          onSubmit={(e) => {
            e.preventDefault();
            const f = new FormData(e.currentTarget);
            add.mutate({ email: f.get("email"), role: f.get("role") });
            e.currentTarget.reset();
          }}
        >
          <div>
            <label className="label">Email</label>
            <input className="input" name="email" type="email" required />
          </div>
          <div>
            <label className="label">Role</label>
            <select className="input" name="role" defaultValue="developer">
              {ROLES.map((r) => (
                <option key={r}>{r}</option>
              ))}
            </select>
          </div>
          <button className="btn btn-primary" disabled={add.isPending}>
            Add member
          </button>
          {add.error && <span className="text-sm text-bad">{(add.error as Error).message}</span>}
        </form>
      )}
    </>
  );
}
