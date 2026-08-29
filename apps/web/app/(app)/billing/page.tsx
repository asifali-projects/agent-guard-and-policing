"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";

import { ErrorBox, PageHeader, Spinner, StatCard } from "@/components/ui";
import { api } from "@/lib/api";
import { useAuth } from "@/lib/auth";
import { num } from "@/lib/format";

interface Plan {
  code: string;
  name: string;
  monthly_price_cents: number;
  limits: Record<string, number>;
  is_public: boolean;
}
interface Subscription {
  plan: Plan;
  status: string;
  usage: { period: string; metrics: Record<string, number>; limits: Record<string, number>; over_limit: string[] };
}

export default function BillingPage() {
  const { can } = useAuth();
  const qc = useQueryClient();

  const sub = useQuery({ queryKey: ["subscription"], queryFn: () => api<Subscription>("/v1/billing/subscription") });
  const plans = useQuery({ queryKey: ["plans"], queryFn: () => api<Plan[]>("/v1/billing/plans") });

  const change = useMutation({
    mutationFn: (plan_code: string) => api("/v1/billing/subscription", { method: "POST", body: { plan_code } }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["subscription"] }),
  });

  if (sub.isLoading) return <Spinner />;
  if (sub.error) return <ErrorBox error={sub.error} />;
  const s = sub.data!;
  const m = s.usage.metrics;

  return (
    <>
      <PageHeader title="Billing" subtitle={`Plan: ${s.plan.name} · usage for ${s.usage.period}`} />

      {s.usage.over_limit.length > 0 && (
        <div className="card mb-4 border-warn/50 text-sm text-warn">
          Over plan limits: {s.usage.over_limit.join(", ")}. Consider upgrading.
        </div>
      )}

      <div className="grid gap-4 md:grid-cols-4">
        <StatCard label="Runtime actions" value={num(m.runtime_actions)} hint={limitHint(s.usage.limits.runtime_actions)} />
        <StatCard label="Blocked" value={num(m.runtime_blocked)} />
        <StatCard label="Red-team tests" value={num(m.redteam_tests)} hint={limitHint(s.usage.limits.redteam_tests)} />
        <StatCard label="Data scans" value={num(m.data_scans)} />
        <StatCard label="Agents" value={num(m.agents)} hint={limitHint(s.usage.limits.agents)} />
        <StatCard label="MCP servers" value={num(m.mcp_servers)} />
        <StatCard label="Users" value={num(m.users)} hint={limitHint(s.usage.limits.users)} />
      </div>

      <h2 className="mb-2 mt-6 text-sm font-semibold text-muted">Plans</h2>
      <div className="grid gap-3 md:grid-cols-4">
        {(plans.data ?? []).map((p) => (
          <div key={p.code} className={`card ${p.code === s.plan.code ? "border-accent" : ""}`}>
            <div className="text-lg font-semibold">{p.name}</div>
            <div className="text-2xl font-bold">
              ${(p.monthly_price_cents / 100).toFixed(0)}
              <span className="text-sm text-muted">/mo</span>
            </div>
            <ul className="mt-2 space-y-0.5 text-xs text-muted">
              {Object.entries(p.limits).map(([k, v]) => (
                <li key={k}>
                  {k.replace(/_/g, " ")}: {num(v)}
                </li>
              ))}
            </ul>
            {p.code === s.plan.code ? (
              <div className="mt-3 text-xs text-accent">current plan</div>
            ) : (
              can("org.billing") && (
                <button
                  className="btn btn-primary mt-3 w-full justify-center"
                  disabled={change.isPending}
                  onClick={() => change.mutate(p.code)}
                >
                  Switch
                </button>
              )
            )}
          </div>
        ))}
      </div>
      <p className="mt-3 text-xs text-muted">
        Payment processing (Stripe) is not wired in this build — switching plans updates the record only.
      </p>
    </>
  );
}

function limitHint(limit: number | undefined): string | undefined {
  return limit ? `limit ${num(limit)}` : undefined;
}
