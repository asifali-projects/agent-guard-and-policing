"use client";

import clsx from "clsx";

import { decisionBg, riskColor, severityBg } from "@/lib/format";
import type { Severity } from "@/lib/types";

export function PageHeader({
  title,
  subtitle,
  actions,
}: {
  title: string;
  subtitle?: string;
  actions?: React.ReactNode;
}) {
  return (
    <div className="mb-5 flex flex-wrap items-end justify-between gap-3">
      <div>
        <h1 className="text-xl font-semibold">{title}</h1>
        {subtitle && <p className="mt-0.5 text-sm text-muted">{subtitle}</p>}
      </div>
      {actions && <div className="flex gap-2">{actions}</div>}
    </div>
  );
}

export function SeverityBadge({ severity }: { severity: Severity }) {
  return (
    <span
      className={clsx(
        "rounded px-1.5 py-0.5 text-xs font-semibold uppercase",
        severityBg[severity] ?? severityBg.info,
      )}
    >
      {severity}
    </span>
  );
}

export function DecisionBadge({ decision }: { decision: string | null }) {
  if (!decision) return <span className="text-muted">—</span>;
  return (
    <span
      className={clsx("rounded px-1.5 py-0.5 text-xs font-semibold", decisionBg(decision))}
    >
      {decision.toUpperCase()}
    </span>
  );
}

export function RiskScore({ score }: { score: number | null | undefined }) {
  return (
    <span className={clsx("font-semibold tabular-nums", riskColor(score))}>
      {score ?? "—"}
    </span>
  );
}

export function StatCard({
  label,
  value,
  hint,
  tone,
}: {
  label: string;
  value: React.ReactNode;
  hint?: string;
  tone?: "ok" | "bad" | "warn";
}) {
  return (
    <div className="card">
      <div className="text-xs uppercase tracking-wide text-muted">{label}</div>
      <div
        className={clsx(
          "mt-1 text-2xl font-bold tabular-nums",
          tone === "ok" && "text-ok",
          tone === "bad" && "text-bad",
          tone === "warn" && "text-warn",
        )}
      >
        {value}
      </div>
      {hint && <div className="mt-0.5 text-xs text-muted">{hint}</div>}
    </div>
  );
}

export function Spinner() {
  return <div className="animate-pulse text-sm text-muted">Loading…</div>;
}

export function ErrorBox({ error }: { error: unknown }) {
  const msg = error instanceof Error ? error.message : String(error);
  return (
    <div className="card border-bad/40 text-sm text-bad">Error: {msg}</div>
  );
}

export function EmptyState({ children }: { children: React.ReactNode }) {
  return <div className="card text-sm text-muted">{children}</div>;
}

export function Table({ children }: { children: React.ReactNode }) {
  return (
    <div className="overflow-x-auto rounded-xl border border-border">
      <table className="w-full border-collapse">{children}</table>
    </div>
  );
}

export function Row({
  children,
  onClick,
}: {
  children: React.ReactNode;
  onClick?: () => void;
}) {
  return (
    <tr
      className={clsx(
        "border-t border-border",
        onClick && "cursor-pointer hover:bg-panel2",
      )}
      onClick={onClick}
    >
      {children}
    </tr>
  );
}

export function Modal({
  title,
  onClose,
  children,
  wide,
}: {
  title: string;
  onClose: () => void;
  children: React.ReactNode;
  wide?: boolean;
}) {
  return (
    <div
      className="fixed inset-0 z-50 flex items-start justify-center bg-black/60 p-4 pt-20"
      onClick={onClose}
    >
      <div
        className={clsx("card w-full", wide ? "max-w-3xl" : "max-w-lg")}
        onClick={(e) => e.stopPropagation()}
      >
        <div className="mb-3 flex items-center justify-between">
          <h2 className="text-base font-semibold">{title}</h2>
          <button className="text-muted hover:text-fg" onClick={onClose}>
            ✕
          </button>
        </div>
        {children}
      </div>
    </div>
  );
}
