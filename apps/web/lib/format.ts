import type { Severity } from "./types";

export function timeAgo(iso: string | null): string {
  if (!iso) return "—";
  const d = new Date(iso).getTime();
  const s = Math.round((Date.now() - d) / 1000);
  if (s < 60) return `${s}s ago`;
  if (s < 3600) return `${Math.round(s / 60)}m ago`;
  if (s < 86400) return `${Math.round(s / 3600)}h ago`;
  return `${Math.round(s / 86400)}d ago`;
}

export function dateTime(iso: string | null): string {
  if (!iso) return "—";
  return new Date(iso).toLocaleString();
}

export function num(n: number | null | undefined): string {
  if (n === null || n === undefined) return "—";
  return n.toLocaleString();
}

export const severityColor: Record<Severity, string> = {
  info: "text-muted",
  low: "text-ok",
  medium: "text-warn",
  high: "text-bad",
  critical: "text-crit",
};

export const severityBg: Record<Severity, string> = {
  info: "bg-muted/15 text-muted",
  low: "bg-ok/15 text-ok",
  medium: "bg-warn/15 text-warn",
  high: "bg-bad/15 text-bad",
  critical: "bg-crit/20 text-crit",
};

export function decisionBg(decision: string | null): string {
  switch (decision) {
    case "ALLOW":
    case "allow":
      return "bg-ok/15 text-ok";
    case "DENY":
    case "deny":
      return "bg-bad/15 text-bad";
    case "APPROVAL":
    case "approval":
      return "bg-warn/15 text-warn";
    case "REDACT":
    case "redact":
      return "bg-accent/15 text-accent";
    case "RATE_LIMIT":
    case "rate_limit":
      return "bg-warn/15 text-warn";
    default:
      return "bg-muted/15 text-muted";
  }
}

export function riskColor(score: number | null | undefined): string {
  if (score === null || score === undefined) return "text-muted";
  if (score >= 85) return "text-crit";
  if (score >= 65) return "text-bad";
  if (score >= 40) return "text-warn";
  return "text-ok";
}
