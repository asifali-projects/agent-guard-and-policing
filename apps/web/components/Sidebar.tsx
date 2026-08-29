"use client";

import clsx from "clsx";
import Link from "next/link";
import { usePathname } from "next/navigation";

/** Information architecture — PRD §8. */
const NAV: { group: string; items: { label: string; href: string }[] }[] = [
  { group: "", items: [{ label: "Dashboard", href: "/" }] },
  {
    group: "Security",
    items: [
      { label: "Agents", href: "/agents" },
      { label: "Tools", href: "/tools" },
      { label: "MCP Servers", href: "/mcp" },
      { label: "Red Team", href: "/red-team" },
      { label: "Findings", href: "/findings" },
      { label: "Threats", href: "/threats" },
      { label: "Incidents", href: "/incidents" },
      { label: "Approvals", href: "/approvals" },
    ],
  },
  {
    group: "Governance",
    items: [
      { label: "Policies", href: "/policies" },
      { label: "Data Security", href: "/data-security" },
    ],
  },
  {
    group: "Observability",
    items: [{ label: "Audit Log", href: "/audit" }],
  },
  {
    group: "Developer",
    items: [
      { label: "API Keys", href: "/api-keys" },
      { label: "Integrations", href: "/integrations" },
    ],
  },
  {
    group: "Administration",
    items: [
      { label: "Team", href: "/team" },
      { label: "SSO & SCIM", href: "/sso" },
      { label: "Billing", href: "/billing" },
    ],
  },
];

export function Sidebar() {
  const pathname = usePathname();
  return (
    <nav className="flex w-52 shrink-0 flex-col gap-4 border-r border-border bg-panel2 p-3">
      <div className="px-2 py-1 text-lg font-bold">
        Agent<span className="text-accent">Guard</span>
      </div>
      {NAV.map((section) => (
        <div key={section.group || "root"}>
          {section.group && (
            <div className="px-2 pb-1 text-[10px] font-semibold uppercase tracking-wider text-muted">
              {section.group}
            </div>
          )}
          <div className="flex flex-col">
            {section.items.map((item) => {
              const active =
                item.href === "/" ? pathname === "/" : pathname.startsWith(item.href);
              return (
                <Link
                  key={item.href}
                  href={item.href}
                  className={clsx(
                    "rounded-lg px-2 py-1.5 text-sm",
                    active ? "bg-accent/20 text-fg" : "text-muted hover:bg-panel hover:text-fg",
                  )}
                >
                  {item.label}
                </Link>
              );
            })}
          </div>
        </div>
      ))}
    </nav>
  );
}
