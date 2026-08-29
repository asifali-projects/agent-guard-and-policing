"use client";

import { useRouter } from "next/navigation";
import { useEffect } from "react";

import { useAuth } from "@/lib/auth";
import { Sidebar } from "./Sidebar";

export function AppShell({ children }: { children: React.ReactNode }) {
  const { me, ready, logout } = useAuth();
  const router = useRouter();

  useEffect(() => {
    if (ready && !me) router.replace("/login");
  }, [ready, me, router]);

  if (!ready) return <div className="p-8 text-sm text-muted">Loading…</div>;
  if (!me) return null;

  const org = me.memberships.find((m) => m.organization_id === me.active_organization_id);

  return (
    <div className="flex min-h-screen">
      <Sidebar />
      <div className="flex min-w-0 flex-1 flex-col">
        <header className="flex items-center justify-between border-b border-border bg-panel2 px-5 py-2 text-sm">
          <div className="text-muted">
            {org?.organization_name ?? "—"}
            {org && <span className="ml-2 rounded bg-panel px-1.5 py-0.5 text-xs">{org.role}</span>}
          </div>
          <div className="flex items-center gap-3">
            <span className="text-muted">{me.email}</span>
            <button className="btn" onClick={logout}>
              Sign out
            </button>
          </div>
        </header>
        <main className="min-w-0 flex-1 p-6">{children}</main>
      </div>
    </div>
  );
}
