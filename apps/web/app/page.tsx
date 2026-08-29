async function getApiHealth() {
  const base = process.env.NEXT_PUBLIC_API_BASE_URL ?? "http://localhost:8000";
  try {
    const res = await fetch(`${base}/healthz`, { cache: "no-store" });
    if (!res.ok) return { reachable: false as const };
    return { reachable: true as const, body: await res.json() };
  } catch {
    return { reachable: false as const };
  }
}

export default async function Home() {
  const health = await getApiHealth();

  return (
    <main>
      <h1>AgentGuard</h1>
      <p className="tag">Security control plane for AI agents — dashboard scaffold (Step 0).</p>

      <div className="card">
        <strong>API status</strong>
        <p>
          {health.reachable ? (
            <span className="status-ok">reachable — v{health.body?.version ?? "?"}</span>
          ) : (
            <span className="status-bad">
              unreachable — start it with <code>.\tasks.ps1 api-dev</code>
            </span>
          )}
        </p>
      </div>

      <div className="card">
        <strong>Next steps</strong>
        <p className="tag">
          Dashboard, agent inventory, red-team, policies, approvals and audit views are built in
          Step 7. This page only verifies the web app compiles and can reach the API.
        </p>
      </div>
    </main>
  );
}
