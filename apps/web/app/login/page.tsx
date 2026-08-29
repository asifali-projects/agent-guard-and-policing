"use client";

import { useRouter } from "next/navigation";
import { useEffect, useState } from "react";

import { ApiError, api } from "@/lib/api";
import { useAuth } from "@/lib/auth";
import type { RegionsResponse } from "@/lib/types";

interface Discovery {
  sso: boolean;
  enforced: boolean;
  name: string | null;
  login_url: string | null;
}

export default function LoginPage() {
  const { me, ready, login, register } = useAuth();
  const router = useRouter();
  const [ssoError, setSsoError] = useState<string | null>(null);
  const [mode, setMode] = useState<"login" | "register">("login");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [org, setOrg] = useState("");
  const [error, setError] = useState<React.ReactNode | null>(null);
  const [busy, setBusy] = useState(false);
  const [ssoBusy, setSsoBusy] = useState(false);
  const [regions, setRegions] = useState<RegionsResponse | null>(null);
  const [regionChoice, setRegionChoice] = useState<string>("");

  useEffect(() => {
    if (ready && me) router.replace("/");
  }, [ready, me, router]);

  useEffect(() => {
    const p = new URLSearchParams(window.location.search).get("sso_error");
    if (p) setSsoError(p);
    api<RegionsResponse>("/v1/regions", { auth: false })
      .then((r) => {
        setRegions(r);
        setRegionChoice(r.current);
      })
      .catch(() => {});
  }, []);

  function wrongRegionMessage(err: ApiError): React.ReactNode {
    if (err.regionUrl) {
      return (
        <>
          Your account&apos;s data is in the <b>{err.region}</b> region.{" "}
          <a className="underline" href={`${err.regionUrl.replace(/\/[^/]*$/, "")}`}>
            Continue there →
          </a>
        </>
      );
    }
    return err.message;
  }

  async function startSso() {
    setError(null);
    if (!email) {
      setError("Enter your work email first.");
      return;
    }
    setSsoBusy(true);
    try {
      const d = await api<Discovery>("/v1/auth/sso/discover", {
        method: "POST",
        auth: false,
        body: { email },
      });
      if (d.sso && d.login_url) {
        window.location.href = d.login_url;
      } else {
        setError("No single sign-on is configured for that domain.");
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : "SSO lookup failed");
    } finally {
      setSsoBusy(false);
    }
  }

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);

    // Registering into a different region: send the browser to that region's app.
    if (mode === "register" && regions && regionChoice && regionChoice !== regions.current) {
      const target = regions.regions.find((r) => r.code === regionChoice);
      if (target?.web_url) {
        window.location.href = `${target.web_url}/login`;
        return;
      }
    }

    setBusy(true);
    try {
      if (mode === "login") await login(email, password);
      else await register(email, password, org, regions?.current);
      router.replace("/");
    } catch (err) {
      if (err instanceof ApiError && err.status === 421) setError(wrongRegionMessage(err));
      else setError(err instanceof Error ? err.message : "failed");
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="flex min-h-screen items-center justify-center p-6">
      <div className="card w-full max-w-sm">
        <div className="mb-4 text-center text-xl font-bold">
          Agent<span className="text-accent">Guard</span>
        </div>
        <div className="mb-4 flex rounded-lg border border-border p-0.5 text-sm">
          {(["login", "register"] as const).map((m) => (
            <button
              key={m}
              className={`flex-1 rounded-md py-1 ${mode === m ? "bg-accent/20" : "text-muted"}`}
              onClick={() => setMode(m)}
            >
              {m === "login" ? "Sign in" : "Create account"}
            </button>
          ))}
        </div>
        <form onSubmit={submit} className="flex flex-col gap-3">
          <div>
            <label className="label">Email</label>
            <input
              className="input"
              type="email"
              required
              value={email}
              onChange={(e) => setEmail(e.target.value)}
            />
          </div>
          <div>
            <label className="label">Password</label>
            <input
              className="input"
              type="password"
              required
              minLength={mode === "register" ? 12 : 1}
              value={password}
              onChange={(e) => setPassword(e.target.value)}
            />
          </div>
          {mode === "register" && (
            <>
              <div>
                <label className="label">Organization name</label>
                <input
                  className="input"
                  required
                  value={org}
                  onChange={(e) => setOrg(e.target.value)}
                />
              </div>
              {regions && regions.regions.length > 1 && (
                <div>
                  <label className="label">Data residency region</label>
                  <select
                    className="input"
                    value={regionChoice}
                    onChange={(e) => setRegionChoice(e.target.value)}
                  >
                    {regions.regions.map((r) => (
                      <option key={r.code} value={r.code}>
                        {r.name}
                      </option>
                    ))}
                  </select>
                  <p className="mt-1 text-xs text-muted">
                    Your data stays in this region — it can&apos;t be changed later.
                  </p>
                </div>
              )}
            </>
          )}
          {(error || ssoError) && <div className="text-sm text-bad">{error ?? ssoError}</div>}
          <button className="btn btn-primary justify-center" disabled={busy}>
            {busy ? "…" : mode === "login" ? "Sign in" : "Create account"}
          </button>
        </form>
        {mode === "login" && (
          <button
            type="button"
            onClick={startSso}
            disabled={ssoBusy}
            className="btn mt-2 w-full justify-center"
          >
            {ssoBusy ? "…" : "Single sign-on"}
          </button>
        )}
        <p className="mt-3 text-center text-xs text-muted">
          {regions ? `Region: ${regions.current.toUpperCase()} · ` : ""}
          MFA-enabled accounts must use the <code>agentguard</code> CLI to sign in.
        </p>
      </div>
    </div>
  );
}
