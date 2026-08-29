"use client";

import { useEffect, useState } from "react";

import { tokens } from "@/lib/api";

/** Landing page for the enterprise SSO round-trip (PRD §9, §51).
 *
 * The API redirects here with the freshly minted session in the URL fragment
 * (`#access_token=…&refresh_token=…`), which never reaches a server. We persist
 * it and hard-navigate to the app so the AuthProvider re-hydrates. */
export default function SsoCallbackPage() {
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const frag = new URLSearchParams(window.location.hash.replace(/^#/, ""));
    const access = frag.get("access_token");
    const refresh = frag.get("refresh_token");
    const org = frag.get("organization_id");
    const err = frag.get("sso_error");

    if (err) {
      window.location.replace(`/login?sso_error=${encodeURIComponent(err)}`);
      return;
    }
    if (access && refresh) {
      tokens.set(access, refresh, org);
      window.location.replace("/");
      return;
    }
    setError("This sign-in link is missing its session tokens.");
  }, []);

  return (
    <div className="flex min-h-screen items-center justify-center p-6 text-sm text-muted">
      {error ? (
        <div className="card max-w-sm text-center">
          <div className="mb-2 text-bad">Sign-in failed</div>
          <p>{error}</p>
          <a className="btn mt-3 inline-block" href="/login">
            Back to sign in
          </a>
        </div>
      ) : (
        "Signing you in…"
      )}
    </div>
  );
}
