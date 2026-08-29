"use client";

import { createContext, useCallback, useContext, useEffect, useState } from "react";

import { api, tokens } from "./api";
import type { Me } from "./types";

interface AuthCtx {
  me: Me | null;
  ready: boolean;
  login: (email: string, password: string, organizationId?: string) => Promise<void>;
  register: (email: string, password: string, organizationName: string) => Promise<void>;
  logout: () => void;
  can: (perm: string) => boolean;
  refreshMe: () => Promise<void>;
}

const Ctx = createContext<AuthCtx | null>(null);

interface TokenResponse {
  access_token: string;
  refresh_token: string;
  organization_id: string | null;
  mfa_required?: boolean;
}

export function AuthProvider({ children }: { children: React.ReactNode }) {
  const [me, setMe] = useState<Me | null>(null);
  const [ready, setReady] = useState(false);

  const refreshMe = useCallback(async () => {
    if (!tokens.access) {
      setMe(null);
      return;
    }
    try {
      setMe(await api<Me>("/v1/auth/me"));
    } catch {
      tokens.clear();
      setMe(null);
    }
  }, []);

  useEffect(() => {
    refreshMe().finally(() => setReady(true));
  }, [refreshMe]);

  const store = (t: TokenResponse) => tokens.set(t.access_token, t.refresh_token, t.organization_id);

  const login = useCallback(
    async (email: string, password: string, organizationId?: string) => {
      const res = await api<TokenResponse>("/v1/auth/login", {
        method: "POST",
        auth: false,
        body: { email, password, organization_id: organizationId },
      });
      if (res.mfa_required) throw new Error("MFA is required — use the CLI for now.");
      store(res);
      await refreshMe();
    },
    [refreshMe],
  );

  const register = useCallback(
    async (email: string, password: string, organizationName: string) => {
      const res = await api<TokenResponse>("/v1/auth/register", {
        method: "POST",
        auth: false,
        body: { email, password, organization_name: organizationName },
      });
      store(res);
      await refreshMe();
    },
    [refreshMe],
  );

  const logout = useCallback(() => {
    api("/v1/auth/logout", { method: "POST", body: {} }).catch(() => {});
    tokens.clear();
    setMe(null);
    window.location.href = "/login";
  }, []);

  const can = useCallback((perm: string) => !!me?.permissions.includes(perm), [me]);

  return (
    <Ctx.Provider value={{ me, ready, login, register, logout, can, refreshMe }}>
      {children}
    </Ctx.Provider>
  );
}

export function useAuth(): AuthCtx {
  const ctx = useContext(Ctx);
  if (!ctx) throw new Error("useAuth must be used inside AuthProvider");
  return ctx;
}
