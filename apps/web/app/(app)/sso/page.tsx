"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";

import { ErrorBox, PageHeader, Row, Spinner, Table } from "@/components/ui";
import { api } from "@/lib/api";
import { useAuth } from "@/lib/auth";

interface Connection {
  id: string;
  name: string;
  protocol: "oidc" | "saml";
  domains: string[];
  enabled: boolean;
  enforced: boolean;
  default_role: string;
  acs_url: string | null;
  metadata_url: string | null;
}

interface ScimConfig {
  enabled: boolean;
  default_role: string;
  token_set: boolean;
  last_request_at: string | null;
  scim_base_url: string;
  users: number;
  groups: number;
}

const ROLES = ["developer", "security_analyst", "security_admin", "auditor", "admin"];

export default function SsoPage() {
  const { me, can } = useAuth();
  const org = me?.active_organization_id;
  const manage = can("org.manage");
  const qc = useQueryClient();
  const base = `/v1/organizations/${org}/sso`;
  const [protocol, setProtocol] = useState<"oidc" | "saml">("oidc");

  const list = useQuery({
    queryKey: ["sso", org],
    queryFn: () => api<Connection[]>(base),
    enabled: !!org,
  });

  const create = useMutation({
    mutationFn: (body: Record<string, unknown>) => api(base, { method: "POST", body }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["sso", org] }),
  });
  const patch = useMutation({
    mutationFn: ({ id, body }: { id: string; body: Record<string, unknown> }) =>
      api(`${base}/${id}`, { method: "PATCH", body }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["sso", org] }),
  });
  const remove = useMutation({
    mutationFn: (id: string) => api(`${base}/${id}`, { method: "DELETE" }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["sso", org] }),
  });

  const scimBase = `/v1/organizations/${org}/scim`;
  const [scimToken, setScimToken] = useState<string | null>(null);
  const scim = useQuery({
    queryKey: ["scim", org],
    queryFn: () => api<ScimConfig>(scimBase),
    enabled: !!org,
  });
  const scimSave = useMutation({
    mutationFn: (body: Record<string, unknown>) => api(scimBase, { method: "PUT", body }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["scim", org] }),
  });
  const scimRotate = useMutation({
    mutationFn: () => api<{ token: string }>(`${scimBase}/rotate-token`, { method: "POST" }),
    onSuccess: (r) => {
      setScimToken(r.token);
      qc.invalidateQueries({ queryKey: ["scim", org] });
    },
  });
  const scimRevoke = useMutation({
    mutationFn: () => api(`${scimBase}/token`, { method: "DELETE" }),
    onSuccess: () => {
      setScimToken(null);
      qc.invalidateQueries({ queryKey: ["scim", org] });
    },
  });

  if (!manage) {
    return (
      <>
        <PageHeader title="SSO & SCIM" subtitle="Enterprise identity (PRD §9, §51)" />
        <p className="text-sm text-muted">
          You need the org.manage permission to configure SSO and SCIM.
        </p>
      </>
    );
  }

  return (
    <>
      <PageHeader
        title="SSO & SCIM"
        subtitle="SAML 2.0 / OIDC sign-in and SCIM 2.0 provisioning (PRD §9, §51)"
      />

      {list.isLoading ? (
        <Spinner />
      ) : list.error ? (
        <ErrorBox error={list.error} />
      ) : (
        <Table>
          <thead>
            <tr className="bg-panel2">
              <th className="th">Name</th>
              <th className="th">Protocol</th>
              <th className="th">Domains</th>
              <th className="th">Default role</th>
              <th className="th">State</th>
              <th className="th"></th>
            </tr>
          </thead>
          <tbody>
            {(list.data ?? []).length === 0 && (
              <Row>
                <td className="td text-muted" colSpan={6}>
                  No SSO connections yet.
                </td>
              </Row>
            )}
            {(list.data ?? []).map((c) => (
              <Row key={c.id}>
                <td className="td font-medium">{c.name}</td>
                <td className="td uppercase text-muted">{c.protocol}</td>
                <td className="td text-xs text-muted">{c.domains.join(", ") || "—"}</td>
                <td className="td text-muted">{c.default_role}</td>
                <td className="td text-xs">
                  {c.enabled ? "enabled" : "disabled"}
                  {c.enforced && <span className="text-bad"> · enforced</span>}
                </td>
                <td className="td text-right">
                  <span className="flex justify-end gap-2">
                    {c.metadata_url && (
                      <a className="btn" href={c.metadata_url} target="_blank" rel="noreferrer">
                        SP metadata
                      </a>
                    )}
                    <button
                      className="btn"
                      onClick={() => patch.mutate({ id: c.id, body: { enabled: !c.enabled } })}
                    >
                      {c.enabled ? "Disable" : "Enable"}
                    </button>
                    <button className="btn btn-danger" onClick={() => remove.mutate(c.id)}>
                      Delete
                    </button>
                  </span>
                </td>
              </Row>
            ))}
          </tbody>
        </Table>
      )}

      <form
        className="card mt-4 flex flex-col gap-3"
        onSubmit={(e) => {
          e.preventDefault();
          const f = new FormData(e.currentTarget);
          const domains = String(f.get("domains") || "")
            .split(/[\s,]+/)
            .filter(Boolean);
          const config =
            protocol === "oidc"
              ? {
                  issuer: f.get("issuer"),
                  client_id: f.get("client_id"),
                  client_secret: f.get("client_secret"),
                }
              : {
                  idp_entity_id: f.get("idp_entity_id"),
                  idp_sso_url: f.get("idp_sso_url"),
                  idp_x509_cert: f.get("idp_x509_cert"),
                };
          create.mutate({
            name: f.get("name"),
            protocol,
            domains,
            enforced: f.get("enforced") === "on",
            default_role: f.get("default_role"),
            config,
          });
          e.currentTarget.reset();
        }}
      >
        <div className="text-sm font-semibold">Add a connection</div>
        <div className="flex flex-wrap items-end gap-3">
          <div>
            <label className="label">Protocol</label>
            <select
              className="input"
              value={protocol}
              onChange={(e) => setProtocol(e.target.value as "oidc" | "saml")}
            >
              <option value="oidc">OIDC</option>
              <option value="saml">SAML 2.0</option>
            </select>
          </div>
          <div className="flex-1">
            <label className="label">Display name</label>
            <input className="input" name="name" required placeholder="Okta / Entra ID" />
          </div>
          <div>
            <label className="label">Default role</label>
            <select className="input" name="default_role" defaultValue="developer">
              {ROLES.map((r) => (
                <option key={r}>{r}</option>
              ))}
            </select>
          </div>
        </div>
        <div>
          <label className="label">Email domains (space or comma separated)</label>
          <input className="input" name="domains" placeholder="acme.com corp.acme.com" />
        </div>

        {protocol === "oidc" ? (
          <div className="grid gap-3 md:grid-cols-3">
            <div>
              <label className="label">Issuer URL</label>
              <input className="input" name="issuer" required placeholder="https://acme.okta.com" />
            </div>
            <div>
              <label className="label">Client ID</label>
              <input className="input" name="client_id" required />
            </div>
            <div>
              <label className="label">Client secret</label>
              <input className="input" name="client_secret" type="password" required />
            </div>
          </div>
        ) : (
          <div className="grid gap-3">
            <div className="grid gap-3 md:grid-cols-2">
              <div>
                <label className="label">IdP entity ID</label>
                <input className="input" name="idp_entity_id" required />
              </div>
              <div>
                <label className="label">IdP SSO URL</label>
                <input className="input" name="idp_sso_url" required />
              </div>
            </div>
            <div>
              <label className="label">IdP signing certificate (PEM or base64)</label>
              <textarea className="input font-mono text-xs" name="idp_x509_cert" rows={4} required />
            </div>
          </div>
        )}

        <label className="flex items-center gap-2 text-sm">
          <input type="checkbox" name="enforced" />
          Enforce — users on these domains cannot sign in with a password
        </label>
        <button className="btn btn-primary self-start" disabled={create.isPending}>
          Create connection
        </button>
        {create.error && (
          <span className="text-sm text-bad">{(create.error as Error).message}</span>
        )}
      </form>

      <p className="mt-3 text-xs text-muted">
        The issuer&apos;s discovery document fills in the authorization, token, and JWKS endpoints
        automatically on save. For SAML, hand the SP metadata link above to your IdP administrator.
      </p>

      <h2 className="mb-2 mt-8 text-sm font-semibold text-muted">
        SCIM provisioning (PRD §51)
      </h2>
      {scim.isLoading ? (
        <Spinner />
      ) : scim.error ? (
        <ErrorBox error={scim.error} />
      ) : (
        <div className="card flex flex-col gap-3">
          <div className="flex flex-wrap items-center gap-x-6 gap-y-1 text-sm">
            <span>
              Status:{" "}
              <span className={scim.data?.enabled ? "text-good" : "text-muted"}>
                {scim.data?.enabled ? "enabled" : "disabled"}
              </span>
            </span>
            <span className="text-muted">Users: {scim.data?.users ?? 0}</span>
            <span className="text-muted">Groups: {scim.data?.groups ?? 0}</span>
            <span className="text-muted">
              Last request:{" "}
              {scim.data?.last_request_at
                ? new Date(scim.data.last_request_at).toLocaleString()
                : "never"}
            </span>
          </div>

          <div>
            <label className="label">SCIM base URL (give this to your IdP)</label>
            <input className="input font-mono text-xs" readOnly value={scim.data?.scim_base_url ?? ""} />
          </div>

          <div className="flex flex-wrap items-end gap-3">
            <div>
              <label className="label">Default role for provisioned users</label>
              <select
                className="input"
                value={scim.data?.default_role ?? "developer"}
                onChange={(e) =>
                  scimSave.mutate({ enabled: scim.data?.enabled ?? true, default_role: e.target.value })
                }
              >
                {ROLES.map((r) => (
                  <option key={r}>{r}</option>
                ))}
              </select>
            </div>
            <button className="btn btn-primary" onClick={() => scimRotate.mutate()}>
              {scim.data?.token_set ? "Rotate token" : "Enable & generate token"}
            </button>
            {scim.data?.token_set && (
              <button className="btn btn-danger" onClick={() => scimRevoke.mutate()}>
                Revoke token
              </button>
            )}
          </div>

          {scimToken && (
            <div className="rounded-lg border border-accent/40 bg-accent/10 p-3 text-sm">
              <div className="mb-1 font-semibold">Copy this bearer token now — it is shown once.</div>
              <code className="block break-all font-mono text-xs">{scimToken}</code>
            </div>
          )}
          <p className="text-xs text-muted">
            Group names that match a role (e.g. <code>security_admin</code>,{" "}
            <code>AgentGuard Developer</code>) set that member&apos;s role; everyone else gets the
            default. Deactivating a user in your IdP revokes their AgentGuard access.
          </p>
        </div>
      )}
    </>
  );
}
