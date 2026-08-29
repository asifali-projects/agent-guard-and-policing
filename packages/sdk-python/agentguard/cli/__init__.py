"""`agentguard` command-line interface (PRD §36)."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import click

from .. import __version__
from .. import config as _config
from ..client import Client
from ..exceptions import AgentGuardError

_COMING = {"deploy": 9}


def _client(ctx: click.Context) -> Client:
    cfg = _config.resolve(
        api_key=ctx.obj.get("api_key"),
        base_url=ctx.obj.get("base_url"),
    )
    return Client(api_key=cfg.api_key, base_url=cfg.base_url, timeout=cfg.timeout)


@click.group(context_settings={"help_option_names": ["-h", "--help"]})
@click.version_option(__version__, prog_name="agentguard")
@click.option("--api-key", envvar="AGENTGUARD_API_KEY", help="Override the configured API key.")
@click.option("--base-url", envvar="AGENTGUARD_BASE_URL", help="Override the API base URL.")
@click.pass_context
def main(ctx: click.Context, api_key: str | None, base_url: str | None) -> None:
    """Secure your AI agents from the command line."""
    ctx.obj = {"api_key": api_key, "base_url": base_url}


@main.command()
@click.option("--api-key", prompt="AgentGuard API key", hide_input=True, help="Your ag_* key.")
@click.option("--base-url", default=None, help="API base URL (default http://localhost:8010).")
@click.pass_context
def login(ctx: click.Context, api_key: str, base_url: str | None) -> None:
    """Save credentials to ~/.agentguard/config.toml."""
    cfg = _config.resolve(api_key=api_key, base_url=base_url)
    client = Client(api_key=cfg.api_key, base_url=cfg.base_url, timeout=cfg.timeout)
    try:
        client.get("/v1/agents")  # cheap authenticated probe
    except AgentGuardError as exc:
        raise click.ClickException(f"credentials rejected: {exc}") from exc
    finally:
        client.close()
    path = _config.save({"api_key": api_key, "base_url": cfg.base_url})
    click.echo(f"saved {path}")


@main.command()
@click.option("--agent", prompt="Agent name")
@click.option(
    "--environment",
    type=click.Choice(["development", "staging", "production"]),
    default="development",
    prompt=True,
)
@click.option("--framework", default="custom")
def init(agent: str, environment: str, framework: str) -> None:
    """Write an agentguard.toml in the current directory."""
    target = Path("agentguard.toml")
    if target.exists():
        raise click.ClickException("agentguard.toml already exists")
    target.write_text(
        f'agent = "{agent}"\nenvironment = "{environment}"\nframework = "{framework}"\n',
        encoding="utf-8",
    )
    click.echo(f"wrote {target}")


@main.command()
@click.pass_context
def whoami(ctx: click.Context) -> None:
    """Show the authenticated principal."""
    client = _client(ctx)
    try:
        me = client.get("/v1/auth/me")
        click.echo(f"{me['email']}  org={me['active_organization_id']}")
    except AgentGuardError:
        click.echo("authenticated as an API key")
    finally:
        client.close()


@main.group()
def agents() -> None:
    """Inspect the agent inventory."""


@agents.command("list")
@click.pass_context
def agents_list(ctx: click.Context) -> None:
    client = _client(ctx)
    try:
        rows = client.get("/v1/agents")
    finally:
        client.close()
    if not rows:
        click.echo("no agents")
        return
    width = max(len(r["name"]) for r in rows)
    for r in rows:
        risk = r.get("risk_score")
        click.echo(
            f"{r['name']:<{width}}  {r['environment']:<11}  {r['status']:<9}  "
            f"risk={risk if risk is not None else '-'}"
        )


@main.group()
def policy() -> None:
    """Work with policies."""


@policy.command("validate")
@click.argument("spec_file", type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.pass_context
def policy_validate(ctx: click.Context, spec_file: Path) -> None:
    """Validate a policy spec file (JSON) without saving it."""
    spec = json.loads(spec_file.read_text(encoding="utf-8"))
    if "spec" in spec:
        spec = spec["spec"]
    client = _client(ctx)
    try:
        result = client.post("/v1/policies/validate", json={"spec": spec})
    finally:
        client.close()
    if result["valid"]:
        click.echo(f"OK — {result['rule_count']} rule(s)")
    else:
        for err in result["errors"]:
            click.echo(f"error: {err}", err=True)
        raise SystemExit(1)


@main.command()
@click.pass_context
def scan(ctx: click.Context) -> None:
    """Security posture summary for every agent (PRD §10 first scan)."""
    client = _client(ctx)
    try:
        rows = client.get("/v1/agents")
    finally:
        client.close()
    if not rows:
        click.echo("no agents to scan — run `agentguard init` and connect one")
        return
    hot = [r for r in rows if (r.get("risk_score") or 0) >= 65]
    click.echo(f"{len(rows)} agent(s) scanned; {len(hot)} at high/critical risk")
    for r in sorted(rows, key=lambda x: -(x.get("risk_score") or 0)):
        rs = r.get("risk_score")
        click.echo(f"  {r['name']:<24} risk={rs if rs is not None else '-'}")
    click.echo("\nrun `agentguard redteam run` for an active assessment (Step 6)")


@main.command()
@click.option("--limit", default=20, show_default=True)
@click.option(
    "--decision", type=click.Choice(["allow", "deny", "approval", "redact", "rate_limit"])
)
@click.pass_context
def logs(ctx: click.Context, limit: int, decision: str | None) -> None:
    """Recent audit events."""
    client = _client(ctx)
    params: dict = {"limit": limit}
    if decision:
        params["decision"] = decision
    try:
        rows = client.get("/v1/audit/events", **params)
    finally:
        client.close()
    for e in rows.get("items", rows if isinstance(rows, list) else []):
        click.echo(
            f"{e['occurred_at']}  {e['action']:<22}  {e.get('decision') or '-':<9}  "
            f"{e.get('actor_id') or ''}"
        )


_SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


@main.group()
def redteam() -> None:
    """AI red-team assessments (PRD §18)."""


@redteam.command("run")
@click.option("--agent", envvar="AGENTGUARD_AGENT", help="Target agent name.")
@click.option(
    "--environment",
    type=click.Choice(["development", "staging", "production"]),
    default="production",
    show_default=True,
)
@click.option(
    "--profile",
    type=click.Choice(["quick", "standard", "deep", "enterprise"]),
    default="standard",
    show_default=True,
)
@click.option(
    "--fail-on",
    type=click.Choice(["low", "medium", "high", "critical"]),
    default=None,
    help="Exit non-zero if any open finding is at or above this severity (CI gate).",
)
@click.pass_context
def redteam_run(
    ctx: click.Context, agent: str | None, environment: str, profile: str, fail_on: str | None
) -> None:
    """Launch an assessment and print the result (PRD §21 CI gate)."""
    if not agent:
        raise click.ClickException("--agent is required (or set AGENTGUARD_AGENT)")
    client = _client(ctx)
    try:
        agent_id = client.resolve_agent_id(name=agent, environment=environment)
        a = client.post(
            "/v1/redteam/assessments",
            json={"agent_id": agent_id, "profile": profile, "environment": environment},
        )
        s = a["summary"]
        click.echo(f"{agent}: {s['passed']}/{s['total']} defended, {s['failed']} finding(s)")
        for sev in ("critical", "high", "medium", "low"):
            n = s.get("by_severity", {}).get(sev, 0)
            if n:
                click.echo(f"  {sev:<9} {n}")
        if fail_on:
            findings = client.get("/v1/redteam/findings", agent_id=agent_id, status="open")
            threshold = _SEVERITY_RANK[fail_on]
            blockers = [f for f in findings if _SEVERITY_RANK.get(f["severity"], 0) >= threshold]
            if blockers:
                click.echo(f"\n{len(blockers)} finding(s) at/above {fail_on} — failing.", err=True)
                for f in blockers:
                    click.echo(f"  [{f['severity']}] {f['title']}", err=True)
                raise SystemExit(1)
    finally:
        client.close()


@main.group()
def mcp() -> None:
    """MCP server security (PRD §17)."""


@mcp.command("scan")
@click.option("--server", "server_name", default=None, help="Scan one server by name.")
@click.pass_context
def mcp_scan(ctx: click.Context, server_name: str | None) -> None:
    client = _client(ctx)
    try:
        servers = client.get("/v1/mcp/servers")
        if server_name:
            servers = [s for s in servers if s["name"] == server_name]
            if not servers:
                raise click.ClickException(f"no MCP server named {server_name!r}")
        if not servers:
            click.echo("no MCP servers registered")
            return
        for s in servers:
            result = client.post(f"/v1/mcp/servers/{s['id']}/scan")
            issues = ", ".join(result["issues"]) or "clean"
            click.echo(f"{s['name']:<24} {result['severity']:<9} {result['status']:<16} {issues}")
    finally:
        client.close()


@main.command()
def deploy() -> None:
    """Deploy-time security gate (Step 9)."""
    step = _COMING["deploy"]
    click.echo(f"`agentguard deploy` arrives in Step {step}.", err=True)
    raise SystemExit(2)


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
