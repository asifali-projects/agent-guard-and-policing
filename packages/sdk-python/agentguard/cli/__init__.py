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

_COMING = {"redteam": 6, "mcp": 6, "deploy": 9}


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


def _stub(name: str) -> None:
    step = _COMING[name]
    click.echo(f"`agentguard {name}` is not available yet — arrives in Step {step}.", err=True)
    raise SystemExit(2)


@main.command()
def redteam() -> None:
    """Run a red-team assessment (Step 6)."""
    _stub("redteam")


@main.command()
def mcp() -> None:
    """Scan an MCP server (Step 6)."""
    _stub("mcp")


@main.command()
def deploy() -> None:
    """Deploy-time security gate (Step 9)."""
    _stub("deploy")


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
