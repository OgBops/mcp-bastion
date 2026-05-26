"""mcp-bastion CLI."""

from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path

import click

from . import __version__
from .audit import AuditLog
from .http_proxy import HttpProxy, serve_http
from .policy import Policy, PolicyEngine
from .stdio_proxy import StdioProxy

STARTER_POLICY = """\
# mcp-bastion starter policy
# https://github.com/OgBops/mcp-bastion

version: 1

# Tools matching these globs are denied. Returns a JSON-RPC error to the client.
deny_tools:
  - "shell.*"
  - "*.delete_*"

# Regex substitutions applied to all string leaves of tools/call arguments
# before forwarding upstream. Useful for stripping API keys / PII.
redact_args:
  - pattern: 'sk-[A-Za-z0-9]{20,}'
    replacement: '[REDACTED_API_KEY]'
  - pattern: '[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}'
    replacement: '[REDACTED_EMAIL]'

# Tools that require human approval before they execute. v0 returns an
# "approval required" error to the client; v0.2 will add an out-of-band
# approval channel.
require_approval:
  - "filesystem.write_file"
  - "github.create_issue"

# Pin tool descriptions on first sight; alert/block if they change.
# Mitigates tool poisoning ("rug pull") attacks.
tool_description_pinning:
  enabled: true
  on_drift: alert  # alert | block

audit:
  path: ~/.mcp-bastion/audit.sqlite
"""


@click.group()
@click.version_option(version=__version__, prog_name="mcp-bastion")
def main() -> None:
    """Security gateway for the Model Context Protocol."""


@main.command()
@click.option(
    "--out",
    "-o",
    default=None,
    type=click.Path(dir_okay=False, writable=True),
    help="Write the starter policy to this path. Default: stdout.",
)
def init(out: str | None) -> None:
    """Print (or write) a starter policy.yaml."""
    if out:
        Path(out).write_text(STARTER_POLICY)
        click.echo(f"wrote {out}", err=True)
    else:
        click.echo(STARTER_POLICY, nl=False)


@main.command()
@click.option(
    "--policy",
    "-p",
    "policy_path",
    type=click.Path(exists=True, dir_okay=False),
    default=None,
    help="Path to policy.yaml. If omitted, runs with permissive defaults.",
)
@click.option(
    "--upstream",
    default=None,
    help="stdio mode: shell command to spawn the upstream MCP server "
    "(e.g. 'uvx mcp-server-filesystem /tmp').",
)
@click.option(
    "--upstream-url",
    default=None,
    help="HTTP mode: URL of an upstream Streamable HTTP MCP server.",
)
@click.option(
    "--listen",
    default=None,
    help="HTTP mode: host:port to bind on (e.g. '127.0.0.1:8080').",
)
@click.option("--verbose", "-v", is_flag=True, help="Log every decision to stderr.")
def up(
    policy_path: str | None,
    upstream: str | None,
    upstream_url: str | None,
    listen: str | None,
    verbose: bool,
) -> None:
    """Start the proxy. Choose stdio (--upstream) OR http (--upstream-url + --listen)."""
    if (upstream and upstream_url) or (not upstream and not upstream_url):
        raise click.UsageError(
            "Specify exactly one of --upstream (stdio) or --upstream-url (http)."
        )
    if upstream_url and not listen:
        raise click.UsageError("--upstream-url requires --listen host:port.")

    policy = (
        Policy.from_yaml(Path(policy_path)) if policy_path else Policy.from_dict({})
    )
    audit = AuditLog(policy.audit_path)
    engine = PolicyEngine(policy)
    engine.attach_pin_store(audit.conn)

    if upstream:
        proxy = StdioProxy(upstream, engine, audit, verbose=verbose)
        try:
            rc = asyncio.run(proxy.run())
            sys.exit(rc)
        finally:
            audit.close()

    # HTTP mode
    host, _, port_s = listen.partition(":")
    if not port_s:
        raise click.UsageError("--listen must be host:port (use 127.0.0.1:8080)")
    try:
        port = int(port_s)
    except ValueError as e:
        raise click.UsageError(f"--listen port must be integer: {e}") from e
    if not (1 <= port <= 65535):
        raise click.UsageError(f"--listen port out of range: {port}")
    bind_host = host or "127.0.0.1"
    if bind_host in ("0.0.0.0", "::", "*"):
        click.echo(
            f"WARNING: binding to {bind_host} exposes the proxy to the network. "
            "Use 127.0.0.1 unless you've intentionally fronted this with TLS+auth.",
            err=True,
        )
    try:
        proxy = HttpProxy(upstream_url, engine, audit, verbose=verbose)
    except ValueError as e:
        raise click.UsageError(str(e)) from e
    try:
        asyncio.run(serve_http(bind_host, port, proxy))
    finally:
        audit.close()


@main.command()
@click.argument("server_name")
@click.argument("upstream_argv", nargs=-1, required=True)
@click.option(
    "--policy",
    "-p",
    "policy_path",
    type=click.Path(),
    default="~/.mcp-bastion/policy.yaml",
    show_default=True,
    help="Path to policy.yaml that the wrapped server will use.",
)
def wrap(
    server_name: str,
    upstream_argv: tuple[str, ...],
    policy_path: str,
) -> None:
    """Print a Claude Desktop / Cursor / VS Code MCP config snippet that wraps
    an upstream MCP server with mcp-bastion.

    Example:

        mcp-bastion wrap filesystem -- uvx mcp-server-filesystem /tmp

    Then paste the resulting snippet into your client config:
      - Claude Desktop: ~/Library/Application Support/Claude/claude_desktop_config.json
      - Cursor:        ~/.cursor/mcp.json
      - VS Code:       .vscode/mcp.json
    """
    upstream_cmd = " ".join(upstream_argv)
    snippet = {
        "mcpServers": {
            server_name: {
                "command": "mcp-bastion",
                "args": [
                    "up",
                    "--policy",
                    str(Path(policy_path).expanduser()),
                    "--upstream",
                    upstream_cmd,
                ],
            }
        }
    }
    click.echo(json.dumps(snippet, indent=2))


@main.command("inspect-log")
@click.option(
    "--policy",
    "-p",
    "policy_path",
    type=click.Path(exists=True, dir_okay=False),
    default=None,
    help="Path to policy.yaml (used to locate the audit DB). Optional.",
)
@click.option("--limit", default=20, show_default=True, help="Number of rows to show.")
@click.option("--verify", is_flag=True, help="Verify the hash chain before printing.")
def inspect_log(policy_path: str | None, limit: int, verify: bool) -> None:
    """Tail the audit log."""
    policy = (
        Policy.from_yaml(Path(policy_path)) if policy_path else Policy.from_dict({})
    )
    audit = AuditLog(policy.audit_path)
    try:
        if verify:
            ok, broken_seq, msg = audit.verify_chain()
            click.echo(f"chain: {'OK' if ok else 'BROKEN'} ({msg})", err=True)
            if not ok:
                sys.exit(2)
        for row in audit.tail(limit):
            short_payload = row["payload_json"]
            if len(short_payload) > 120:
                short_payload = short_payload[:117] + "..."
            click.echo(
                json.dumps(
                    {
                        "seq": row["seq"],
                        "ts": row["timestamp"],
                        "dir": row["direction"],
                        "method": row["method"],
                        "tool": row["tool_name"],
                        "decision": row["decision_type"],
                        "reason": row["decision_reason"],
                        "payload": short_payload,
                    }
                )
            )
    finally:
        audit.close()


if __name__ == "__main__":
    main()
