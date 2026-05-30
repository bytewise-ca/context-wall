"""ctxfw CLI — analyze, daemon, replay, refresh, init."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import click
import httpx

try:
    from rich.console import Console
    from rich.table import Table
    from rich.syntax import Syntax
    _rich = True
except ImportError:
    _rich = False


console = Console() if _rich else None


def _print(data, output_format: str):
    if output_format == "json":
        click.echo(json.dumps(data, indent=2, default=str))
    elif _rich and console:
        if isinstance(data, str):
            console.print(data)
        else:
            console.print_json(json.dumps(data, default=str))
    else:
        click.echo(json.dumps(data, indent=2, default=str))


@click.group()
@click.option("--config", default="ctxfw.yaml", envvar="CTXFW_CONFIG", help="Config file path")
@click.option("--api-url", default="http://localhost:8080", envvar="CTXFW_API_URL", help="Daemon API URL")
@click.option("--token", envvar="CTXFW_API_TOKEN", help="API token", default="")
@click.option("--output", type=click.Choice(["human", "json"]), default="human", help="Output format")
@click.pass_context
def cli(ctx, config, api_url, token, output):
    """CRE — Context Reliability Engine CLI."""
    ctx.ensure_object(dict)
    ctx.obj["config"] = config
    ctx.obj["api_url"] = api_url.rstrip("/")
    ctx.obj["token"] = token
    ctx.obj["output"] = output


def _headers(ctx) -> dict:
    token = ctx.obj.get("token", "")
    if token:
        return {"Authorization": f"Bearer {token}"}
    return {}


@cli.command()
@click.argument("task")
@click.option("--session-id", default=None, help="Session ID")
@click.option("--repository-root", default=None, help="Repository root path")
@click.option("--trust-cutoff", default=0.30, help="Minimum trust score")
@click.pass_context
def analyze(ctx, task, session_id, repository_root, trust_cutoff):
    """Analyze a task and return ranked candidate files."""
    api_url = ctx.obj["api_url"]
    output = ctx.obj["output"]
    try:
        resp = httpx.post(
            f"{api_url}/analyze",
            json={
                "task": task,
                "session_id": session_id,
                "repository_root": repository_root,
                "options": {"trust_cutoff": trust_cutoff},
            },
            headers=_headers(ctx),
            timeout=35,
        )
        resp.raise_for_status()
        data = resp.json()

        if output == "human" and _rich and console:
            table = Table(title=f"Analysis: {task[:60]}")
            table.add_column("File", style="cyan")
            table.add_column("Trust", style="green")
            table.add_column("Tokens", style="yellow")
            for s in data.get("slices", []):
                table.add_row(s["file_path"], f"{s['trust_score']:.2f}", str(s["token_count"]))
            console.print(table)
            console.print(f"\nTask type: {data.get('task_type')} | Total tokens: {data.get('total_tokens')}")
        else:
            _print(data, output)
    except httpx.HTTPError as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)


@cli.command()
@click.option("--host", default="0.0.0.0", help="Host to bind to")
@click.option("--port", default=None, type=int, help="Port override")
@click.option("--config", "config_path", default="ctxfw.yaml", envvar="CTXFW_CONFIG")
def daemon(host, port, config_path):
    """Start the CRE daemon (API + MCP + background jobs)."""
    import asyncio
    from context_firewall.daemon.main import run_daemon
    from context_firewall.config import load_config

    cfg = load_config(config_path)
    if port:
        cfg.rest_api.port = port

    asyncio.run(run_daemon(cfg, host=host))


@cli.command()
@click.argument("session_id")
@click.option("--request-id", default=None, help="Filter to specific request")
@click.pass_context
def replay(ctx, session_id, request_id):
    """Replay provenance events for a session."""
    api_url = ctx.obj["api_url"]
    output = ctx.obj["output"]
    params = {"session_id": session_id}
    if request_id:
        params["request_id"] = request_id
    try:
        resp = httpx.get(
            f"{api_url}/provenance/replay",
            params=params,
            headers=_headers(ctx),
            timeout=15,
        )
        resp.raise_for_status()
        _print(resp.json(), output)
    except httpx.HTTPError as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)


@cli.command()
@click.argument("files", nargs=-1)
@click.pass_context
def refresh(ctx, files):
    """Trigger incremental graph refresh for changed files."""
    api_url = ctx.obj["api_url"]
    output = ctx.obj["output"]
    file_list = list(files) if files else []

    try:
        resp = httpx.post(
            f"{api_url}/webhook/ci",
            json={"changed_files": file_list, "event": "push"},
            headers=_headers(ctx),
            timeout=10,
        )
        resp.raise_for_status()
        _print({"status": "refresh triggered", "files": file_list}, output)
    except httpx.HTTPError as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)


@cli.group("sources")
def sources_group():
    """Manage source trust registry entries."""


@sources_group.command("add")
@click.option("--id", "source_id", required=True, help="Unique source identifier")
@click.option("--type", "source_type", default="unknown", help="Source type (web, code_repository, api, etc.)")
@click.option("--tier", required=True, type=click.Choice(["internal", "external", "untrusted", "regulated"]), help="Trust tier")
@click.option("--owner", default="", help="Owner team or person")
@click.option("--region", default="", help="Data region (e.g. us-east-1)")
@click.option("--classification", default="", help="Data classification (phi, pii, pci, financial, etc.)")
@click.pass_context
def sources_add(ctx, source_id, source_type, tier, owner, region, classification):
    """Register or update a source in the trust registry."""
    api_url = ctx.obj["api_url"]
    output = ctx.obj["output"]
    try:
        resp = httpx.post(
            f"{api_url}/v1/sources",
            json={
                "id": source_id,
                "type": source_type,
                "trust_tier": tier,
                "owner": owner,
                "region": region,
                "data_classification": classification,
            },
            headers=_headers(ctx),
            timeout=10,
        )
        resp.raise_for_status()
        _print(resp.json(), output)
    except httpx.HTTPError as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)


@sources_group.command("list")
@click.pass_context
def sources_list(ctx):
    """List all registered sources."""
    api_url = ctx.obj["api_url"]
    output = ctx.obj["output"]
    try:
        resp = httpx.get(f"{api_url}/v1/sources", headers=_headers(ctx), timeout=10)
        resp.raise_for_status()
        data = resp.json()
        if output == "human" and _rich and console:
            table = Table(title="Registered Sources")
            table.add_column("ID", style="cyan")
            table.add_column("Type", style="yellow")
            table.add_column("Tier", style="green")
            table.add_column("Owner")
            table.add_column("Classification")
            for s in data.get("sources", []):
                table.add_row(
                    s["id"], s["type"], s["trust_tier"],
                    s.get("owner", ""), s.get("data_classification", ""),
                )
            console.print(table)
        else:
            _print(data, output)
    except httpx.HTTPError as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)


@sources_group.command("get")
@click.argument("source_id")
@click.pass_context
def sources_get(ctx, source_id):
    """Get details for a specific source."""
    api_url = ctx.obj["api_url"]
    output = ctx.obj["output"]
    try:
        resp = httpx.get(f"{api_url}/v1/sources/{source_id}", headers=_headers(ctx), timeout=10)
        resp.raise_for_status()
        _print(resp.json(), output)
    except httpx.HTTPError as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)


@sources_group.command("update")
@click.argument("source_id")
@click.option("--tier", type=click.Choice(["internal", "external", "untrusted", "regulated"]), help="New trust tier")
@click.option("--owner", help="New owner")
@click.option("--region", help="New region")
@click.option("--classification", help="New data classification")
@click.pass_context
def sources_update(ctx, source_id, tier, owner, region, classification):
    """Update fields on an existing source."""
    api_url = ctx.obj["api_url"]
    output = ctx.obj["output"]
    body: dict = {}
    if tier:
        body["trust_tier"] = tier
    if owner is not None:
        body["owner"] = owner
    if region is not None:
        body["region"] = region
    if classification is not None:
        body["data_classification"] = classification
    if not body:
        click.echo("Nothing to update. Provide at least one option.", err=True)
        sys.exit(1)
    try:
        resp = httpx.patch(f"{api_url}/v1/sources/{source_id}", json=body, headers=_headers(ctx), timeout=10)
        resp.raise_for_status()
        _print(resp.json(), output)
    except httpx.HTTPError as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)


@sources_group.command("remove")
@click.argument("source_id")
@click.option("--confirm", is_flag=True, help="Skip confirmation prompt")
@click.pass_context
def sources_remove(ctx, source_id, confirm):
    """Soft-delete a source from the registry."""
    api_url = ctx.obj["api_url"]
    output = ctx.obj["output"]
    if not confirm:
        click.confirm(f"Remove source '{source_id}'?", abort=True)
    try:
        resp = httpx.delete(f"{api_url}/v1/sources/{source_id}", headers=_headers(ctx), timeout=10)
        resp.raise_for_status()
        _print(resp.json(), output)
    except httpx.HTTPError as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)


@cli.group("policy")
def policy_group():
    """Policy management — validate and inspect policy files."""


@policy_group.command("validate")
@click.argument("path")
def policy_validate(path):
    """Validate a policy YAML file or directory.

    Exits 0 on success. Reports errors with context.
    """
    import yaml as _yaml
    from context_firewall.policy.dsl.evaluator import validate_policy_file

    target = Path(path)
    files = list(target.glob("*.yaml")) + list(target.glob("*.yml")) if target.is_dir() else [target]

    total_errors = 0
    for f in files:
        try:
            raw = _yaml.safe_load(f.read_text()) or {}
            errors = validate_policy_file(raw)
            if errors:
                click.echo(f"ERRORS in {f}:", err=True)
                for e in errors:
                    click.echo(f"  {e}", err=True)
                total_errors += len(errors)
            else:
                click.echo(f"OK: {f} ({len(raw.get('rules', []))} rules)")
        except Exception as e:
            click.echo(f"ERROR reading {f}: {e}", err=True)
            total_errors += 1

    if total_errors:
        sys.exit(1)
    click.echo(f"All {len(files)} file(s) valid.")


@cli.group("compliance")
def compliance_group():
    """Compliance export — generate and verify signed audit bundles."""


@compliance_group.command("export")
@click.option("--session", "session_id", default=None, help="Export a specific session")
@click.option("--from", "from_ts", default=None, help="Start timestamp (ISO 8601)")
@click.option("--to", "to_ts", default=None, help="End timestamp (ISO 8601)")
@click.option("--framework", default=None, type=click.Choice(["hipaa", "soc2", "fedramp"]), help="Filter by framework")
@click.option("--out", default=None, help="Output file path (default: stdout)")
@click.pass_context
def compliance_export(ctx, session_id, from_ts, to_ts, framework, out):
    """Export a signed compliance bundle."""
    api_url = ctx.obj["api_url"]
    body: dict = {}
    if session_id:
        endpoint = f"{api_url}/v1/compliance/export/{session_id}"
        params: dict = {}
        if framework:
            params["framework"] = framework
        try:
            resp = httpx.get(endpoint, params=params, headers=_headers(ctx), timeout=30)
        except httpx.HTTPError as e:
            click.echo(f"Error: {e}", err=True)
            sys.exit(1)
    else:
        if from_ts:
            body["from_ts"] = from_ts
        if to_ts:
            body["to_ts"] = to_ts
        if framework:
            body["framework"] = framework
        try:
            resp = httpx.post(f"{api_url}/v1/compliance/export", json=body, headers=_headers(ctx), timeout=30)
        except httpx.HTTPError as e:
            click.echo(f"Error: {e}", err=True)
            sys.exit(1)

    try:
        resp.raise_for_status()
    except httpx.HTTPStatusError as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)

    bundle_json = json.dumps(resp.json(), indent=2)
    if out:
        Path(out).write_text(bundle_json)
        click.echo(f"Bundle written to {out}")
    else:
        click.echo(bundle_json)


@compliance_group.command("verify")
@click.argument("bundle_file")
@click.pass_context
def compliance_verify(ctx, bundle_file):
    """Verify a compliance bundle file."""
    api_url = ctx.obj["api_url"]
    try:
        bundle = json.loads(Path(bundle_file).read_text())
    except Exception as e:
        click.echo(f"Error reading bundle: {e}", err=True)
        sys.exit(1)
    try:
        resp = httpx.post(f"{api_url}/v1/compliance/verify", json=bundle, headers=_headers(ctx), timeout=15)
        resp.raise_for_status()
        data = resp.json()
    except httpx.HTTPError as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)

    if data.get("valid"):
        click.echo(f"VALID — {data.get('message', 'chain intact, signature verified')}")
        sys.exit(0)
    else:
        click.echo(f"INVALID — {data.get('message', 'verification failed')}", err=True)
        sys.exit(1)


@cli.group("keys")
def keys_group():
    """Manage tenant signing keypair for compliance bundle signatures."""


@keys_group.command("generate")
@click.option("--key-dir", default=".ctxfw/keys", help="Directory to write keys")
def keys_generate(key_dir):
    """Generate an Ed25519 signing keypair."""
    from context_firewall.compliance.keys import generate_keypair
    _, pub_pem = generate_keypair(Path(key_dir))
    click.echo(f"Keypair generated in {key_dir}")
    click.echo(f"Public key:\n{pub_pem}")


@keys_group.command("export-public")
@click.option("--key-dir", default=".ctxfw/keys", help="Directory containing keys")
def keys_export_public(key_dir):
    """Print the public key PEM."""
    from context_firewall.compliance.keys import load_public_key_pem
    pem = load_public_key_pem(Path(key_dir))
    if not pem:
        click.echo("No public key found. Run 'ctxfw keys generate' first.", err=True)
        sys.exit(1)
    click.echo(pem)


@cli.command("init")
@click.option("--force", is_flag=True, help="Overwrite existing config")
def init_cmd(force):
    """Initialize CRE in the current directory."""
    config_path = Path("ctxfw.yaml")
    policy_dir = Path(".ctxfw/policies")
    policy_dir.mkdir(parents=True, exist_ok=True)
    db_dir = Path(".ctxfw")
    db_dir.mkdir(exist_ok=True)

    if config_path.exists() and not force:
        click.echo("ctxfw.yaml already exists. Use --force to overwrite.")
        sys.exit(1)

    config_path.write_text(
        "# CRE configuration\n"
        "repository_root: .\n\n"
        "rest_api:\n"
        "  port: 8080\n"
        "  auth:\n"
        "    enabled: false\n\n"
        "mcp:\n"
        "  transport: stdio\n\n"
        "graph:\n"
        "  max_depth: 4\n"
        "  max_nodes: 50\n"
        "  trust_cutoff: 0.30\n\n"
        "storage:\n"
        "  db_path: .ctxfw/cre.db\n\n"
        "# Compliance configuration (Phase 2)\n"
        "# compliance_hmac_key: change-this-to-a-random-secret\n"
        "# compliance_baa_mode: false   # set true for HIPAA BAA deployments\n"
        "# compliance_packs:\n"
        "#   - hipaa\n"
        "#   - soc2\n"
        "#   - fedramp\n\n"
        "# Policy DSL — four-layer hierarchy (Phase 3)\n"
        "# Place policy YAML files in subdirectories of the policy_dir:\n"
        "#   .ctxfw/policies/fleet/   — tenant-wide, deny-wins (highest priority)\n"
        "#   .ctxfw/policies/org/     — organization-wide\n"
        "#   .ctxfw/policies/team/    — team-level\n"
        "#   .ctxfw/policies/repo/    — repository-level (lowest priority)\n"
        "# Flat policy files in policy_dir/ continue to work unchanged.\n"
        "# Validate with: ctxfw policy validate .ctxfw/policies/\n"
    )

    default_policy = Path(".ctxfw/policies/default.yaml")
    if not default_policy.exists():
        default_policy.write_text(
            "# Default CRE policy\n"
            "rules:\n"
            "  - name: block_secrets\n"
            "    scope: content\n"
            "    detector: secret\n"
            "    action: exclude\n"
            "    reason: secret pattern detected\n"
            "  - name: redact_pii\n"
            "    scope: content\n"
            "    detector: pii\n"
            "    action: redact\n"
            "    reason: PII pattern detected\n"
            "denied_paths: []\n"
        )

    click.echo("CRE initialized.")
    click.echo("  Config: ctxfw.yaml")
    click.echo("  Policy: .ctxfw/policies/default.yaml")
    click.echo("  Database: .ctxfw/cre.db (created on first run)")
    click.echo("\nStart the daemon with: ctxfwd")
