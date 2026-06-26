"""ThreatSentinel CLI — Typer-based command-line interface.

Entry point registered in pyproject.toml as 'threatsentinel'.
All async work is dispatched via asyncio.run() from sync Typer callbacks.
"""

from __future__ import annotations

import asyncio
import sys
from datetime import datetime
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt
from rich.table import Table
from rich import box

from threatsentinel import __version__
from threatsentinel.analyzers.campaign_correlator import correlate_campaign
from threatsentinel.analyzers.deduplicator import deduplicate_techniques
from threatsentinel.analyzers.mitre_mapper import map_ttps
from threatsentinel.analyzers.risk_scorer import calculate_risk_score
from threatsentinel.enrichers import run_enrichment_pipeline
from threatsentinel.ioc_parser import parse_file, parse_ioc
from threatsentinel.logging_config import configure_logging, get_logger
from threatsentinel.models import (
    BulkResult,
    CaseStatus,
    Disposition,
    IOCType,
    InvestigationResult,
    Severity,
)
from threatsentinel.reporters import FORMATS, render_bulk, render_single, write_output
from threatsentinel.reporters.terminal import console
from threatsentinel.state import get_config
from threatsentinel.storage.case_db import CaseDB
from threatsentinel.suppression import load_baseline

logger = get_logger(__name__)

# ---------------------------------------------------------------------------
# Typer app instances
# ---------------------------------------------------------------------------

app = typer.Typer(
    name="threatsentinel",
    help="🛡️  ThreatSentinel — Automated Multi-Source IOC Investigation & Threat Intelligence Platform",
    add_completion=False,
    rich_markup_mode="rich",
    pretty_exceptions_enable=True,
)

case_app = typer.Typer(help="Manage named investigation cases.")
baseline_app = typer.Typer(help="Manage the false-positive suppression baseline.")

app.add_typer(case_app, name="case")
app.add_typer(baseline_app, name="baseline")


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------


def _version_callback(value: bool) -> None:
    if value:
        console.print(f"ThreatSentinel [cyan]v{__version__}[/cyan]")
        raise typer.Exit()


def _get_db() -> CaseDB:
    cfg = get_config()
    return CaseDB(cfg.db_path)


async def _investigate(
    ioc_value: str,
    skip_greynoise: bool = False,
    no_cache: bool = False,
) -> InvestigationResult:
    """Core async investigation pipeline for a single IOC."""
    cfg = get_config()
    ioc = parse_ioc(ioc_value)

    if ioc.ioc_type == IOCType.UNKNOWN:
        console.print(f"[red]Cannot classify IOC:[/red] [bold]{ioc_value}[/bold]")
        raise typer.Exit(code=1)

    # Check suppression baseline
    baseline = load_baseline(cfg.baseline_path)
    suppressed, reason = baseline.is_suppressed(ioc.value)

    if suppressed:
        result = InvestigationResult(
            ioc=ioc,
            risk_score=0,
            risk_label=Severity.INFORMATIONAL,
            recommendation=f"Suppressed: {reason}",
            suppressed=True,
        )
        return result

    # Run parallel enrichment
    bundle = await run_enrichment_pipeline(ioc, cfg, skip_greynoise=skip_greynoise)

    # Post-enrichment analysis
    risk_score, risk_label, recommendation = calculate_risk_score(bundle)
    techniques = deduplicate_techniques(map_ttps(bundle))
    campaign = correlate_campaign(bundle)

    result = InvestigationResult(
        ioc=ioc,
        risk_score=risk_score,
        risk_label=risk_label,
        recommendation=recommendation,
        enrichment=bundle,
        mitre_techniques=techniques,
        campaign=campaign,
        investigated_at=datetime.utcnow(),
    )
    return result


# ---------------------------------------------------------------------------
# Root options
# ---------------------------------------------------------------------------

@app.callback()
def main(
    version: Optional[bool] = typer.Option(
        None,
        "--version",
        "-V",
        callback=_version_callback,
        is_eager=True,
        help="Show version and exit.",
    ),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Enable DEBUG logging."),
) -> None:
    cfg = get_config()
    log_level = "DEBUG" if verbose else cfg.ts_log_level
    configure_logging(log_level)


# ---------------------------------------------------------------------------
# threatsentinel scan
# ---------------------------------------------------------------------------

@app.command("scan")
def scan(
    ioc: str = typer.Argument(..., help="IOC to investigate (IP, domain, URL, hash, email)."),
    fmt: str = typer.Option(
        "terminal",
        "--format",
        "-f",
        help=f"Output format. Options: {', '.join(FORMATS)}",
    ),
    output: Optional[Path] = typer.Option(
        None, "--output", "-o", help="Write report to file (default: stdout)."
    ),
    case: Optional[str] = typer.Option(None, "--case", "-c", help="Associate with a named case."),
    no_cache: bool = typer.Option(False, "--no-cache", help="Bypass cached results."),
    no_greynoise: bool = typer.Option(False, "--no-greynoise", help="Skip GreyNoise (saves quota)."),
    quiet: bool = typer.Option(False, "--quiet", "-q", help="Suppress progress spinners."),
) -> None:
    """Investigate a single indicator of compromise."""

    async def _run() -> InvestigationResult:
        if not quiet and fmt == "terminal":
            with console.status(f"[cyan]Investigating [bold]{ioc}[/bold]…"):
                return await _investigate(ioc, skip_greynoise=no_greynoise, no_cache=no_cache)
        return await _investigate(ioc, skip_greynoise=no_greynoise, no_cache=no_cache)

    result = asyncio.run(_run())
    result.case_name = case

    # Persist to case if specified
    if case:
        async def _save() -> None:
            db = _get_db()
            await db.init_db()
            await db.upsert_ioc(case, result)

        asyncio.run(_save())

    # Render output
    rendered = render_single(result, fmt)

    if rendered is not None:
        if output:
            write_output(rendered, output, fmt)
            console.print(f"[green]Report written to[/green] [bold]{output}[/bold]")
        else:
            print(rendered)

    # Exit with non-zero code for CRITICAL/HIGH findings (useful in CI)
    if result.risk_label in (Severity.CRITICAL, Severity.HIGH):
        raise typer.Exit(code=2)


# ---------------------------------------------------------------------------
# threatsentinel bulk
# ---------------------------------------------------------------------------

@app.command("bulk")
def bulk(
    file: Path = typer.Argument(..., help="Path to .txt or .csv file with one IOC per line."),
    fmt: str = typer.Option("terminal", "--format", "-f", help=f"Output format: {', '.join(FORMATS)}"),
    output: Optional[Path] = typer.Option(None, "--output", "-o", help="Write report to file."),
    case: Optional[str] = typer.Option(None, "--case", "-c", help="Associate all IOCs with this case."),
    concurrency: int = typer.Option(5, "--concurrency", min=1, max=20, help="Max parallel investigations."),
    delay: float = typer.Option(1.0, "--delay", help="Seconds between batches."),
    stop_on_critical: bool = typer.Option(
        False, "--stop-on-critical", help="Halt immediately on first CRITICAL finding."
    ),
    no_greynoise: bool = typer.Option(False, "--no-greynoise", help="Skip GreyNoise for all IOCs."),
) -> None:
    """Investigate multiple IOCs from a .txt or .csv file."""

    if not file.exists():
        console.print(f"[red]File not found:[/red] {file}")
        raise typer.Exit(code=1)

    ioc_records = parse_file(file)
    if not ioc_records:
        console.print("[yellow]No valid IOCs found in file.[/yellow]")
        raise typer.Exit(code=0)

    console.print(
        f"[cyan]Investigating [bold]{len(ioc_records)}[/bold] IOCs "
        f"with concurrency=[bold]{concurrency}[/bold]…[/cyan]"
    )

    bulk_result = BulkResult(case_name=case)
    semaphore = asyncio.Semaphore(concurrency)
    critical_found = False

    async def _investigate_one(ioc_record) -> InvestigationResult:
        async with semaphore:
            result = await _investigate(
                ioc_record.value, skip_greynoise=no_greynoise
            )
            result.case_name = case
            return result

    async def _run_all() -> None:
        nonlocal critical_found
        cfg = get_config()
        db = _get_db() if case else None
        if db:
            await db.init_db()

        # Process in batches
        batch_size = concurrency
        for batch_start in range(0, len(ioc_records), batch_size):
            batch = ioc_records[batch_start: batch_start + batch_size]

            tasks = [_investigate_one(ioc) for ioc in batch]
            results = await asyncio.gather(*tasks, return_exceptions=True)

            for r in results:
                if isinstance(r, Exception):
                    console.print(f"[red]Error during investigation: {r}[/red]")
                    bulk_result.error_count = getattr(bulk_result, "error_count", 0) + 1
                    continue

                bulk_result.results.append(r)

                if db:
                    await db.upsert_ioc(case, r)

                if r.risk_label == Severity.CRITICAL:
                    critical_found = True
                    console.print(
                        f"[bold red]⚠  CRITICAL:[/bold red] [bold]{r.ioc.value}[/bold] "
                        f"(score={r.risk_score})"
                    )
                    if stop_on_critical:
                        console.print("[red]--stop-on-critical triggered. Halting.[/red]")
                        return

            # Rate-limit delay between batches
            if batch_start + batch_size < len(ioc_records) and delay > 0:
                await asyncio.sleep(delay)

        bulk_result.tally()

    asyncio.run(_run_all())
    bulk_result.tally()

    rendered = render_bulk(bulk_result, fmt)

    if rendered is not None:
        if output:
            write_output(rendered, output, fmt)
            console.print(f"[green]Report written to[/green] [bold]{output}[/bold]")
        else:
            print(rendered)

    if critical_found:
        raise typer.Exit(code=2)


# ---------------------------------------------------------------------------
# threatsentinel case sub-commands
# ---------------------------------------------------------------------------

@case_app.command("create")
def case_create(
    name: str = typer.Option(..., "--name", "-n", help="Case name (unique identifier)."),
    description: str = typer.Option("", "--description", "-d", help="Case description."),
) -> None:
    """Create a new investigation case."""

    async def _run() -> None:
        db = _get_db()
        await db.init_db()
        case_id = await db.create_case(name, description)
        console.print(f"[green]✓[/green] Case [bold]{name!r}[/bold] created (id={case_id})")

    asyncio.run(_run())


@case_app.command("list")
def case_list() -> None:
    """List all investigation cases."""

    async def _run() -> None:
        db = _get_db()
        await db.init_db()
        cases = await db.list_cases()
        if not cases:
            console.print("[dim]No cases found. Create one with: threatsentinel case create[/dim]")
            return

        t = Table(box=box.ROUNDED, header_style="bold cyan")
        t.add_column("Name", min_width=24)
        t.add_column("Status", min_width=12)
        t.add_column("IOCs", justify="right")
        t.add_column("Description")
        t.add_column("Updated")

        for c in cases:
            status_color = {"open": "green", "in-progress": "yellow", "closed": "dim"}.get(
                c["status"], "white"
            )
            t.add_row(
                f"[bold]{c['name']}[/bold]",
                f"[{status_color}]{c['status']}[/{status_color}]",
                str(c.get("ioc_count", 0)),
                c.get("description", "")[:60],
                c["updated_at"][:16],
            )
        console.print(t)

    asyncio.run(_run())


@case_app.command("view")
def case_view(
    name: str = typer.Argument(..., help="Case name to view."),
) -> None:
    """View a case and all its IOC records."""

    async def _run() -> None:
        db = _get_db()
        await db.init_db()
        case = await db.get_case(name)
        if not case:
            console.print(f"[red]Case not found:[/red] {name!r}")
            raise typer.Exit(code=1)

        console.print(Panel(
            f"[bold]{case['name']}[/bold]\n"
            f"Status: [cyan]{case['status']}[/cyan]\n"
            f"Description: {case.get('description', '') or '—'}\n"
            f"Created: {case['created_at'][:16]}  Updated: {case['updated_at'][:16]}",
            title="Case Details",
            border_style="cyan",
        ))

        iocs = await db.get_case_iocs(name)
        if not iocs:
            console.print("[dim]No IOCs in this case yet.[/dim]")
            return

        t = Table(box=box.ROUNDED, header_style="bold cyan")
        t.add_column("IOC", min_width=30)
        t.add_column("Type", min_width=8)
        t.add_column("Score", justify="right")
        t.add_column("Severity", min_width=14)
        t.add_column("Disposition", min_width=14)
        t.add_column("Note")

        for ioc in iocs:
            label = ioc["risk_label"]
            colors = {
                "CRITICAL": "red", "HIGH": "red", "MEDIUM": "yellow",
                "LOW": "green", "INFORMATIONAL": "cyan",
            }
            color = colors.get(label, "white")
            t.add_row(
                ioc["value"],
                ioc["ioc_type"],
                f"[{color}]{ioc['risk_score']}[/{color}]",
                f"[{color}]{label}[/{color}]",
                ioc.get("disposition", "new"),
                (ioc.get("analyst_note") or "")[:40],
            )
        console.print(t)

    asyncio.run(_run())


@case_app.command("update")
def case_update(
    name: str = typer.Argument(..., help="Case name."),
    ioc: str = typer.Option(..., "--ioc", help="IOC value to update."),
    disposition: str = typer.Option(
        ...,
        "--disposition",
        help="new | investigating | blocked | false-positive | escalated | closed",
    ),
) -> None:
    """Update the disposition of an IOC within a case."""

    try:
        disp = Disposition(disposition)
    except ValueError:
        console.print(f"[red]Invalid disposition:[/red] {disposition!r}")
        raise typer.Exit(code=1)

    async def _run() -> None:
        db = _get_db()
        await db.init_db()
        ok = await db.update_disposition(name, ioc, disp)
        if ok:
            console.print(f"[green]✓[/green] Updated [bold]{ioc}[/bold] → [cyan]{disp.value}[/cyan]")
        else:
            console.print(f"[red]IOC not found in case {name!r}:[/red] {ioc}")

    asyncio.run(_run())


@case_app.command("note")
def case_note(
    name: str = typer.Argument(..., help="Case name."),
    text: str = typer.Option(..., "--text", "-t", help="Note text to add."),
) -> None:
    """Add a note to a case."""

    async def _run() -> None:
        db = _get_db()
        await db.init_db()
        await db.add_note(name, text)
        console.print(f"[green]✓[/green] Note added to case [bold]{name!r}[/bold]")

    asyncio.run(_run())


@case_app.command("close")
def case_close(
    name: str = typer.Argument(..., help="Case name to close."),
) -> None:
    """Close a case."""

    async def _run() -> None:
        db = _get_db()
        await db.init_db()
        ok = await db.update_case_status(name, CaseStatus.CLOSED)
        if ok:
            console.print(f"[green]✓[/green] Case [bold]{name!r}[/bold] closed.")
        else:
            console.print(f"[red]Case not found:[/red] {name!r}")

    asyncio.run(_run())


@case_app.command("export")
def case_export(
    name: str = typer.Argument(..., help="Case name to export."),
    fmt: str = typer.Option("markdown", "--format", "-f", help="Output format."),
    output: Optional[Path] = typer.Option(None, "--output", "-o", help="Output file path."),
) -> None:
    """Export a full case report."""

    async def _run() -> None:
        db = _get_db()
        await db.init_db()
        iocs = await db.get_case_iocs(name)

        if not iocs:
            console.print(f"[yellow]No IOCs found in case {name!r}[/yellow]")
            return

        import json as _json
        results: list[InvestigationResult] = []
        for ioc_row in iocs:
            from threatsentinel.ioc_parser import parse_ioc as _parse
            from threatsentinel.models import (
                EnrichmentBundle, IOCType, MITRETechnique, Severity
            )
            ioc_record = _parse(ioc_row["value"])
            try:
                enrichment = EnrichmentBundle.model_validate(
                    _json.loads(ioc_row.get("enrichment_json", "{}"))
                )
            except Exception:
                enrichment = EnrichmentBundle()

            try:
                mitre_raw = _json.loads(ioc_row.get("mitre_json", "[]"))
                techniques = [MITRETechnique.model_validate(t) for t in mitre_raw]
            except Exception:
                techniques = []

            results.append(
                InvestigationResult(
                    ioc=ioc_record,
                    risk_score=ioc_row["risk_score"],
                    risk_label=Severity(ioc_row["risk_label"]),
                    recommendation="",
                    enrichment=enrichment,
                    mitre_techniques=techniques,
                    campaign=ioc_row.get("campaign"),
                    case_name=name,
                )
            )

        bulk_result = BulkResult(results=results, case_name=name)
        bulk_result.tally()
        rendered = render_bulk(bulk_result, fmt)

        if rendered:
            if output:
                write_output(rendered, output, fmt)
                console.print(f"[green]Exported to[/green] [bold]{output}[/bold]")
            else:
                print(rendered)

    asyncio.run(_run())


@case_app.command("delete")
def case_delete(
    name: str = typer.Argument(..., help="Case name to delete."),
    confirm: bool = typer.Option(False, "--confirm", help="Confirm deletion without prompt."),
) -> None:
    """Permanently delete a case and all its records."""

    if not confirm:
        answer = Prompt.ask(
            f"[yellow]Delete case [bold]{name!r}[/bold] and all its IOC records? (yes/no)[/yellow]"
        )
        if answer.lower() not in ("yes", "y"):
            console.print("[dim]Aborted.[/dim]")
            return

    async def _run() -> None:
        db = _get_db()
        await db.init_db()
        ok = await db.delete_case(name)
        if ok:
            console.print(f"[green]✓[/green] Case [bold]{name!r}[/bold] deleted.")
        else:
            console.print(f"[red]Case not found:[/red] {name!r}")

    asyncio.run(_run())


# ---------------------------------------------------------------------------
# threatsentinel hunt
# ---------------------------------------------------------------------------

@app.command("hunt")
def hunt(
    ttp: Optional[str] = typer.Option(None, "--ttp", help="ATT&CK technique ID (e.g. T1090.003)."),
    actor: Optional[str] = typer.Option(None, "--actor", help="Threat actor name to search for."),
    min_risk: Optional[int] = typer.Option(None, "--min-risk", min=0, max=100, help="Minimum risk score."),
    after: Optional[str] = typer.Option(None, "--after", help="Start date (YYYY-MM-DD)."),
    before: Optional[str] = typer.Option(None, "--before", help="End date (YYYY-MM-DD)."),
    fmt: str = typer.Option("terminal", "--format", "-f", help="Output format."),
    output: Optional[Path] = typer.Option(None, "--output", "-o", help="Write results to file."),
) -> None:
    """Search the local case database for IOCs matching criteria."""

    if not any([ttp, actor, min_risk is not None, after, before]):
        console.print("[red]Provide at least one filter: --ttp, --actor, --min-risk, --after/--before[/red]")
        raise typer.Exit(code=1)

    async def _run() -> None:
        db = _get_db()
        await db.init_db()
        rows: list[dict] = []

        if ttp:
            rows = await db.hunt_by_ttp(ttp)
        elif actor:
            rows = await db.hunt_by_actor(actor)
        elif min_risk is not None:
            rows = await db.hunt_by_min_risk(min_risk)
        elif after and before:
            rows = await db.hunt_by_date_range(after, before)

        if not rows:
            console.print("[yellow]No matching IOCs found in local case database.[/yellow]")
            return

        t = Table(
            title=f"Hunt Results ({len(rows)} IOC{'s' if len(rows) != 1 else ''})",
            box=box.ROUNDED,
            header_style="bold magenta",
        )
        t.add_column("IOC", min_width=28)
        t.add_column("Type", min_width=8)
        t.add_column("Score", justify="right")
        t.add_column("Label", min_width=14)
        t.add_column("Case", min_width=18)
        t.add_column("Campaign")
        t.add_column("Last Seen")

        for row in sorted(rows, key=lambda r: r.get("risk_score", 0), reverse=True):
            label = row.get("risk_label", "INFORMATIONAL")
            colors = {
                "CRITICAL": "red", "HIGH": "red", "MEDIUM": "yellow",
                "LOW": "green", "INFORMATIONAL": "cyan",
            }
            color = colors.get(label, "white")
            t.add_row(
                row.get("value", ""),
                row.get("ioc_type", ""),
                f"[{color}]{row.get('risk_score', 0)}[/{color}]",
                f"[{color}]{label}[/{color}]",
                row.get("case_name", ""),
                row.get("campaign") or "—",
                (row.get("last_investigated") or "")[:16],
            )
        console.print(t)

    asyncio.run(_run())


# ---------------------------------------------------------------------------
# threatsentinel baseline sub-commands
# ---------------------------------------------------------------------------

@baseline_app.command("add")
def baseline_add(
    ioc_value: str = typer.Argument(..., help="IOC or glob pattern to suppress."),
    reason: str = typer.Option("", "--reason", "-r", help="Reason for suppression."),
    added_by: str = typer.Option("", "--added-by", help="Analyst identifier."),
) -> None:
    """Add an IOC to the suppression baseline."""
    cfg = get_config()
    baseline = load_baseline(cfg.baseline_path)
    baseline.add_rule(ioc_value, reason, added_by)
    baseline.save(cfg.baseline_path)
    console.print(
        f"[green]✓[/green] Added [bold]{ioc_value!r}[/bold] to baseline "
        f"({'[dim]' + reason + '[/dim]' if reason else 'no reason given'})"
    )


@baseline_app.command("list")
def baseline_list() -> None:
    """List all suppression rules."""
    cfg = get_config()
    baseline = load_baseline(cfg.baseline_path)

    if not baseline.rules:
        console.print("[dim]No suppression rules configured.[/dim]")
        return

    t = Table(box=box.ROUNDED, header_style="bold cyan")
    t.add_column("IOC / Pattern", min_width=30)
    t.add_column("Reason")
    t.add_column("Added By")
    t.add_column("Added At")

    for rule in baseline.rules:
        t.add_row(
            f"[bold]{rule.ioc}[/bold]",
            rule.reason or "—",
            rule.added_by or "—",
            rule.added_at[:16] if rule.added_at else "—",
        )
    console.print(t)
    console.print(f"\n[dim]Baseline file: {cfg.baseline_path}[/dim]")


@baseline_app.command("remove")
def baseline_remove(
    ioc_value: str = typer.Argument(..., help="IOC value to remove from baseline."),
) -> None:
    """Remove an IOC from the suppression baseline."""
    cfg = get_config()
    baseline = load_baseline(cfg.baseline_path)
    if baseline.remove_rule(ioc_value):
        baseline.save(cfg.baseline_path)
        console.print(f"[green]✓[/green] Removed [bold]{ioc_value!r}[/bold] from baseline")
    else:
        console.print(f"[yellow]Not found in baseline:[/yellow] {ioc_value!r}")


@baseline_app.command("check")
def baseline_check(
    ioc_value: str = typer.Argument(..., help="IOC value to check against baseline."),
) -> None:
    """Check whether an IOC would be suppressed (dry-run)."""
    cfg = get_config()
    baseline = load_baseline(cfg.baseline_path)
    suppressed, reason = baseline.is_suppressed(ioc_value)
    if suppressed:
        console.print(
            f"[yellow]⊘ SUPPRESSED[/yellow]  [bold]{ioc_value}[/bold] — {reason or 'no reason given'}"
        )
    else:
        console.print(f"[green]✓ NOT suppressed[/green]  [bold]{ioc_value}[/bold] — would be investigated normally")


# ---------------------------------------------------------------------------
# threatsentinel setup
# ---------------------------------------------------------------------------

@app.command("setup")
def setup(
    update_attack: bool = typer.Option(False, "--update-attack", help="Download/update local ATT&CK bundle."),
    test_connections: bool = typer.Option(False, "--test-connections", help="Test API connectivity."),
    show_config: bool = typer.Option(False, "--show-config", help="Show current config (masked)."),
) -> None:
    """First-time configuration wizard and connection tester."""

    cfg = get_config()

    if show_config:
        t = Table(title="Current Configuration", box=box.ROUNDED, header_style="bold cyan")
        t.add_column("Setting", min_width=28)
        t.add_column("Value")
        for k, v in cfg.masked().items():
            style = "dim" if v in ("(not set)", "") else ""
            t.add_row(k, f"[{style}]{v}[/{style}]")
        console.print(t)
        return

    if update_attack:
        console.print("[cyan]Downloading MITRE ATT&CK Enterprise bundle (may take 30–60s)…[/cyan]")
        import urllib.request

        url = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
        attack_path = cfg.attack_bundle_path
        attack_path.parent.mkdir(parents=True, exist_ok=True)
        try:
            urllib.request.urlretrieve(url, str(attack_path))
            console.print(f"[green]✓[/green] ATT&CK bundle saved to {attack_path}")
        except Exception as exc:
            console.print(f"[red]Failed to download ATT&CK bundle: {exc}[/red]")
        return

    if test_connections:
        console.print("[cyan]Testing API connections…[/cyan]\n")

        async def _test() -> None:
            import httpx

            tests = [
                ("VirusTotal", "https://www.virustotal.com/api/v3/metadata",
                 {"x-apikey": cfg.virustotal_api_key}),
                ("AbuseIPDB", "https://api.abuseipdb.com/api/v2/check?ipAddress=1.1.1.1&maxAgeInDays=1",
                 {"Key": cfg.abuseipdb_api_key}),
                ("AlienVault OTX", "https://otx.alienvault.com/api/v1/user/me",
                 {"X-OTX-API-KEY": cfg.otx_api_key}),
                ("GreyNoise", "https://api.greynoise.io/ping", {}),
                ("URLhaus (no key)", "https://urlhaus-api.abuse.ch/v1/urls/recent/", {}),
                ("MalwareBazaar (no key)", "https://mb-api.abuse.ch/api/v1/", {}),
            ]

            async with httpx.AsyncClient(timeout=10.0) as client:
                for name, url, headers in tests:
                    try:
                        resp = await client.get(url, headers=headers)
                        if resp.status_code in (200, 401, 403, 404):
                            icon = "✓" if resp.status_code == 200 else "⚠"
                            color = "green" if resp.status_code == 200 else "yellow"
                            console.print(
                                f"  [{color}]{icon}[/{color}] {name}: HTTP {resp.status_code}"
                            )
                        else:
                            console.print(f"  [red]✗[/red] {name}: HTTP {resp.status_code}")
                    except Exception as exc:
                        console.print(f"  [red]✗[/red] {name}: {exc}")

        asyncio.run(_test())
        return

    # Interactive setup wizard
    console.print(
        Panel(
            "[bold cyan]ThreatSentinel Setup Wizard[/bold cyan]\n\n"
            "This wizard will help you configure your API keys.\n"
            "All keys are stored in your [bold].env[/bold] file — "
            "never committed to git.\n\n"
            "Get free API keys from:\n"
            "  • VirusTotal: https://www.virustotal.com/gui/join-us\n"
            "  • AbuseIPDB:  https://www.abuseipdb.com/register\n"
            "  • OTX:        https://otx.alienvault.com/\n"
            "  • GreyNoise:  https://viz.greynoise.io/signup (optional)\n"
            "  • Shodan:     https://account.shodan.io/register (optional)",
            title="🛡️ ThreatSentinel",
            border_style="cyan",
        )
    )

    env_path = Path(".env")
    lines: list[str] = []

    vt_key = Prompt.ask("VirusTotal API Key", default=cfg.virustotal_api_key or "")
    abuse_key = Prompt.ask("AbuseIPDB API Key", default=cfg.abuseipdb_api_key or "")
    otx_key = Prompt.ask("AlienVault OTX API Key", default=cfg.otx_api_key or "")
    gn_key = Prompt.ask("GreyNoise API Key (optional, press Enter to skip)", default="")
    shodan_key = Prompt.ask("Shodan API Key (optional, press Enter to skip)", default="")

    lines.append("# ThreatSentinel — Environment Configuration")
    lines.append(f"VIRUSTOTAL_API_KEY={vt_key}")
    lines.append(f"ABUSEIPDB_API_KEY={abuse_key}")
    lines.append(f"OTX_API_KEY={otx_key}")
    if gn_key:
        lines.append(f"GREYNOISE_API_KEY={gn_key}")
    if shodan_key:
        lines.append(f"SHODAN_API_KEY={shodan_key}")
    lines.append("")
    lines.append("TS_LOG_LEVEL=INFO")
    lines.append("TS_TIMEOUT=15")
    lines.append("TS_RATE_LIMIT_DELAY=0.5")

    env_path.write_text("\n".join(lines), encoding="utf-8")
    console.print(f"\n[green]✓[/green] Configuration saved to [bold]{env_path}[/bold]")
    console.print("\nRun [bold cyan]threatsentinel setup --test-connections[/bold cyan] to verify.")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def run() -> None:
    app()


if __name__ == "__main__":
    run()