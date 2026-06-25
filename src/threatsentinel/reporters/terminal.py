"""Terminal reporter — Rich-formatted console output."""

from __future__ import annotations

from datetime import datetime

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich import box

from threatsentinel.models import BulkResult, InvestigationResult, Severity

console = Console()

_SEVERITY_COLORS: dict[str, str] = {
    "CRITICAL": "bold red",
    "HIGH": "red",
    "MEDIUM": "yellow",
    "LOW": "green",
    "INFORMATIONAL": "dim cyan",
}

_SEVERITY_ICONS: dict[str, str] = {
    "CRITICAL": "🔴",
    "HIGH": "🟠",
    "MEDIUM": "🟡",
    "LOW": "🟢",
    "INFORMATIONAL": "ℹ️ ",
}


def _severity_text(label: str) -> Text:
    color = _SEVERITY_COLORS.get(label, "white")
    icon = _SEVERITY_ICONS.get(label, "")
    return Text(f"{icon}  {label}", style=color)


def print_result(result: InvestigationResult) -> None:
    """Print a full investigation result to the terminal."""
    label = result.risk_label.value
    color = _SEVERITY_COLORS.get(label, "white")

    console.print()
    console.rule(
        f"[bold]ThreatSentinel v1.0.0 — IOC Investigation Report[/bold]",
        style="cyan",
    )
    console.print()

    # Header info
    header_table = Table.grid(padding=(0, 2))
    header_table.add_column(style="dim", min_width=18)
    header_table.add_column()
    header_table.add_row("IOC", f"[bold]{result.ioc.value}[/bold] ({result.ioc.ioc_type.value.upper()})")
    header_table.add_row(
        "Risk Score",
        Text(f"{result.risk_score} / 100  ●  {label}", style=color),
    )
    if result.campaign:
        header_table.add_row("Campaign", f"[italic]{result.campaign}[/italic]")
    if result.first_seen:
        header_table.add_row("First Seen", result.first_seen)
    if result.last_seen:
        header_table.add_row("Last Seen", result.last_seen)
    if result.case_name:
        header_table.add_row("Case", result.case_name)
    header_table.add_row(
        "Investigated",
        result.investigated_at.strftime("%Y-%m-%d %H:%M:%S UTC"),
    )
    console.print(header_table)
    console.print()

    # Suppressed banner
    if result.suppressed:
        console.print(
            Panel(
                "[dim]This IOC matches a suppression rule and has been marked as a known-good indicator.[/dim]",
                border_style="dim",
                title="Suppressed",
            )
        )
        return

    # Enrichment sources table
    src_table = Table(box=box.ROUNDED, show_header=True, header_style="bold cyan")
    src_table.add_column("Source", min_width=24)
    src_table.add_column("Verdict")

    e = result.enrichment

    if e.virustotal.available:
        if e.virustotal.total_engines > 0:
            ratio = f"{e.virustotal.malicious}/{e.virustotal.total_engines} engines"
            verdict = "Malicious" if e.virustotal.malicious > 0 else "Clean"
            style = "red" if e.virustotal.malicious > 0 else "green"
            src_table.add_row("VirusTotal", Text(f"{ratio} — {verdict}", style=style))
        else:
            src_table.add_row("VirusTotal", Text("No detections", style="dim"))
    else:
        src_table.add_row("VirusTotal", Text(f"Unavailable: {e.virustotal.error}", style="dim"))

    if e.abuseipdb.available:
        if e.abuseipdb.abuse_confidence_score > 0:
            src_table.add_row(
                "AbuseIPDB",
                Text(
                    f"Confidence {e.abuseipdb.abuse_confidence_score}% — Reported {e.abuseipdb.total_reports:,}×",
                    style="red" if e.abuseipdb.abuse_confidence_score >= 50 else "yellow",
                ),
            )
        else:
            src_table.add_row("AbuseIPDB", Text("Not reported", style="dim green"))
    else:
        src_table.add_row("AbuseIPDB", Text(f"Unavailable: {e.abuseipdb.error}", style="dim"))

    if e.otx.available:
        if e.otx.pulse_count > 0:
            tags_str = " / ".join(e.otx.tags[:3]) if e.otx.tags else ""
            src_table.add_row(
                "AlienVault OTX",
                Text(
                    f"{e.otx.pulse_count} pulses" + (f" — {tags_str}" if tags_str else ""),
                    style="red" if e.otx.pulse_count >= 5 else "yellow",
                ),
            )
        else:
            src_table.add_row("AlienVault OTX", Text("No pulses", style="dim green"))
    else:
        src_table.add_row("AlienVault OTX", Text(f"Unavailable: {e.otx.error}", style="dim"))

    if e.greynoise.available:
        cls = e.greynoise.classification
        style = {"malicious": "red", "benign": "green", "unknown": "yellow"}.get(cls, "dim")
        name_str = f" — {e.greynoise.name}" if e.greynoise.name else ""
        src_table.add_row("GreyNoise", Text(f"{cls.capitalize()}{name_str}", style=style))
    else:
        src_table.add_row("GreyNoise", Text(f"Unavailable: {e.greynoise.error}", style="dim"))

    if e.urlhaus.available:
        qs = e.urlhaus.query_status
        if qs == "ok":
            status_str = f"Active — {e.urlhaus.url_status}"
            style = "red" if e.urlhaus.url_status == "online" else "yellow"
        elif qs == "is_whitelisted":
            status_str = "Whitelisted"
            style = "green"
        else:
            status_str = "Not listed"
            style = "dim green"
        src_table.add_row("URLhaus", Text(status_str, style=style))
    else:
        src_table.add_row("URLhaus", Text(f"Unavailable: {e.urlhaus.error}", style="dim"))

    if e.malwarebazaar.available:
        qs = e.malwarebazaar.query_status
        if qs == "ok":
            family = e.malwarebazaar.malware_family or "Unknown family"
            src_table.add_row("MalwareBazaar", Text(f"Found — {family}", style="red"))
        else:
            src_table.add_row("MalwareBazaar", Text("Not found", style="dim green"))
    else:
        src_table.add_row(
            "MalwareBazaar", Text(f"Unavailable: {e.malwarebazaar.error}", style="dim")
        )

    if e.shodan.ports:
        ports_str = ", ".join(str(p) for p in e.shodan.ports[:6])
        if len(e.shodan.ports) > 6:
            ports_str += f" +{len(e.shodan.ports) - 6} more"
        src_table.add_row(
            "Shodan",
            f"Ports: {ports_str}" + (f" | ASN: {e.shodan.asn}" if e.shodan.asn else ""),
        )

    console.print(src_table)
    console.print()

    # MITRE ATT&CK table
    if result.mitre_techniques:
        mitre_table = Table(
            title="MITRE ATT&CK TTPs Identified",
            box=box.ROUNDED,
            header_style="bold magenta",
        )
        mitre_table.add_column("Technique ID", min_width=14)
        mitre_table.add_column("Name", min_width=34)
        mitre_table.add_column("Tactic", min_width=22)
        mitre_table.add_column("Confidence", justify="right")
        for t in result.mitre_techniques:
            conf_pct = f"{int(t.confidence * 100)}%"
            mitre_table.add_row(
                Text(t.technique_id, style="bold"),
                t.name,
                t.tactic,
                Text(conf_pct, style="cyan"),
            )
        console.print(mitre_table)
        console.print()

    # Recommendation panel
    rec_color = color
    console.print(
        Panel(
            Text(result.recommendation, style=rec_color),
            title="[bold]Recommendation[/bold]",
            border_style=rec_color,
        )
    )
    console.print()


def print_bulk_summary(bulk: BulkResult) -> None:
    """Print a summary table for bulk investigation results."""
    console.print()
    console.rule("[bold]ThreatSentinel — Bulk Investigation Summary[/bold]", style="cyan")
    console.print()

    summary = Table(box=box.SIMPLE_HEAVY, show_header=False)
    summary.add_column(style="dim", min_width=22)
    summary.add_column()

    summary.add_row("Total IOCs Investigated", str(bulk.total))
    summary.add_row("CRITICAL", Text(str(bulk.critical_count), style="bold red"))
    summary.add_row("HIGH", Text(str(bulk.high_count), style="red"))
    summary.add_row("MEDIUM", Text(str(bulk.medium_count), style="yellow"))
    summary.add_row("LOW", Text(str(bulk.low_count), style="green"))
    summary.add_row("INFORMATIONAL", Text(str(bulk.informational_count), style="dim cyan"))
    summary.add_row("Suppressed", Text(str(bulk.suppressed_count), style="dim"))

    console.print(summary)
    console.print()

    # Top 10 highest risk
    top_results = sorted(
        [r for r in bulk.results if not r.suppressed],
        key=lambda r: r.risk_score,
        reverse=True,
    )[:10]

    if top_results:
        top_table = Table(
            title="Top Findings (by Risk Score)",
            box=box.ROUNDED,
            header_style="bold cyan",
        )
        top_table.add_column("IOC", min_width=30)
        top_table.add_column("Type", min_width=8)
        top_table.add_column("Score", justify="right", min_width=6)
        top_table.add_column("Severity", min_width=14)
        top_table.add_column("Campaign")

        for r in top_results:
            label = r.risk_label.value
            color = _SEVERITY_COLORS.get(label, "white")
            top_table.add_row(
                r.ioc.value,
                r.ioc.ioc_type.value,
                Text(str(r.risk_score), style=color),
                _severity_text(label),
                r.campaign or "—",
            )
        console.print(top_table)
        console.print()