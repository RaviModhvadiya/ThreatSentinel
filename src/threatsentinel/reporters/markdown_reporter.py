"""Markdown reporter — analyst-ready output for Confluence, Jira, GitHub."""

from __future__ import annotations

from pathlib import Path

from threatsentinel.models import BulkResult, InvestigationResult, Severity

_SEVERITY_BADGE: dict[str, str] = {
    "CRITICAL": "🔴 CRITICAL",
    "HIGH": "🟠 HIGH",
    "MEDIUM": "🟡 MEDIUM",
    "LOW": "🟢 LOW",
    "INFORMATIONAL": "ℹ️ INFORMATIONAL",
}


def render_single(result: InvestigationResult) -> str:
    """Render a single InvestigationResult as a Markdown string."""
    lines: list[str] = []
    label = result.risk_label.value
    badge = _SEVERITY_BADGE.get(label, label)

    lines.append(f"# ThreatSentinel Investigation Report")
    lines.append("")
    lines.append(f"**Generated:** {result.investigated_at.strftime('%Y-%m-%d %H:%M:%S UTC')}  ")
    if result.case_name:
        lines.append(f"**Case:** {result.case_name}  ")
    lines.append("")

    lines.append("## Summary")
    lines.append("")
    lines.append(f"| Field | Value |")
    lines.append(f"|---|---|")
    lines.append(f"| **IOC** | `{result.ioc.value}` |")
    lines.append(f"| **Type** | {result.ioc.ioc_type.value.upper()} |")
    lines.append(f"| **Risk Score** | **{result.risk_score} / 100** |")
    lines.append(f"| **Severity** | {badge} |")
    if result.campaign:
        lines.append(f"| **Campaign** | {result.campaign} |")
    if result.first_seen:
        lines.append(f"| **First Seen** | {result.first_seen} |")
    if result.last_seen:
        lines.append(f"| **Last Seen** | {result.last_seen} |")
    if result.suppressed:
        lines.append(f"| **Suppressed** | ✅ Yes (matched suppression baseline) |")
    lines.append("")

    if result.suppressed:
        lines.append("> **Note:** This IOC matched a suppression rule and has been marked as a known-good indicator.")
        return "\n".join(lines)

    lines.append("## Enrichment Results")
    lines.append("")
    lines.append("| Source | Verdict |")
    lines.append("|---|---|")

    e = result.enrichment
    if e.virustotal.available:
        if e.virustotal.total_engines > 0:
            lines.append(
                f"| VirusTotal | {e.virustotal.malicious}/{e.virustotal.total_engines} "
                f"engines — {'**Malicious**' if e.virustotal.malicious > 0 else 'Clean'} |"
            )
        else:
            lines.append("| VirusTotal | No data |")
    else:
        lines.append(f"| VirusTotal | ⚠️ Unavailable |")

    if e.abuseipdb.available:
        if e.abuseipdb.abuse_confidence_score > 0:
            lines.append(
                f"| AbuseIPDB | Confidence **{e.abuseipdb.abuse_confidence_score}%** "
                f"— {e.abuseipdb.total_reports:,} reports |"
            )
        else:
            lines.append("| AbuseIPDB | Not reported |")
    else:
        lines.append("| AbuseIPDB | ⚠️ Unavailable (IP-only) |")

    if e.otx.available:
        tags_str = ", ".join(e.otx.tags[:5]) if e.otx.tags else "none"
        lines.append(
            f"| AlienVault OTX | {e.otx.pulse_count} pulses — Tags: {tags_str} |"
        )
    else:
        lines.append("| AlienVault OTX | ⚠️ Unavailable |")

    if e.greynoise.available:
        cls = e.greynoise.classification.capitalize()
        name_str = f" ({e.greynoise.name})" if e.greynoise.name else ""
        lines.append(f"| GreyNoise | {cls}{name_str} |")
    else:
        lines.append("| GreyNoise | ⚠️ Unavailable |")

    if e.urlhaus.available:
        if e.urlhaus.query_status == "ok":
            lines.append(
                f"| URLhaus | **Active** — Status: {e.urlhaus.url_status} "
                f"Tags: {', '.join(e.urlhaus.tags) if e.urlhaus.tags else 'none'} |"
            )
        else:
            lines.append("| URLhaus | Not listed |")
    else:
        lines.append("| URLhaus | ⚠️ Unavailable |")

    if e.malwarebazaar.available and e.malwarebazaar.query_status == "ok":
        lines.append(
            f"| MalwareBazaar | **Found** — Family: {e.malwarebazaar.malware_family or 'Unknown'} |"
        )
    else:
        lines.append("| MalwareBazaar | Not found / N/A |")

    if e.shodan.ports:
        lines.append(
            f"| Shodan | Ports: {', '.join(str(p) for p in e.shodan.ports[:8])} |"
        )

    lines.append("")

    if result.mitre_techniques:
        lines.append("## MITRE ATT&CK Techniques")
        lines.append("")
        lines.append("| Technique ID | Name | Tactic | Confidence |")
        lines.append("|---|---|---|---|")
        for t in result.mitre_techniques:
            conf_pct = f"{int(t.confidence * 100)}%"
            lines.append(f"| `{t.technique_id}` | {t.name} | {t.tactic} | {conf_pct} |")
        lines.append("")

    lines.append("## Analyst Recommendation")
    lines.append("")
    lines.append(f"> **{badge}** — {result.recommendation}")
    lines.append("")

    return "\n".join(lines)


def render_bulk(bulk: BulkResult) -> str:
    """Render a BulkResult as a Markdown report."""
    lines: list[str] = []
    lines.append("# ThreatSentinel — Bulk Investigation Report")
    lines.append("")
    lines.append(f"**Generated:** {bulk.investigated_at.strftime('%Y-%m-%d %H:%M:%S UTC')}  ")
    if bulk.case_name:
        lines.append(f"**Case:** {bulk.case_name}  ")
    lines.append("")

    lines.append("## Summary")
    lines.append("")
    lines.append("| Severity | Count |")
    lines.append("|---|---|")
    lines.append(f"| 🔴 CRITICAL | **{bulk.critical_count}** |")
    lines.append(f"| 🟠 HIGH | **{bulk.high_count}** |")
    lines.append(f"| 🟡 MEDIUM | {bulk.medium_count} |")
    lines.append(f"| 🟢 LOW | {bulk.low_count} |")
    lines.append(f"| ℹ️ INFORMATIONAL | {bulk.informational_count} |")
    lines.append(f"| *(Suppressed)* | {bulk.suppressed_count} |")
    lines.append(f"| **Total** | **{bulk.total}** |")
    lines.append("")

    lines.append("## All Findings")
    lines.append("")
    lines.append("| IOC | Type | Score | Severity | Campaign | Recommendation |")
    lines.append("|---|---|---|---|---|---|")

    for r in sorted(bulk.results, key=lambda x: x.risk_score, reverse=True):
        badge = _SEVERITY_BADGE.get(r.risk_label.value, r.risk_label.value)
        suppressed_note = " *(suppressed)*" if r.suppressed else ""
        lines.append(
            f"| `{r.ioc.value}`{suppressed_note} | {r.ioc.ioc_type.value} "
            f"| {r.risk_score} | {badge} "
            f"| {r.campaign or '—'} | {r.recommendation} |"
        )

    lines.append("")
    return "\n".join(lines)


def write(content: str, output: Path) -> None:
    """Write rendered Markdown to a file."""
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(content, encoding="utf-8")