"""HTML reporter — self-contained offline dashboard with ATT&CK heatmap."""

from __future__ import annotations

import json
from pathlib import Path

from threatsentinel.models import BulkResult, InvestigationResult, Severity

_SEVERITY_COLOR: dict[str, str] = {
    "CRITICAL": "#dc2626",
    "HIGH": "#ea580c",
    "MEDIUM": "#ca8a04",
    "LOW": "#16a34a",
    "INFORMATIONAL": "#0891b2",
}

_TACTIC_ORDER = [
    "Reconnaissance", "Resource Development", "Initial Access", "Execution",
    "Persistence", "Privilege Escalation", "Defense Evasion", "Credential Access",
    "Discovery", "Lateral Movement", "Collection", "Command & Control",
    "Exfiltration", "Impact",
]


def _severity_badge(label: str) -> str:
    color = _SEVERITY_COLOR.get(label, "#6b7280")
    return (
        f'<span style="background:{color};color:#fff;padding:3px 10px;'
        f'border-radius:4px;font-weight:600;font-size:0.85em">{label}</span>'
    )


def _build_tactic_heatmap(results: list[InvestigationResult]) -> str:
    """Build an ATT&CK tactic coverage heatmap as HTML."""
    tactic_counts: dict[str, int] = {}
    for r in results:
        for t in r.mitre_techniques:
            tac = t.tactic
            tactic_counts[tac] = tactic_counts.get(tac, 0) + 1

    max_count = max(tactic_counts.values(), default=1)
    cells = []
    for tactic in _TACTIC_ORDER:
        count = tactic_counts.get(tactic, 0)
        intensity = int((count / max_count) * 200) if max_count > 0 else 0
        bg = f"rgb(220,{20 + intensity},{20 + intensity})" if count > 0 else "#1e293b"
        label_color = "#fff"
        short = tactic.split(" ")[0]
        cells.append(
            f'<div title="{tactic}: {count} IOC(s)" style="background:{bg};color:{label_color};'
            f'padding:8px 4px;border-radius:4px;text-align:center;font-size:0.72em;'
            f'font-weight:600;cursor:default">{short}<br>'
            f'<span style="font-size:1.2em">{count}</span></div>'
        )

    return (
        '<div style="display:grid;grid-template-columns:repeat(7,1fr);gap:4px;'
        'max-width:700px">' + "".join(cells) + "</div>"
    )


def _result_row(r: InvestigationResult) -> str:
    label = r.risk_label.value
    color = _SEVERITY_COLOR.get(label, "#6b7280")
    bar_width = r.risk_score
    suppressed_note = '<span style="color:#6b7280;font-size:0.8em"> (suppressed)</span>' if r.suppressed else ""
    ttps = ", ".join(t.technique_id for t in r.mitre_techniques[:3])
    if len(r.mitre_techniques) > 3:
        ttps += f" +{len(r.mitre_techniques) - 3}"

    return f"""
    <tr>
      <td style="font-family:monospace;font-size:0.9em">{r.ioc.value}{suppressed_note}</td>
      <td>{r.ioc.ioc_type.value.upper()}</td>
      <td>
        <div style="display:flex;align-items:center;gap:8px">
          <div style="width:80px;background:#334155;border-radius:3px;height:8px">
            <div style="width:{bar_width}%;background:{color};border-radius:3px;height:8px"></div>
          </div>
          <strong style="color:{color}">{r.risk_score}</strong>
        </div>
      </td>
      <td>{_severity_badge(label)}</td>
      <td style="font-size:0.85em">{r.campaign or '—'}</td>
      <td style="font-family:monospace;font-size:0.8em;color:#94a3b8">{ttps or '—'}</td>
    </tr>"""


def render_single(result: InvestigationResult) -> str:
    """Render a single result as a self-contained HTML page."""
    bulk = BulkResult(results=[result])
    bulk.tally()
    return render_bulk(bulk)


def render_bulk(bulk: BulkResult) -> str:
    """Render all results as a self-contained HTML dashboard."""
    total = bulk.total
    critical = bulk.critical_count
    high = bulk.high_count
    medium = bulk.medium_count
    low = bulk.low_count
    info = bulk.informational_count
    case = bulk.case_name or "Ad-hoc Investigation"

    rows = "".join(_result_row(r) for r in
                   sorted(bulk.results, key=lambda x: x.risk_score, reverse=True))

    heatmap = _build_tactic_heatmap(bulk.results)

    # Donut chart data for Chart.js (embedded inline)
    chart_data = json.dumps([critical, high, medium, low, info])
    chart_colors = json.dumps([
        "#dc2626", "#ea580c", "#ca8a04", "#16a34a", "#0891b2"
    ])
    chart_labels = json.dumps(["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"])

    generated = bulk.investigated_at.strftime("%Y-%m-%d %H:%M:%S UTC")

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>ThreatSentinel — {case}</title>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
<style>
  *, *::before, *::after {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ font-family: system-ui, sans-serif; background: #0f172a; color: #e2e8f0; line-height: 1.6; }}
  .container {{ max-width: 1200px; margin: 0 auto; padding: 24px; }}
  header {{ display: flex; justify-content: space-between; align-items: center;
    border-bottom: 1px solid #334155; padding-bottom: 16px; margin-bottom: 24px; }}
  h1 {{ font-size: 1.5rem; color: #38bdf8; letter-spacing: -0.02em; }}
  .meta {{ font-size: 0.85em; color: #64748b; }}
  .cards {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr));
    gap: 12px; margin-bottom: 24px; }}
  .card {{ background: #1e293b; border-radius: 8px; padding: 16px; text-align: center; }}
  .card-value {{ font-size: 2rem; font-weight: 700; }}
  .card-label {{ font-size: 0.8em; color: #64748b; margin-top: 4px; }}
  section {{ background: #1e293b; border-radius: 8px; padding: 20px; margin-bottom: 24px; }}
  section h2 {{ font-size: 1rem; color: #94a3b8; margin-bottom: 16px;
    text-transform: uppercase; letter-spacing: 0.08em; }}
  table {{ width: 100%; border-collapse: collapse; font-size: 0.9em; }}
  th {{ text-align: left; padding: 10px 12px; color: #64748b; font-size: 0.8em;
    text-transform: uppercase; letter-spacing: 0.05em; border-bottom: 1px solid #334155; }}
  td {{ padding: 10px 12px; border-bottom: 1px solid #1e293b; vertical-align: middle; }}
  tr:hover td {{ background: #0f172a; }}
  input[type=text] {{ background: #0f172a; border: 1px solid #334155; color: #e2e8f0;
    padding: 8px 12px; border-radius: 6px; width: 300px; font-size: 0.9em; }}
  input[type=text]:focus {{ outline: none; border-color: #38bdf8; }}
  .chart-row {{ display: grid; grid-template-columns: 260px 1fr; gap: 24px; align-items: center; }}
  footer {{ text-align: center; color: #334155; font-size: 0.8em; padding: 24px 0; }}
</style>
</head>
<body>
<div class="container">
  <header>
    <div>
      <h1>🛡️ ThreatSentinel</h1>
      <div class="meta">Case: <strong>{case}</strong> &nbsp;·&nbsp; {generated}</div>
    </div>
    <div class="meta">{total} IOCs investigated</div>
  </header>

  <!-- Stat cards -->
  <div class="cards">
    <div class="card"><div class="card-value" style="color:#dc2626">{critical}</div><div class="card-label">CRITICAL</div></div>
    <div class="card"><div class="card-value" style="color:#ea580c">{high}</div><div class="card-label">HIGH</div></div>
    <div class="card"><div class="card-value" style="color:#ca8a04">{medium}</div><div class="card-label">MEDIUM</div></div>
    <div class="card"><div class="card-value" style="color:#16a34a">{low}</div><div class="card-label">LOW</div></div>
    <div class="card"><div class="card-value" style="color:#0891b2">{info}</div><div class="card-label">INFORMATIONAL</div></div>
    <div class="card"><div class="card-value" style="color:#475569">{bulk.suppressed_count}</div><div class="card-label">SUPPRESSED</div></div>
  </div>

  <!-- Risk distribution chart + ATT&CK heatmap -->
  <section>
    <h2>Risk Distribution &amp; ATT&amp;CK Coverage</h2>
    <div class="chart-row">
      <canvas id="donutChart" width="240" height="240"></canvas>
      <div>
        <p style="font-size:0.85em;color:#64748b;margin-bottom:12px">
          ATT&amp;CK Tactic Coverage (by IOC count)
        </p>
        {heatmap}
      </div>
    </div>
  </section>

  <!-- IOC table -->
  <section>
    <h2>All Findings</h2>
    <div style="margin-bottom:12px">
      <input type="text" id="filterInput" placeholder="Filter IOCs…" oninput="filterTable()">
    </div>
    <table id="iocTable">
      <thead>
        <tr>
          <th>IOC</th><th>Type</th><th>Score</th><th>Severity</th>
          <th>Campaign</th><th>ATT&amp;CK TTPs</th>
        </tr>
      </thead>
      <tbody>{rows}</tbody>
    </table>
  </section>

  <footer>Generated by ThreatSentinel v1.0.0 — Built for Blue Team Analysts</footer>
</div>

<script>
// Donut chart
const ctx = document.getElementById('donutChart').getContext('2d');
new Chart(ctx, {{
  type: 'doughnut',
  data: {{
    labels: {chart_labels},
    datasets: [{{ data: {chart_data}, backgroundColor: {chart_colors}, borderWidth: 0 }}]
  }},
  options: {{
    plugins: {{ legend: {{ labels: {{ color: '#94a3b8', font: {{ size: 11 }} }} }} }},
    cutout: '65%'
  }}
}});

// Table filter
function filterTable() {{
  const val = document.getElementById('filterInput').value.toLowerCase();
  document.querySelectorAll('#iocTable tbody tr').forEach(row => {{
    row.style.display = row.textContent.toLowerCase().includes(val) ? '' : 'none';
  }});
}}
</script>
</body>
</html>"""


def write(content: str, output: Path) -> None:
    """Write HTML report to disk."""
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(content, encoding="utf-8")