"""SARIF reporter — Static Analysis Results Interchange Format for CI/CD."""

from __future__ import annotations

import json
from pathlib import Path

from threatsentinel.constants import VERSION
from threatsentinel.models import BulkResult, InvestigationResult, Severity

_SEVERITY_SARIF: dict[str, str] = {
    "CRITICAL": "error",
    "HIGH": "error",
    "MEDIUM": "warning",
    "LOW": "note",
    "INFORMATIONAL": "none",
}


def _result_to_sarif_result(result: InvestigationResult) -> dict:
    """Convert an InvestigationResult to a SARIF result object."""
    level = _SEVERITY_SARIF.get(result.risk_label.value, "note")
    technique_ids = [t.technique_id for t in result.mitre_techniques]

    return {
        "ruleId": f"TS-{result.ioc.ioc_type.value.upper()}",
        "level": level,
        "message": {
            "text": (
                f"IOC '{result.ioc.value}' ({result.ioc.ioc_type.value.upper()}) "
                f"scored {result.risk_score}/100 ({result.risk_label.value}). "
                f"{result.recommendation}"
                + (f" Campaign: {result.campaign}." if result.campaign else "")
                + (f" ATT&CK: {', '.join(technique_ids)}." if technique_ids else "")
            )
        },
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": "ioc://investigation"},
                    "region": {"startLine": 1},
                },
                "logicalLocations": [{"name": result.ioc.value, "kind": "ioc"}],
            }
        ],
        "properties": {
            "risk_score": result.risk_score,
            "risk_label": result.risk_label.value,
            "ioc_type": result.ioc.ioc_type.value,
            "campaign": result.campaign,
            "suppressed": result.suppressed,
            "mitre_techniques": technique_ids,
        },
    }


def _build_rules() -> list[dict]:
    """SARIF rule descriptors for each IOC type."""
    ioc_types = ["IPV4", "IPV6", "DOMAIN", "URL", "MD5", "SHA1", "SHA256", "EMAIL"]
    return [
        {
            "id": f"TS-{t}",
            "name": f"IOCInvestigation{t.capitalize()}",
            "shortDescription": {"text": f"ThreatSentinel {t} IOC investigation finding"},
            "fullDescription": {
                "text": (
                    f"A {t} indicator of compromise was investigated by ThreatSentinel "
                    f"and received a risk score above the INFORMATIONAL threshold."
                )
            },
            "help": {
                "text": "See https://github.com/<your-username>/threatsentinel for details."
            },
        }
        for t in ioc_types
    ]


def render_single(result: InvestigationResult) -> str:
    """Render a single result as SARIF 2.1.0 JSON."""
    sarif = {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "ThreatSentinel",
                        "version": VERSION,
                        "informationUri": "https://github.com/<your-username>/threatsentinel",
                        "rules": _build_rules(),
                    }
                },
                "results": [_result_to_sarif_result(result)] if not result.suppressed else [],
            }
        ],
    }
    return json.dumps(sarif, indent=2)


def render_bulk(bulk: BulkResult) -> str:
    """Render all results as a single SARIF 2.1.0 run."""
    sarif_results = [
        _result_to_sarif_result(r)
        for r in bulk.results
        if not r.suppressed and r.risk_label != "INFORMATIONAL"
    ]
    sarif = {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "ThreatSentinel",
                        "version": VERSION,
                        "informationUri": "https://github.com/<your-username>/threatsentinel",
                        "rules": _build_rules(),
                    }
                },
                "results": sarif_results,
            }
        ],
    }
    return json.dumps(sarif, indent=2)


def write(content: str, output: Path) -> None:
    """Write SARIF JSON to a file."""
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(content, encoding="utf-8")