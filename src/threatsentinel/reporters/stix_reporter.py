"""STIX 2.1 reporter — generates valid threat-intelligence bundles.

Produces STIX 2.1 JSON without requiring the stix2 library so the tool
stays lightweight. The output is fully spec-compliant and importable
into MISP, OpenCTI, or any TAXII-capable platform.
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from pathlib import Path

from threatsentinel.models import BulkResult, InvestigationResult


def _now_stix() -> str:
    """Current UTC time formatted as STIX timestamp (RFC 3339)."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")


def _stix_id(obj_type: str) -> str:
    """Generate a STIX 2.1 compliant UUID identifier."""
    return f"{obj_type}--{uuid.uuid4()}"


def _ioc_pattern(ioc_type: str, value: str) -> str:
    """Build a STIX pattern expression for a given IOC."""
    pattern_map = {
        "ipv4": f"[ipv4-addr:value = '{value}']",
        "ipv6": f"[ipv6-addr:value = '{value}']",
        "domain": f"[domain-name:value = '{value}']",
        "url": f"[url:value = '{value}']",
        "md5": f"[file:hashes.MD5 = '{value}']",
        "sha1": f"[file:hashes.'SHA-1' = '{value}']",
        "sha256": f"[file:hashes.'SHA-256' = '{value}']",
        "email": f"[email-addr:value = '{value}']",
    }
    return pattern_map.get(ioc_type, f"[artifact:payload_bin = '{value}']")


def _result_to_stix_objects(result: InvestigationResult) -> list[dict]:
    """Convert one InvestigationResult into a list of STIX SDOs."""
    now = _now_stix()
    objects: list[dict] = []

    # --- Indicator SDO ---
    labels: list[str] = ["malicious-activity"]
    all_tags = result.enrichment.all_tags()
    labels.extend(t.replace(" ", "-") for t in all_tags[:5])

    indicator_id = _stix_id("indicator")
    indicator = {
        "type": "indicator",
        "spec_version": "2.1",
        "id": indicator_id,
        "created": now,
        "modified": now,
        "name": f"ThreatSentinel — {result.ioc.ioc_type.value.upper()}: {result.ioc.value}",
        "description": result.recommendation,
        "indicator_types": ["malicious-activity"],
        "pattern": _ioc_pattern(result.ioc.ioc_type.value, result.ioc.value),
        "pattern_type": "stix",
        "valid_from": now,
        "labels": list(set(labels)),
        "confidence": result.risk_score,
        "external_references": [],
    }

    # Add VirusTotal reference if available
    if result.enrichment.virustotal.malicious > 0:
        indicator["external_references"].append({
            "source_name": "VirusTotal",
            "description": (
                f"{result.enrichment.virustotal.malicious}/"
                f"{result.enrichment.virustotal.total_engines} AV engines flagged this IOC"
            ),
        })

    # Add AbuseIPDB reference if available
    if result.enrichment.abuseipdb.abuse_confidence_score > 0:
        indicator["external_references"].append({
            "source_name": "AbuseIPDB",
            "description": f"Abuse confidence score: {result.enrichment.abuseipdb.abuse_confidence_score}%",
        })

    # Add MITRE ATT&CK kill chain phases
    if result.mitre_techniques:
        indicator["kill_chain_phases"] = [
            {
                "kill_chain_name": "mitre-attack",
                "phase_name": t.tactic.lower().replace(" ", "-").replace("&", "and"),
            }
            for t in result.mitre_techniques
        ]

    objects.append(indicator)

    # --- Threat Actor SDO (if campaign known) ---
    if result.campaign:
        actor_id = _stix_id("threat-actor")
        actor = {
            "type": "threat-actor",
            "spec_version": "2.1",
            "id": actor_id,
            "created": now,
            "modified": now,
            "name": result.campaign,
            "threat_actor_types": ["criminal"],
            "labels": ["threat-actor"],
        }
        objects.append(actor)

        # Relationship: threat-actor → indicator
        relationship = {
            "type": "relationship",
            "spec_version": "2.1",
            "id": _stix_id("relationship"),
            "created": now,
            "modified": now,
            "relationship_type": "uses",
            "source_ref": actor_id,
            "target_ref": indicator_id,
        }
        objects.append(relationship)

    return objects


def render_single(result: InvestigationResult) -> str:
    """Render a single InvestigationResult as a STIX 2.1 Bundle JSON string."""
    bundle = {
        "type": "bundle",
        "id": _stix_id("bundle"),
        "objects": _result_to_stix_objects(result),
    }
    return json.dumps(bundle, indent=2)


def render_bulk(bulk: BulkResult) -> str:
    """Render all results as a single STIX 2.1 Bundle."""
    all_objects: list[dict] = []
    for r in bulk.results:
        if not r.suppressed:
            all_objects.extend(_result_to_stix_objects(r))

    bundle = {
        "type": "bundle",
        "id": _stix_id("bundle"),
        "objects": all_objects,
    }
    return json.dumps(bundle, indent=2)


def write(content: str, output: Path) -> None:
    """Write rendered STIX JSON to a file."""
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(content, encoding="utf-8")