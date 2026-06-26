"""JSON reporter — ECS-compatible machine-readable output."""

from __future__ import annotations

import json
from pathlib import Path

from threatsentinel.models import BulkResult, InvestigationResult


def render_single(result: InvestigationResult) -> str:
    """Serialize a single InvestigationResult to ECS-compatible JSON string."""
    return json.dumps(result.to_ecs(), indent=2, default=str)


def render_bulk(bulk: BulkResult) -> str:
    """Serialize a BulkResult to a JSON array of ECS documents."""
    payload = {
        "threatsentinel": {"version": "1.0.0"},
        "summary": {
            "total": bulk.total,
            "critical": bulk.critical_count,
            "high": bulk.high_count,
            "medium": bulk.medium_count,
            "low": bulk.low_count,
            "informational": bulk.informational_count,
            "suppressed": bulk.suppressed_count,
            "generated_at": bulk.investigated_at.isoformat() + "Z",
            "case": bulk.case_name,
        },
        "results": [r.to_ecs() for r in bulk.results],
    }
    return json.dumps(payload, indent=2, default=str)


def write(content: str, output: Path) -> None:
    """Write rendered JSON to a file."""
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(content, encoding="utf-8")