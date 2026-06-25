"""Deduplicator — remove duplicate ATT&CK techniques across sources."""

from __future__ import annotations

from threatsentinel.models import MITRETechnique


def deduplicate_techniques(techniques: list[MITRETechnique]) -> list[MITRETechnique]:
    """Deduplicate techniques by technique_id, keeping highest confidence.

    Args:
        techniques: Raw list (may contain duplicates).

    Returns:
        Deduplicated list sorted by confidence descending.
    """
    best: dict[str, MITRETechnique] = {}
    for t in techniques:
        existing = best.get(t.technique_id)
        if existing is None or t.confidence > existing.confidence:
            best[t.technique_id] = t
    return sorted(best.values(), key=lambda x: x.confidence, reverse=True)