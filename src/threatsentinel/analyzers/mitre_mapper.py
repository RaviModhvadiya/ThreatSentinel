"""MITRE ATT&CK TTP Mapper.

Maps IOC context tags (from enrichment sources) to ATT&CK v15 Enterprise
techniques using a local JSON index. No internet required after installation.

The tag_to_technique.json index lives at src/threatsentinel/data/ and is
shipped with the package. It can be extended by contributors.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from threatsentinel.logging_config import get_logger
from threatsentinel.models import EnrichmentBundle, MITRETechnique

logger = get_logger(__name__)

# Path to the bundled tag-to-technique index
_DATA_DIR = Path(__file__).parent.parent / "data"
_TAG_MAP_PATH = _DATA_DIR / "tag_to_technique.json"

# Module-level cache
_TAG_MAP: dict[str, list[dict[str, Any]]] | None = None


def _load_tag_map() -> dict[str, list[dict[str, Any]]]:
    """Load (and cache) the tag-to-technique mapping index."""
    global _TAG_MAP
    if _TAG_MAP is not None:
        return _TAG_MAP

    if not _TAG_MAP_PATH.exists():
        logger.warning("ATT&CK tag map not found at %s — TTP mapping disabled", _TAG_MAP_PATH)
        _TAG_MAP = {}
        return _TAG_MAP

    with _TAG_MAP_PATH.open("r", encoding="utf-8") as fh:
        _TAG_MAP = json.load(fh)

    logger.debug("Loaded ATT&CK tag map with %d entries from %s", len(_TAG_MAP), _TAG_MAP_PATH)
    return _TAG_MAP


def map_ttps(bundle: EnrichmentBundle) -> list[MITRETechnique]:
    """Map enrichment tags to MITRE ATT&CK techniques.

    Algorithm:
      1. Collect all normalized tags from the enrichment bundle.
      2. For each tag, look up matching techniques in the index.
      3. If multiple tags match the same technique, average the confidences.
      4. Deduplicate by technique_id, keeping the highest confidence.
      5. Sort by confidence descending.

    Args:
        bundle: The enrichment results for an IOC.

    Returns:
        List of MITRETechnique objects sorted by confidence (highest first).
    """
    tag_map = _load_tag_map()
    if not tag_map:
        return []

    all_tags = bundle.all_tags()
    if not all_tags:
        logger.debug("No tags to map — returning empty TTP list")
        return []

    # technique_id → {technique info, list of confidence values}
    technique_hits: dict[str, dict[str, Any]] = {}

    for tag in all_tags:
        # Try exact match first
        matches = tag_map.get(tag, [])

        # Try partial/substring match for compound tags
        if not matches:
            for key, techs in tag_map.items():
                if key in tag or tag in key:
                    matches = techs
                    break

        for tech in matches:
            tid = tech["technique_id"]
            if tid not in technique_hits:
                technique_hits[tid] = {
                    "technique_id": tid,
                    "name": tech["name"],
                    "tactic": tech["tactic"],
                    "confidences": [],
                }
            technique_hits[tid]["confidences"].append(tech.get("confidence", 0.5))

    # Build final list with averaged confidence
    result: list[MITRETechnique] = []
    for info in technique_hits.values():
        confidences = info["confidences"]
        avg_confidence = sum(confidences) / len(confidences)
        # Boost confidence slightly when multiple tags corroborate same technique
        if len(confidences) > 1:
            avg_confidence = min(1.0, avg_confidence * 1.15)

        result.append(
            MITRETechnique(
                technique_id=info["technique_id"],
                name=info["name"],
                tactic=info["tactic"],
                confidence=round(avg_confidence, 2),
            )
        )

    # Sort by confidence descending
    result.sort(key=lambda t: t.confidence, reverse=True)

    logger.debug(
        "Mapped %d tags → %d ATT&CK techniques for this IOC",
        len(all_tags),
        len(result),
    )
    return result