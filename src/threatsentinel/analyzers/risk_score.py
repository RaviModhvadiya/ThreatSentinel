"""Risk Scorer — weighted multi-factor risk score calculation.

Produces a deterministic 0-100 integer score from an EnrichmentBundle.
The same input always yields the same score — no randomness.
"""

from __future__ import annotations

from threatsentinel.constants import (
    CONTEXT_BONUSES,
    GREYNOISE_SCORE_MAP,
    SCORE_WEIGHTS,
    SEVERITY_RECOMMENDATIONS,
    SEVERITY_THRESHOLDS,
    URLHAUS_SCORE_MAP,
)
from threatsentinel.logging_config import get_logger
from threatsentinel.models import EnrichmentBundle, Severity

logger = get_logger(__name__)


def calculate_risk_score(bundle: EnrichmentBundle) -> tuple[int, Severity, str]:
    """Calculate the weighted risk score from an EnrichmentBundle.

    Formula (from README):
        score = min(100, round(
            vt_weight   × vt_score     +
            abuse_weight × abuse_score  +
            otx_weight  × otx_score    +
            gn_weight   × gn_score     +
            urlhaus_weight × urlhaus_score +
            context_weight × context_bonus
        ))

    Returns:
        Tuple of (score: int, label: Severity, recommendation: str)
    """
    weights = SCORE_WEIGHTS

    # --- VirusTotal component ---
    vt_score = bundle.virustotal.score if bundle.virustotal.available else 0.0

    # --- AbuseIPDB component ---
    abuse_score = float(bundle.abuseipdb.abuse_confidence_score) if bundle.abuseipdb.available else 0.0

    # --- OTX component ---
    otx_score = bundle.otx.score if bundle.otx.available else 0.0

    # --- GreyNoise component ---
    if bundle.greynoise.available:
        gn_score = GREYNOISE_SCORE_MAP.get(bundle.greynoise.classification, 50.0)
    else:
        gn_score = 0.0

    # --- URLhaus component ---
    if bundle.urlhaus.available and bundle.urlhaus.query_status not in ("no_results", "is_whitelisted"):
        urlhaus_score = URLHAUS_SCORE_MAP.get(bundle.urlhaus.url_status or "no_results", 0.0)
    else:
        urlhaus_score = 0.0

    # --- Context bonus (additive, weighted) ---
    all_tags = bundle.all_tags()
    context_total = 0.0
    matched_bonuses: list[str] = []
    for tag in all_tags:
        for keyword, bonus in CONTEXT_BONUSES.items():
            if keyword in tag:
                context_total += bonus
                matched_bonuses.append(tag)
    context_score = min(context_total, 100.0)

    # --- Weighted sum ---
    raw = (
        weights["virustotal"] * vt_score
        + weights["abuseipdb"] * abuse_score
        + weights["otx"] * otx_score
        + weights["greynoise"] * gn_score
        + weights["urlhaus"] * urlhaus_score
        + weights["context_bonus"] * context_score
    )

    final_score = min(100, round(raw))

    label = _score_to_severity(final_score)
    recommendation = SEVERITY_RECOMMENDATIONS[label.value]

    logger.debug(
        "Risk score: %d (%s) — vt=%.1f abuse=%.1f otx=%.1f gn=%.1f urlhaus=%.1f ctx=%.1f",
        final_score,
        label,
        vt_score,
        abuse_score,
        otx_score,
        gn_score,
        urlhaus_score,
        context_score,
    )

    return final_score, label, recommendation


def _score_to_severity(score: int) -> Severity:
    """Map a 0-100 score to a Severity label using threshold table."""
    for label, (low, high) in SEVERITY_THRESHOLDS.items():
        if low <= score <= high:
            return Severity(label)
    return Severity.CRITICAL