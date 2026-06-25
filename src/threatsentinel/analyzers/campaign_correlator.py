"""Campaign correlator — links IOCs to known threat actor campaigns."""

from __future__ import annotations

from threatsentinel.logging_config import get_logger
from threatsentinel.models import EnrichmentBundle

logger = get_logger(__name__)


def correlate_campaign(bundle: EnrichmentBundle) -> str | None:
    """Extract the most specific campaign or adversary attribution.

    Checks OTX adversary field first (most authoritative), then
    malware families, then tags for known APT/campaign references.

    Returns:
        Campaign string (e.g. "APT29 — Cozy Bear") or None.
    """
    # 1. OTX adversary attribution (most specific)
    if bundle.otx.adversary:
        campaign = bundle.otx.adversary
        logger.debug("Campaign from OTX adversary: %r", campaign)
        return campaign

    # 2. OTX malware families
    if bundle.otx.malware_families:
        family = bundle.otx.malware_families[0]
        logger.debug("Campaign from malware family: %r", family)
        return family

    # 3. GreyNoise named scanner/actor
    if bundle.greynoise.name and bundle.greynoise.classification == "malicious":
        logger.debug("Campaign from GreyNoise name: %r", bundle.greynoise.name)
        return bundle.greynoise.name

    # 4. MalwareBazaar malware family
    if bundle.malwarebazaar.malware_family:
        logger.debug("Campaign from MalwareBazaar: %r", bundle.malwarebazaar.malware_family)
        return bundle.malwarebazaar.malware_family

    # 5. Scan all tags for known APT/threat group references
    apt_keywords = [
        "apt", "lazarus", "cozy-bear", "fancy-bear", "carbanak",
        "fin7", "emotet", "conti", "lockbit", "revil",
        "cobalt-strike", "blackcat", "alphv",
    ]
    for tag in bundle.all_tags():
        for kw in apt_keywords:
            if kw in tag:
                logger.debug("Campaign inferred from tag: %r", tag)
                return tag

    return None