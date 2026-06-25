"""Enrichers package — parallel pipeline runner.

Import `run_enrichment_pipeline` to execute all applicable enrichers
concurrently for a given IOC.
"""

from __future__ import annotations

import asyncio

from threatsentinel.constants import IOC_ENRICHER_MAP
from threatsentinel.enrichers.abuseipdb import AbuseIPDBEnricher
from threatsentinel.enrichers.greynoise import GreyNoiseEnricher
from threatsentinel.enrichers.malwarebazaar import MalwareBazaarEnricher
from threatsentinel.enrichers.otx import OTXEnricher
from threatsentinel.enrichers.shodan import ShodanEnricher
from threatsentinel.enrichers.urlhaus import URLhausEnricher
from threatsentinel.enrichers.virustotal import VirusTotalEnricher
from threatsentinel.logging_config import get_logger
from threatsentinel.models import EnrichmentBundle, IOCRecord
from threatsentinel.state import AppConfig

logger = get_logger(__name__)


def _merge_bundles(*bundles: EnrichmentBundle) -> EnrichmentBundle:
    """Merge multiple partial EnrichmentBundles into one."""
    merged = EnrichmentBundle()
    for b in bundles:
        if b.virustotal.available or b.virustotal.malicious > 0:
            merged.virustotal = b.virustotal
        if b.abuseipdb.available and b.abuseipdb.abuse_confidence_score > 0:
            merged.abuseipdb = b.abuseipdb
        if b.otx.available or b.otx.pulse_count > 0:
            merged.otx = b.otx
        if b.greynoise.available and b.greynoise.classification != "unknown":
            merged.greynoise = b.greynoise
        if b.urlhaus.query_status != "no_results":
            merged.urlhaus = b.urlhaus
        if b.malwarebazaar.query_status == "ok":
            merged.malwarebazaar = b.malwarebazaar
        if b.shodan.ports:
            merged.shodan = b.shodan
    return merged


async def run_enrichment_pipeline(
    ioc: IOCRecord,
    config: AppConfig,
    skip_greynoise: bool = False,
) -> EnrichmentBundle:
    """Run all applicable enrichers concurrently and merge results.

    Args:
        ioc: The parsed IOC to investigate.
        config: App configuration with API keys.
        skip_greynoise: If True, skip GreyNoise (saves monthly quota).

    Returns:
        Merged EnrichmentBundle with results from all sources.
    """
    applicable = IOC_ENRICHER_MAP.get(ioc.ioc_type.value, [])
    logger.debug("Running enrichers for %s (%s): %s", ioc.value, ioc.ioc_type, applicable)

    timeout = config.ts_timeout

    enricher_map = {
        "virustotal": VirusTotalEnricher(api_key=config.virustotal_api_key, timeout=timeout),
        "abuseipdb": AbuseIPDBEnricher(api_key=config.abuseipdb_api_key, timeout=timeout),
        "otx": OTXEnricher(api_key=config.otx_api_key, timeout=timeout),
        "greynoise": GreyNoiseEnricher(api_key=config.greynoise_api_key, timeout=timeout),
        "urlhaus": URLhausEnricher(timeout=timeout),
        "malwarebazaar": MalwareBazaarEnricher(timeout=timeout),
        "shodan": ShodanEnricher(api_key=config.shodan_api_key, timeout=timeout),
    }

    tasks = []
    enricher_names = []
    for name in applicable:
        if skip_greynoise and name == "greynoise":
            continue
        enricher = enricher_map.get(name)
        if enricher:
            tasks.append(enricher.enrich(ioc))
            enricher_names.append(name)

    if not tasks:
        logger.warning("No enrichers applicable for IOC type: %s", ioc.ioc_type)
        return EnrichmentBundle()

    results = await asyncio.gather(*tasks, return_exceptions=True)

    valid_bundles: list[EnrichmentBundle] = []
    for name, result in zip(enricher_names, results):
        if isinstance(result, Exception):
            logger.error("Enricher %r raised an exception: %s", name, result)
        elif isinstance(result, EnrichmentBundle):
            valid_bundles.append(result)

    # Close all HTTP clients
    for enricher in enricher_map.values():
        try:
            await enricher.close()
        except Exception:
            pass

    return _merge_bundles(*valid_bundles)