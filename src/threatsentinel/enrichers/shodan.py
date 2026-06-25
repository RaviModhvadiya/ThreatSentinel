"""Shodan enricher — open ports and ASN data (optional, IP-only)."""

from __future__ import annotations

from threatsentinel.constants import SHODAN_BASE_URL
from threatsentinel.enrichers.base import BaseEnricher
from threatsentinel.logging_config import get_logger
from threatsentinel.models import EnrichmentBundle, IOCRecord, IOCType, ShodanResult

logger = get_logger(__name__)


class ShodanEnricher(BaseEnricher):
    """Query Shodan for open ports and network context (IP-only)."""

    async def enrich(self, ioc: IOCRecord) -> EnrichmentBundle:
        bundle = EnrichmentBundle()

        if ioc.ioc_type not in (IOCType.IPV4, IOCType.IPV6):
            bundle.shodan.available = False
            bundle.shodan.error = "Shodan only supports IP addresses"
            return bundle

        if not self.api_key:
            bundle.shodan.available = False
            bundle.shodan.error = "SHODAN_API_KEY not configured (optional)"
            return bundle

        url = f"{SHODAN_BASE_URL}/shodan/host/{ioc.normalized}"
        data = await self._get(url, params={"key": self.api_key})
        bundle.shodan = self._parse_response(data)
        return bundle

    def _parse_response(self, data: dict | None) -> ShodanResult:
        result = ShodanResult()
        if data is None:
            result.available = False
            result.error = "No response from Shodan"
            return result

        result.ports = data.get("ports", [])
        result.hostnames = data.get("hostnames", [])
        result.country = data.get("country_name")
        result.org = data.get("org")
        result.asn = data.get("asn")
        result.tags = data.get("tags", [])

        logger.debug("Shodan: ports=%s, org=%r", result.ports[:5], result.org)
        return result