"""GreyNoise enricher — internet scanner classification (IP-only)."""

from __future__ import annotations

from threatsentinel.constants import GREYNOISE_BASE_URL, GREYNOISE_SCORE_MAP
from threatsentinel.enrichers.base import BaseEnricher
from threatsentinel.logging_config import get_logger
from threatsentinel.models import EnrichmentBundle, GreyNoiseResult, IOCRecord, IOCType

logger = get_logger(__name__)


class GreyNoiseEnricher(BaseEnricher):
    """Query GreyNoise for IP classification (benign / malicious / unknown)."""

    def _headers(self) -> dict[str, str]:
        headers: dict[str, str] = {"Accept": "application/json"}
        if self.api_key:
            headers["key"] = self.api_key
        return headers

    async def enrich(self, ioc: IOCRecord) -> EnrichmentBundle:
        bundle = EnrichmentBundle()

        if ioc.ioc_type not in (IOCType.IPV4, IOCType.IPV6):
            bundle.greynoise.available = False
            bundle.greynoise.error = "GreyNoise only supports IP addresses"
            return bundle

        if not self.api_key:
            bundle.greynoise.available = False
            bundle.greynoise.error = "GREYNOISE_API_KEY not configured"
            return bundle

        url = f"{GREYNOISE_BASE_URL}/community/{ioc.normalized}"
        data = await self._get(url, headers=self._headers())
        bundle.greynoise = self._parse_response(data)
        return bundle

    def _parse_response(self, data: dict | None) -> GreyNoiseResult:
        result = GreyNoiseResult()
        if data is None:
            result.available = False
            result.error = "No response from GreyNoise"
            return result

        result.classification = data.get("classification", "unknown")
        result.name = data.get("name")
        result.tags = data.get("tags", [])
        result.score = GREYNOISE_SCORE_MAP.get(result.classification, 50.0)

        logger.debug("GreyNoise: classification=%r, name=%r", result.classification, result.name)
        return result