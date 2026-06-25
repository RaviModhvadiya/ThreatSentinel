"""AlienVault OTX enricher — threat pulses and actor attribution."""

from __future__ import annotations

from threatsentinel.constants import OTX_BASE_URL, OTX_PULSE_SCORE_MULTIPLIER
from threatsentinel.enrichers.base import BaseEnricher
from threatsentinel.logging_config import get_logger
from threatsentinel.models import EnrichmentBundle, IOCRecord, IOCType, OTXResult

logger = get_logger(__name__)

# OTX indicator type string mapping
_OTX_TYPE_MAP: dict[str, str] = {
    IOCType.IPV4: "IPv4",
    IOCType.IPV6: "IPv6",
    IOCType.DOMAIN: "domain",
    IOCType.URL: "url",
    IOCType.MD5: "FileHash-MD5",
    IOCType.SHA1: "FileHash-SHA1",
    IOCType.SHA256: "FileHash-SHA256",
    IOCType.EMAIL: "email",
}


class OTXEnricher(BaseEnricher):
    """Query AlienVault OTX for threat pulses and IOC context."""

    def _headers(self) -> dict[str, str]:
        headers: dict[str, str] = {"Accept": "application/json"}
        if self.api_key:
            headers["X-OTX-API-KEY"] = self.api_key
        return headers

    async def enrich(self, ioc: IOCRecord) -> EnrichmentBundle:
        bundle = EnrichmentBundle()

        otx_type = _OTX_TYPE_MAP.get(ioc.ioc_type)
        if not otx_type:
            bundle.otx.available = False
            bundle.otx.error = f"OTX does not support IOC type: {ioc.ioc_type}"
            return bundle

        result = await self._query_indicators(ioc, otx_type)
        bundle.otx = result
        return bundle

    async def _query_indicators(self, ioc: IOCRecord, otx_type: str) -> OTXResult:
        """Query OTX indicators endpoint for pulse and tag data."""
        # Determine API section
        if ioc.ioc_type == IOCType.IPV4:
            section = "IPv4"
            value = ioc.normalized
        elif ioc.ioc_type == IOCType.IPV6:
            section = "IPv6"
            value = ioc.normalized
        elif ioc.ioc_type == IOCType.DOMAIN:
            section = "domain"
            value = ioc.normalized
        elif ioc.ioc_type == IOCType.URL:
            section = "url"
            value = ioc.value  # URLs should NOT be lowercased
        elif ioc.ioc_type == IOCType.EMAIL:
            section = "email"
            value = ioc.normalized
        else:
            section = "file"
            value = ioc.normalized

        url = f"{OTX_BASE_URL}/indicators/{section}/{value}/general"
        data = await self._get(url, headers=self._headers())
        return self._parse_response(data)

    def _parse_response(self, data: dict | None) -> OTXResult:
        result = OTXResult()
        if data is None:
            result.available = False
            result.error = "No response from OTX"
            return result

        # Pulse count
        pulse_info = data.get("pulse_info", {})
        result.pulse_count = pulse_info.get("count", 0)

        # Collect tags from all pulses
        tags: set[str] = set()
        malware_families: set[str] = set()
        adversary: str | None = None
        references: list[str] = []

        for pulse in pulse_info.get("pulses", []):
            tags.update(pulse.get("tags", []))
            malware_families.update(pulse.get("malware_families", []) or [])
            if not adversary and pulse.get("adversary"):
                adversary = pulse["adversary"]
            references.extend(pulse.get("references", []))

        result.tags = sorted(tags)
        result.malware_families = sorted(malware_families)
        result.adversary = adversary
        result.references = references[:5]  # cap to avoid huge payloads

        # Score: pulse_count × multiplier, capped at 100
        result.score = min(float(result.pulse_count * OTX_PULSE_SCORE_MULTIPLIER), 100.0)

        logger.debug("OTX: %d pulses, adversary=%r", result.pulse_count, adversary)
        return result