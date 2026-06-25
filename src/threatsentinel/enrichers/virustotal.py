"""VirusTotal enricher — IP, domain, URL, and file hash lookups."""

from __future__ import annotations

import base64

from threatsentinel.constants import VT_BASE_URL
from threatsentinel.enrichers.base import BaseEnricher
from threatsentinel.logging_config import get_logger
from threatsentinel.models import EnrichmentBundle, IOCRecord, IOCType, VTResult

logger = get_logger(__name__)


class VirusTotalEnricher(BaseEnricher):
    """Query VirusTotal API v3 for any supported IOC type."""

    def _headers(self) -> dict[str, str]:
        return {"x-apikey": self.api_key, "Accept": "application/json"}

    async def enrich(self, ioc: IOCRecord) -> EnrichmentBundle:
        bundle = EnrichmentBundle()

        if not self.api_key:
            bundle.virustotal.available = False
            bundle.virustotal.error = "VIRUSTOTAL_API_KEY not configured"
            return bundle

        result = await self._query(ioc)
        bundle.virustotal = result
        return bundle

    async def _query(self, ioc: IOCRecord) -> VTResult:
        """Dispatch to the correct VT endpoint based on IOC type."""
        if ioc.ioc_type == IOCType.IPV4:
            return await self._query_ip(ioc.normalized)
        if ioc.ioc_type == IOCType.IPV6:
            return await self._query_ip(ioc.normalized)
        if ioc.ioc_type == IOCType.DOMAIN:
            return await self._query_domain(ioc.normalized)
        if ioc.ioc_type == IOCType.URL:
            return await self._query_url(ioc.value)
        if ioc.ioc_type in (IOCType.MD5, IOCType.SHA1, IOCType.SHA256):
            return await self._query_hash(ioc.normalized)
        result = VTResult()
        result.available = False
        result.error = f"IOC type {ioc.ioc_type} not supported by VirusTotal enricher"
        return result

    async def _query_ip(self, ip: str) -> VTResult:
        url = f"{VT_BASE_URL}/ip_addresses/{ip}"
        data = await self._get(url, headers=self._headers())
        return self._parse_response(data)

    async def _query_domain(self, domain: str) -> VTResult:
        url = f"{VT_BASE_URL}/domains/{domain}"
        data = await self._get(url, headers=self._headers())
        return self._parse_response(data)

    async def _query_url(self, raw_url: str) -> VTResult:
        # VT requires URL to be base64url-encoded (no padding)
        encoded = base64.urlsafe_b64encode(raw_url.encode()).rstrip(b"=").decode()
        url = f"{VT_BASE_URL}/urls/{encoded}"
        data = await self._get(url, headers=self._headers())
        return self._parse_response(data)

    async def _query_hash(self, file_hash: str) -> VTResult:
        url = f"{VT_BASE_URL}/files/{file_hash}"
        data = await self._get(url, headers=self._headers())
        return self._parse_response(data)

    def _parse_response(self, data: dict | None) -> VTResult:
        result = VTResult()
        if data is None:
            result.available = False
            result.error = "No response from VirusTotal"
            return result

        attrs = data.get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})

        result.malicious = stats.get("malicious", 0)
        result.suspicious = stats.get("suspicious", 0)
        result.harmless = stats.get("harmless", 0)
        result.undetected = stats.get("undetected", 0)
        result.total_engines = sum(stats.values()) if stats else 0

        # Categories (for domain/URL responses)
        cats = attrs.get("categories", {})
        result.categories = list(set(cats.values())) if isinstance(cats, dict) else []

        # Tags
        result.tags = attrs.get("tags", [])

        # Compute normalized score
        if result.total_engines > 0:
            result.score = (result.malicious / result.total_engines) * 100
        else:
            result.score = 0.0

        logger.debug(
            "VT: %d/%d malicious for this IOC (score=%.1f)",
            result.malicious,
            result.total_engines,
            result.score,
        )
        return result