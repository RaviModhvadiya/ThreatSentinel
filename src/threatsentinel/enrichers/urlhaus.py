"""URLhaus enricher — malware URL and host lookup (no API key required)."""

from __future__ import annotations

from threatsentinel.constants import URLHAUS_BASE_URL, URLHAUS_SCORE_MAP
from threatsentinel.enrichers.base import BaseEnricher
from threatsentinel.logging_config import get_logger
from threatsentinel.models import EnrichmentBundle, IOCRecord, IOCType, URLhausResult

logger = get_logger(__name__)


class URLhausEnricher(BaseEnricher):
    """Query URLhaus for malware distribution URLs and C2 hosts."""

    async def enrich(self, ioc: IOCRecord) -> EnrichmentBundle:
        bundle = EnrichmentBundle()

        if ioc.ioc_type == IOCType.URL:
            data = await self._post(
                f"{URLHAUS_BASE_URL}/url/",
                data={"url": ioc.value},
            )
            bundle.urlhaus = self._parse_url_response(data)

        elif ioc.ioc_type == IOCType.DOMAIN:
            data = await self._post(
                f"{URLHAUS_BASE_URL}/host/",
                data={"host": ioc.normalized},
            )
            bundle.urlhaus = self._parse_host_response(data)

        elif ioc.ioc_type in (IOCType.IPV4, IOCType.IPV6):
            data = await self._post(
                f"{URLHAUS_BASE_URL}/host/",
                data={"host": ioc.normalized},
            )
            bundle.urlhaus = self._parse_host_response(data)

        else:
            bundle.urlhaus.available = False
            bundle.urlhaus.error = f"URLhaus does not support IOC type: {ioc.ioc_type}"

        return bundle

    def _parse_url_response(self, data: dict | None) -> URLhausResult:
        result = URLhausResult()
        if data is None:
            result.available = False
            result.error = "No response from URLhaus"
            return result

        result.query_status = data.get("query_status", "no_results")
        if result.query_status == "is_whitelisted":
            result.score = 0.0
            return result

        result.url_status = data.get("url_status")
        result.tags = data.get("tags", []) or []
        result.urlhaus_reference = data.get("urlhaus_reference")
        result.score = URLHAUS_SCORE_MAP.get(result.url_status or "no_results", 0.0)

        logger.debug("URLhaus: status=%r, url_status=%r", result.query_status, result.url_status)
        return result

    def _parse_host_response(self, data: dict | None) -> URLhausResult:
        result = URLhausResult()
        if data is None:
            result.available = False
            result.error = "No response from URLhaus"
            return result

        result.query_status = data.get("query_status", "no_results")
        if result.query_status == "no_results":
            result.score = 0.0
            return result

        # Collect tags from all associated URLs
        tags: set[str] = set()
        has_online = False
        for url_entry in data.get("urls", []):
            if url_entry.get("url_status") == "online":
                has_online = True
            entry_tags = url_entry.get("tags", []) or []
            tags.update(entry_tags)

        result.tags = sorted(tags)
        result.url_status = "online" if has_online else "offline"
        result.score = URLHAUS_SCORE_MAP.get(result.url_status, 0.0)

        logger.debug("URLhaus host: %d URLs found, online=%s", len(data.get("urls", [])), has_online)
        return result