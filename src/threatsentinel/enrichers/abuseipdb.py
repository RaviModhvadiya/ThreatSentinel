"""AbuseIPDB enricher — IP address abuse reports."""

from __future__ import annotations

from threatsentinel.constants import ABUSEIPDB_BASE_URL
from threatsentinel.enrichers.base import BaseEnricher
from threatsentinel.logging_config import get_logger
from threatsentinel.models import AbuseIPDBResult, EnrichmentBundle, IOCRecord, IOCType

logger = get_logger(__name__)


class AbuseIPDBEnricher(BaseEnricher):
    """Query AbuseIPDB for IP reputation and abuse reports."""

    async def enrich(self, ioc: IOCRecord) -> EnrichmentBundle:
        bundle = EnrichmentBundle()

        # AbuseIPDB only supports IP addresses
        if ioc.ioc_type not in (IOCType.IPV4, IOCType.IPV6):
            bundle.abuseipdb.available = False
            bundle.abuseipdb.error = "AbuseIPDB only supports IP addresses"
            return bundle

        if not self.api_key:
            bundle.abuseipdb.available = False
            bundle.abuseipdb.error = "ABUSEIPDB_API_KEY not configured"
            return bundle

        result = await self._check_ip(ioc.normalized)
        bundle.abuseipdb = result
        return bundle

    async def _check_ip(self, ip: str) -> AbuseIPDBResult:
        url = f"{ABUSEIPDB_BASE_URL}/check"
        headers = {"Key": self.api_key, "Accept": "application/json"}
        params = {"ipAddress": ip, "maxAgeInDays": "90", "verbose": ""}

        data = await self._get(url, headers=headers, params=params)
        return self._parse_response(data)

    def _parse_response(self, data: dict | None) -> AbuseIPDBResult:
        result = AbuseIPDBResult()
        if data is None:
            result.available = False
            result.error = "No response from AbuseIPDB"
            return result

        inner = data.get("data", {})
        result.abuse_confidence_score = inner.get("abuseConfidenceScore", 0)
        result.total_reports = inner.get("totalReports", 0)
        result.country_code = inner.get("countryCode")
        result.isp = inner.get("isp")
        result.domain = inner.get("domain")
        result.is_whitelisted = inner.get("isWhitelisted", False)

        # Score is the raw confidence score (0-100)
        result.score = float(result.abuse_confidence_score)

        logger.debug(
            "AbuseIPDB: score=%d, reports=%d for this IP",
            result.abuse_confidence_score,
            result.total_reports,
        )
        return result