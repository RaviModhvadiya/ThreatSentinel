"""Enricher base — protocol definition and shared async HTTP helpers.

All enricher modules implement EnricherProtocol. The BaseEnricher class
provides rate limiting, retry with exponential backoff, and timeout handling
so individual enrichers only need to implement business logic.
"""

from __future__ import annotations

import asyncio
from abc import abstractmethod
from typing import Any, Protocol, runtime_checkable

import httpx

from threatsentinel.constants import DEFAULT_TIMEOUT_SECONDS, MAX_RETRIES, RETRY_BACKOFF_BASE
from threatsentinel.logging_config import get_logger
from threatsentinel.models import EnrichmentBundle, IOCRecord

logger = get_logger(__name__)


@runtime_checkable
class EnricherProtocol(Protocol):
    """Interface every enricher must satisfy."""

    async def enrich(self, ioc: IOCRecord) -> EnrichmentBundle:
        """Query this source and return results merged into a bundle."""
        ...


class BaseEnricher:
    """Shared HTTP logic for all enrichers.

    Subclasses call `_get()` / `_post()` instead of building httpx clients
    directly. Rate limiting and retry logic live here so each enricher stays
    focused on API-specific parsing.
    """

    def __init__(self, api_key: str = "", timeout: int = DEFAULT_TIMEOUT_SECONDS) -> None:
        self.api_key = api_key
        self.timeout = timeout
        self._client: httpx.AsyncClient | None = None

    async def _get_client(self) -> httpx.AsyncClient:
        if self._client is None or self._client.is_closed:
            self._client = httpx.AsyncClient(
                timeout=httpx.Timeout(self.timeout),
                follow_redirects=False,  # Never follow redirects to malicious hosts
                verify=True,
            )
        return self._client

    async def close(self) -> None:
        if self._client and not self._client.is_closed:
            await self._client.aclose()

    async def _get(
        self,
        url: str,
        headers: dict[str, str] | None = None,
        params: dict[str, Any] | None = None,
    ) -> dict[str, Any] | None:
        """Perform a GET request with retry + exponential backoff."""
        client = await self._get_client()
        for attempt in range(MAX_RETRIES):
            try:
                resp = await client.get(url, headers=headers or {}, params=params or {})
                if resp.status_code == 429:
                    wait = RETRY_BACKOFF_BASE ** attempt
                    logger.warning("Rate limited by %s — waiting %ds", url, wait)
                    await asyncio.sleep(wait)
                    continue
                resp.raise_for_status()
                return resp.json()
            except httpx.HTTPStatusError as exc:
                logger.warning("HTTP %d from %s: %s", exc.response.status_code, url, exc)
                return None
            except httpx.TimeoutException:
                logger.warning("Timeout on GET %s (attempt %d/%d)", url, attempt + 1, MAX_RETRIES)
                if attempt < MAX_RETRIES - 1:
                    await asyncio.sleep(RETRY_BACKOFF_BASE ** attempt)
            except httpx.RequestError as exc:
                logger.error("Network error on GET %s: %s", url, exc)
                return None
        return None

    async def _post(
        self,
        url: str,
        data: dict[str, Any] | None = None,
        headers: dict[str, str] | None = None,
    ) -> dict[str, Any] | None:
        """Perform a POST request with retry + exponential backoff."""
        client = await self._get_client()
        for attempt in range(MAX_RETRIES):
            try:
                resp = await client.post(url, data=data or {}, headers=headers or {})
                if resp.status_code == 429:
                    wait = RETRY_BACKOFF_BASE ** attempt
                    await asyncio.sleep(wait)
                    continue
                resp.raise_for_status()
                return resp.json()
            except httpx.HTTPStatusError as exc:
                logger.warning("HTTP %d from %s: %s", exc.response.status_code, url, exc)
                return None
            except httpx.TimeoutException:
                logger.warning("Timeout on POST %s (attempt %d)", url, attempt + 1)
                if attempt < MAX_RETRIES - 1:
                    await asyncio.sleep(RETRY_BACKOFF_BASE ** attempt)
            except httpx.RequestError as exc:
                logger.error("Network error on POST %s: %s", url, exc)
                return None
        return None