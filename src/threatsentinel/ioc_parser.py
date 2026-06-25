"""IOC Parser — auto-detection and validation of indicator types.

Supports: IPv4, IPv6, domain, URL, MD5, SHA1, SHA256, email.
All classification is regex-based; no DNS lookups are performed here.
"""

from __future__ import annotations

import re
from pathlib import Path

from threatsentinel.logging_config import get_logger
from threatsentinel.models import IOCRecord, IOCType

logger = get_logger(__name__)

# ---------------------------------------------------------------------------
# Compiled regex patterns (order matters — checked top-to-bottom)
# ---------------------------------------------------------------------------

# IPv4: four octets 0-255 separated by dots
_RE_IPV4 = re.compile(
    r"^((25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(25[0-5]|2[0-4]\d|[01]?\d\d?)$"
)

# IPv6: full or compressed notation
_RE_IPV6 = re.compile(
    r"^(([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}"
    r"|([0-9a-fA-F]{1,4}:){1,7}:"
    r"|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}"
    r"|::([fF]{4}(:0{1,4})?:)?(25[0-5]|2[0-4]\d|[01]?\d\d?)"
    r"(\.((25[0-5]|2[0-4]\d|[01]?\d\d?))){3}"
    r"|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}"
    r"|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}"
    r"|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}"
    r"|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}"
    r"|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})"
    r"|:((:[0-9a-fA-F]{1,4}){1,7}|:)"
    r"|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]+"
    r"|::(ffff(:0{1,4})?:)?(25[0-5]|2[0-4]\d|[01]?\d\d?)"
    r"(\.((25[0-5]|2[0-4]\d|[01]?\d\d?))){3}"
    r"|([0-9a-fA-F]{1,4}:){1,4}:(25[0-5]|2[0-4]\d|[01]?\d\d?)"
    r"(\.((25[0-5]|2[0-4]\d|[01]?\d\d?))){3})$"
)

# URL: starts with http:// or https://
_RE_URL = re.compile(r"^https?://", re.IGNORECASE)

# SHA256: exactly 64 hex chars
_RE_SHA256 = re.compile(r"^[0-9a-fA-F]{64}$")

# SHA1: exactly 40 hex chars
_RE_SHA1 = re.compile(r"^[0-9a-fA-F]{40}$")

# MD5: exactly 32 hex chars
_RE_MD5 = re.compile(r"^[0-9a-fA-F]{32}$")

# Email: simple RFC 5321-ish pattern
_RE_EMAIL = re.compile(r"^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$")

# Domain: labels separated by dots, TLD 2-63 chars, no http
_RE_DOMAIN = re.compile(
    r"^(?!https?://)"
    r"(?:[a-zA-Z0-9]"
    r"(?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+"
    r"[a-zA-Z]{2,63}$"
)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def detect_type(value: str) -> IOCType:
    """Detect the IOC type of a raw string.

    The check order is important:
      1. URLs before domains (URLs contain a domain-like portion)
      2. Hashes before domains (hex strings could match domain regex loosely)
    """
    v = value.strip()

    if _RE_IPV4.match(v):
        return IOCType.IPV4
    if _RE_IPV6.match(v):
        return IOCType.IPV6
    if _RE_URL.match(v):
        return IOCType.URL
    if _RE_SHA256.match(v):
        return IOCType.SHA256
    if _RE_SHA1.match(v):
        return IOCType.SHA1
    if _RE_MD5.match(v):
        return IOCType.MD5
    if _RE_EMAIL.match(v):
        return IOCType.EMAIL
    if _RE_DOMAIN.match(v):
        return IOCType.DOMAIN

    return IOCType.UNKNOWN


def parse_ioc(value: str) -> IOCRecord:
    """Parse a raw string into a typed IOCRecord.

    Args:
        value: Raw indicator string (IP, domain, hash, URL, email).

    Returns:
        IOCRecord with detected type and normalized value.
    """
    stripped = value.strip()
    ioc_type = detect_type(stripped)
    normalized = stripped.lower()

    if ioc_type == IOCType.UNKNOWN:
        logger.warning("Could not classify IOC: %r — type set to UNKNOWN", stripped)

    return IOCRecord(value=stripped, ioc_type=ioc_type, normalized=normalized)


def parse_file(path: Path) -> list[IOCRecord]:
    """Parse a .txt or .csv file of IOCs (one per line).

    Lines starting with '#' are treated as comments and skipped.
    Empty lines are skipped. CSV files use the first column only.

    Args:
        path: Path to the input file.

    Returns:
        List of IOCRecord objects (may include UNKNOWN types).
    """
    records: list[IOCRecord] = []
    seen: set[str] = set()
    skipped_comments = 0
    skipped_empty = 0
    skipped_dupes = 0

    with path.open("r", encoding="utf-8", errors="replace") as fh:
        for raw_line in fh:
            line = raw_line.strip()

            if not line:
                skipped_empty += 1
                continue
            if line.startswith("#"):
                skipped_comments += 1
                continue

            # For CSV: use first column only
            value = line.split(",")[0].strip()
            if not value:
                continue

            lower = value.lower()
            if lower in seen:
                skipped_dupes += 1
                continue
            seen.add(lower)

            records.append(parse_ioc(value))

    logger.info(
        "Parsed %d unique IOCs from %s "
        "(skipped: %d comments, %d empty, %d duplicates)",
        len(records),
        path.name,
        skipped_comments,
        skipped_empty,
        skipped_dupes,
    )
    return records