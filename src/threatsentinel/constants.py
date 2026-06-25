"""ThreatSentinel constants — API endpoints, scoring weights, thresholds.

Edit source weights here to retune the risk scoring formula without touching
any other module.
"""

from __future__ import annotations

# ---------------------------------------------------------------------------
# Version
# ---------------------------------------------------------------------------

VERSION = "1.0.0"

# ---------------------------------------------------------------------------
# API Base URLs
# ---------------------------------------------------------------------------

VT_BASE_URL = "https://www.virustotal.com/api/v3"
ABUSEIPDB_BASE_URL = "https://api.abuseipdb.com/api/v2"
OTX_BASE_URL = "https://otx.alienvault.com/api/v1"
GREYNOISE_BASE_URL = "https://api.greynoise.io/v3"
URLHAUS_BASE_URL = "https://urlhaus-api.abuse.ch/v1"
MALWAREBAZAAR_BASE_URL = "https://mb-api.abuse.ch/api/v1"
SHODAN_BASE_URL = "https://api.shodan.io"

# ---------------------------------------------------------------------------
# Risk Scoring Weights
# Must sum to 1.0
# ---------------------------------------------------------------------------

SCORE_WEIGHTS: dict[str, float] = {
    "virustotal": 0.35,
    "abuseipdb": 0.25,
    "otx": 0.15,
    "greynoise": 0.10,
    "urlhaus": 0.10,
    "context_bonus": 0.05,
}

# GreyNoise classification → score mapping
GREYNOISE_SCORE_MAP: dict[str, float] = {
    "benign": 0.0,
    "unknown": 50.0,
    "malicious": 100.0,
}

# URLhaus status → score mapping
URLHAUS_SCORE_MAP: dict[str, float] = {
    "online": 100.0,
    "offline": 40.0,
    "no_results": 0.0,
    "is_whitelisted": 0.0,
}

# MalwareBazaar status → score mapping
MALWAREBAZAAR_SCORE_MAP: dict[str, float] = {
    "ok": 100.0,
    "hash_not_found": 0.0,
}

# Context signal bonus points (additive, capped at 100 total)
CONTEXT_BONUSES: dict[str, float] = {
    "tor": 10.0,
    "tor-exit": 10.0,
    "c2": 15.0,
    "command-and-control": 15.0,
    "apt": 20.0,
    "ransomware": 15.0,
    "botnet": 12.0,
    "phishing": 10.0,
    "malware": 10.0,
    "scanner": 5.0,
    "brute-force": 8.0,
}

# ---------------------------------------------------------------------------
# Severity thresholds
# ---------------------------------------------------------------------------

SEVERITY_THRESHOLDS: dict[str, tuple[int, int]] = {
    "INFORMATIONAL": (0, 19),
    "LOW": (20, 39),
    "MEDIUM": (40, 59),
    "HIGH": (60, 79),
    "CRITICAL": (80, 100),
}

SEVERITY_RECOMMENDATIONS: dict[str, str] = {
    "INFORMATIONAL": "Log and monitor. No immediate action required.",
    "LOW": "Add to watchlist. Review in next analyst cycle.",
    "MEDIUM": "Investigate further. Check for related IOCs in SIEM.",
    "HIGH": "Block and alert. Assign to L2 analyst for triage.",
    "CRITICAL": "BLOCK immediately. Escalate to IR team. Create incident ticket.",
}

# ---------------------------------------------------------------------------
# OTX pulse score calculation
# ---------------------------------------------------------------------------

OTX_PULSE_SCORE_MULTIPLIER = 8  # pulse_count × 8, capped at 100

# ---------------------------------------------------------------------------
# HTTP defaults
# ---------------------------------------------------------------------------

DEFAULT_TIMEOUT_SECONDS = 15
DEFAULT_RATE_LIMIT_DELAY = 0.5  # seconds between requests to the same source
MAX_RETRIES = 3
RETRY_BACKOFF_BASE = 2  # exponential: 2^attempt seconds

# ---------------------------------------------------------------------------
# Default paths
# ---------------------------------------------------------------------------

DEFAULT_DB_PATH = "~/.threatsentinel/cases.db"
DEFAULT_CACHE_TTL = 3600  # seconds
DEFAULT_BASELINE_FILE = ".threatsentinel-baseline.yaml"
DEFAULT_ATTACK_BUNDLE_PATH = "~/.threatsentinel/enterprise-attack.json"
LOCAL_TAG_MAP_PATH = "data/tag_to_technique.json"  # relative to package root

# ---------------------------------------------------------------------------
# IOC type → applicable enrichers mapping
# Enrichers not in the list for an IOC type are skipped automatically.
# ---------------------------------------------------------------------------

IOC_ENRICHER_MAP: dict[str, list[str]] = {
    "ipv4": ["virustotal", "abuseipdb", "otx", "greynoise", "urlhaus", "shodan"],
    "ipv6": ["virustotal", "abuseipdb", "otx", "greynoise"],
    "domain": ["virustotal", "otx", "urlhaus"],
    "url": ["virustotal", "otx", "urlhaus"],
    "md5": ["virustotal", "malwarebazaar"],
    "sha1": ["virustotal", "malwarebazaar"],
    "sha256": ["virustotal", "malwarebazaar"],
    "email": ["otx"],
    "unknown": [],
}