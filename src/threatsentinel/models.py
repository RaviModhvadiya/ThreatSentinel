"""Core data models for ThreatSentinel.

All shared Pydantic models used across enrichers, analyzers, reporters,
and storage layers. Import from here — never create duplicate model classes.
"""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class IOCType(StrEnum):
    IPV4 = "ipv4"
    IPV6 = "ipv6"
    DOMAIN = "domain"
    URL = "url"
    MD5 = "md5"
    SHA1 = "sha1"
    SHA256 = "sha256"
    EMAIL = "email"
    UNKNOWN = "unknown"


class Severity(StrEnum):
    INFORMATIONAL = "INFORMATIONAL"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class Disposition(StrEnum):
    NEW = "new"
    INVESTIGATING = "investigating"
    BLOCKED = "blocked"
    FALSE_POSITIVE = "false-positive"
    ESCALATED = "escalated"
    CLOSED = "closed"


class CaseStatus(StrEnum):
    OPEN = "open"
    IN_PROGRESS = "in-progress"
    CLOSED = "closed"


# ---------------------------------------------------------------------------
# IOC Record
# ---------------------------------------------------------------------------


class IOCRecord(BaseModel):
    """A parsed and validated indicator of compromise."""

    value: str
    ioc_type: IOCType
    normalized: str  # lowercase, stripped version for API queries


# ---------------------------------------------------------------------------
# Per-source enrichment results
# ---------------------------------------------------------------------------


class VTResult(BaseModel):
    """VirusTotal scan result."""

    malicious: int = 0
    suspicious: int = 0
    harmless: int = 0
    undetected: int = 0
    total_engines: int = 0
    categories: list[str] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)
    score: float = 0.0
    available: bool = True
    error: str | None = None


class AbuseIPDBResult(BaseModel):
    """AbuseIPDB lookup result (IP-only)."""

    abuse_confidence_score: int = 0
    total_reports: int = 0
    country_code: str | None = None
    isp: str | None = None
    domain: str | None = None
    is_whitelisted: bool = False
    score: float = 0.0
    available: bool = True
    error: str | None = None


class OTXResult(BaseModel):
    """AlienVault OTX pulse result."""

    pulse_count: int = 0
    tags: list[str] = Field(default_factory=list)
    malware_families: list[str] = Field(default_factory=list)
    adversary: str | None = None
    references: list[str] = Field(default_factory=list)
    score: float = 0.0
    available: bool = True
    error: str | None = None


class GreyNoiseResult(BaseModel):
    """GreyNoise classification result (IP-only)."""

    classification: str = "unknown"  # benign / malicious / unknown
    name: str | None = None
    tags: list[str] = Field(default_factory=list)
    score: float = 0.0
    available: bool = True
    error: str | None = None


class URLhausResult(BaseModel):
    """URLhaus threat intelligence result."""

    query_status: str = "no_results"  # ok / no_results / is_whitelisted
    url_status: str | None = None  # online / offline
    tags: list[str] = Field(default_factory=list)
    urlhaus_reference: str | None = None
    score: float = 0.0
    available: bool = True
    error: str | None = None


class MalwareBazaarResult(BaseModel):
    """MalwareBazaar file hash lookup result (hash-only)."""

    query_status: str = "hash_not_found"
    file_type: str | None = None
    file_name: str | None = None
    malware_family: str | None = None
    tags: list[str] = Field(default_factory=list)
    yara_rules: list[str] = Field(default_factory=list)
    score: float = 0.0
    available: bool = True
    error: str | None = None


class ShodanResult(BaseModel):
    """Shodan host data (IP-only, optional)."""

    ports: list[int] = Field(default_factory=list)
    hostnames: list[str] = Field(default_factory=list)
    country: str | None = None
    org: str | None = None
    asn: str | None = None
    tags: list[str] = Field(default_factory=list)
    available: bool = True
    error: str | None = None


# ---------------------------------------------------------------------------
# Aggregated enrichment bundle
# ---------------------------------------------------------------------------


class EnrichmentBundle(BaseModel):
    """Container for all enrichment source results for one IOC."""

    virustotal: VTResult = Field(default_factory=VTResult)
    abuseipdb: AbuseIPDBResult = Field(default_factory=AbuseIPDBResult)
    otx: OTXResult = Field(default_factory=OTXResult)
    greynoise: GreyNoiseResult = Field(default_factory=GreyNoiseResult)
    urlhaus: URLhausResult = Field(default_factory=URLhausResult)
    malwarebazaar: MalwareBazaarResult = Field(default_factory=MalwareBazaarResult)
    shodan: ShodanResult = Field(default_factory=ShodanResult)

    def all_tags(self) -> list[str]:
        """Collect and normalize all tags from every source."""
        raw: list[str] = []
        raw.extend(self.virustotal.tags)
        raw.extend(self.virustotal.categories)
        raw.extend(self.otx.tags)
        raw.extend(self.otx.malware_families)
        raw.extend(self.greynoise.tags)
        raw.extend(self.urlhaus.tags)
        raw.extend(self.malwarebazaar.tags)
        raw.extend(self.shodan.tags)
        return list({t.lower().strip() for t in raw if t})


# ---------------------------------------------------------------------------
# Analysis results
# ---------------------------------------------------------------------------


class MITRETechnique(BaseModel):
    """A single ATT&CK technique finding with confidence."""

    technique_id: str
    name: str
    tactic: str
    confidence: float = Field(ge=0.0, le=1.0, default=0.5)


class InvestigationResult(BaseModel):
    """Complete investigation result for a single IOC."""

    ioc: IOCRecord
    risk_score: int = Field(ge=0, le=100, default=0)
    risk_label: Severity = Severity.INFORMATIONAL
    recommendation: str = ""
    enrichment: EnrichmentBundle = Field(default_factory=EnrichmentBundle)
    mitre_techniques: list[MITRETechnique] = Field(default_factory=list)
    campaign: str | None = None
    first_seen: str | None = None
    last_seen: str | None = None
    suppressed: bool = False
    investigated_at: datetime = Field(default_factory=datetime.utcnow)
    case_name: str | None = None

    def to_ecs(self) -> dict[str, Any]:
        """Serialize to Elastic Common Schema (ECS) compatible dict."""
        return {
            "threatsentinel": {"version": "1.0.0", "generated_at": self.investigated_at.isoformat() + "Z"},
            "event": {"kind": "alert", "category": "threat", "type": "indicator"},
            "threat": {
                "indicator": {
                    "type": self.ioc.ioc_type.value,
                    "value": self.ioc.value,
                    "first_seen": self.first_seen,
                    "last_seen": self.last_seen,
                },
                "framework": "MITRE ATT&CK",
                "technique": [
                    {"id": t.technique_id, "name": t.name, "tactic": t.tactic}
                    for t in self.mitre_techniques
                ],
            },
            "risk_score": self.risk_score,
            "risk_label": self.risk_label.value,
            "enrichment": {
                "virustotal": {
                    "malicious": self.enrichment.virustotal.malicious,
                    "total_engines": self.enrichment.virustotal.total_engines,
                    "score": self.enrichment.virustotal.score,
                },
                "abuseipdb": {
                    "abuse_confidence_score": self.enrichment.abuseipdb.abuse_confidence_score,
                    "total_reports": self.enrichment.abuseipdb.total_reports,
                },
                "otx": {
                    "pulse_count": self.enrichment.otx.pulse_count,
                    "tags": self.enrichment.otx.tags,
                },
                "greynoise": {
                    "classification": self.enrichment.greynoise.classification,
                    "name": self.enrichment.greynoise.name,
                },
                "urlhaus": {
                    "status": self.enrichment.urlhaus.url_status,
                    "tags": self.enrichment.urlhaus.tags,
                },
                "malwarebazaar": {
                    "status": self.enrichment.malwarebazaar.query_status,
                    "family": self.enrichment.malwarebazaar.malware_family,
                },
            },
            "mitre_attack": [
                {"technique_id": t.technique_id, "confidence": t.confidence}
                for t in self.mitre_techniques
            ],
            "recommendation": self.recommendation,
            "campaign": self.campaign,
            "suppressed": self.suppressed,
            "case": self.case_name,
        }


# ---------------------------------------------------------------------------
# Bulk / hunt result containers
# ---------------------------------------------------------------------------


class BulkResult(BaseModel):
    """Result of a bulk IOC investigation."""

    results: list[InvestigationResult] = Field(default_factory=list)
    total: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    informational_count: int = 0
    suppressed_count: int = 0
    error_count: int = 0
    investigated_at: datetime = Field(default_factory=datetime.utcnow)
    case_name: str | None = None

    def tally(self) -> None:
        """Recompute all counter fields from results list."""
        self.total = len(self.results)
        self.critical_count = sum(1 for r in self.results if r.risk_label == Severity.CRITICAL)
        self.high_count = sum(1 for r in self.results if r.risk_label == Severity.HIGH)
        self.medium_count = sum(1 for r in self.results if r.risk_label == Severity.MEDIUM)
        self.low_count = sum(1 for r in self.results if r.risk_label == Severity.LOW)
        self.informational_count = sum(
            1 for r in self.results if r.risk_label == Severity.INFORMATIONAL
        )
        self.suppressed_count = sum(1 for r in self.results if r.suppressed)