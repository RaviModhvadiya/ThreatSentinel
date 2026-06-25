"""Application state and configuration loader.

Reads API keys and settings from environment variables (or a .env file if
python-dotenv is installed). All fields have safe defaults so the tool
degrades gracefully when optional keys are absent.
"""

from __future__ import annotations

import os
from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class AppConfig(BaseSettings):
    """ThreatSentinel runtime configuration.

    Values are read from environment variables. A .env file in the current
    working directory is automatically loaded if present.
    """

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # --- Required API keys (tool works without them but results are incomplete) ---
    virustotal_api_key: str = Field(default="", alias="VIRUSTOTAL_API_KEY")
    abuseipdb_api_key: str = Field(default="", alias="ABUSEIPDB_API_KEY")
    otx_api_key: str = Field(default="", alias="OTX_API_KEY")

    # --- Optional API keys ---
    greynoise_api_key: str = Field(default="", alias="GREYNOISE_API_KEY")
    shodan_api_key: str = Field(default="", alias="SHODAN_API_KEY")

    # --- ThreatSentinel settings ---
    ts_db_path: str = Field(default="~/.threatsentinel/cases.db", alias="TS_DB_PATH")
    ts_cache_ttl: int = Field(default=3600, alias="TS_CACHE_TTL")
    ts_timeout: int = Field(default=15, alias="TS_TIMEOUT")
    ts_log_level: str = Field(default="INFO", alias="TS_LOG_LEVEL")
    ts_rate_limit_delay: float = Field(default=0.5, alias="TS_RATE_LIMIT_DELAY")
    ts_baseline_file: str = Field(
        default=".threatsentinel-baseline.yaml", alias="TS_BASELINE_FILE"
    )
    ts_attack_bundle_path: str = Field(
        default="~/.threatsentinel/enterprise-attack.json",
        alias="TS_ATTACK_BUNDLE_PATH",
    )

    @property
    def db_path(self) -> Path:
        """Resolved absolute path to the SQLite database file."""
        p = Path(self.ts_db_path).expanduser().resolve()
        p.parent.mkdir(parents=True, exist_ok=True)
        return p

    @property
    def baseline_path(self) -> Path:
        """Resolved absolute path to the suppression baseline YAML."""
        return Path(self.ts_baseline_file).expanduser().resolve()

    @property
    def attack_bundle_path(self) -> Path:
        """Resolved absolute path to the local ATT&CK STIX bundle."""
        return Path(self.ts_attack_bundle_path).expanduser().resolve()

    def missing_keys(self) -> list[str]:
        """Return names of recommended (non-optional) keys that are empty."""
        missing = []
        if not self.virustotal_api_key:
            missing.append("VIRUSTOTAL_API_KEY")
        if not self.abuseipdb_api_key:
            missing.append("ABUSEIPDB_API_KEY")
        if not self.otx_api_key:
            missing.append("OTX_API_KEY")
        return missing

    def masked(self) -> dict[str, str]:
        """Return config dict with secrets masked for display."""

        def mask(v: str) -> str:
            if not v:
                return "(not set)"
            return v[:4] + "..." + v[-4:] if len(v) > 8 else "****"

        return {
            "VIRUSTOTAL_API_KEY": mask(self.virustotal_api_key),
            "ABUSEIPDB_API_KEY": mask(self.abuseipdb_api_key),
            "OTX_API_KEY": mask(self.otx_api_key),
            "GREYNOISE_API_KEY": mask(self.greynoise_api_key),
            "SHODAN_API_KEY": mask(self.shodan_api_key),
            "TS_DB_PATH": self.ts_db_path,
            "TS_CACHE_TTL": str(self.ts_cache_ttl),
            "TS_TIMEOUT": str(self.ts_timeout),
            "TS_LOG_LEVEL": self.ts_log_level,
            "TS_RATE_LIMIT_DELAY": str(self.ts_rate_limit_delay),
            "TS_BASELINE_FILE": self.ts_baseline_file,
        }


# Module-level singleton — import this wherever config is needed.
_config: AppConfig | None = None


def get_config() -> AppConfig:
    """Return the global AppConfig singleton, loading it on first call."""
    global _config
    if _config is None:
        _config = AppConfig()
    return _config


def reload_config() -> AppConfig:
    """Force reload the config (useful for tests or after .env changes)."""
    global _config
    _config = AppConfig()
    return _config