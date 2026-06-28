"""Suppression baseline — false-positive management.

Loads a YAML baseline file and checks IOC values against it using
exact match or glob-style patterns. Mirrors enterprise SIEM tuning.
"""

from __future__ import annotations

import fnmatch
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Optional

import yaml

from threatsentinel.logging_config import get_logger

logger = get_logger(__name__)

@dataclass
class SuppressionRule:
    """A single suppression entry from the baseline YAML."""

    ioc: str
    reason: str = ""
    added_by: str = ""
    added_at: str = ""

@dataclass
class SuppressionBaseline:
    """Loaded set of suppression rules."""

    rules: list[SuppressionRule] = field(default_factory=list)
    source_path: Optional[Path] = None

    def is_suppressed(self, ioc_value: str) -> tuple[bool, str]:
        """Check if an IOC value matches any suppression rule.

        Supports:
          - Exact string match (case-insensitive)
          - Glob patterns using fnmatch (e.g. *.microsoft.com)

        Returns:
            (suppressed: bool, reason: str)
        """
        lower = ioc_value.lower().strip()
        for rule in self.rules:
            pattern = rule.ioc.lower().strip()
            if lower == pattern or fnmatch.fnmatch(lower, pattern):
                logger.debug("IOC %r suppressed by rule %r (%s)", ioc_value, rule.ioc, rule.reason)
                return True, rule.reason
        return False, ""

    def add_rule(self, ioc: str, reason: str, added_by: str = "") -> None:
        """Add a new suppression rule (in-memory; call save() to persist)."""
        self.rules.append(
            SuppressionRule(
                ioc=ioc,
                reason=reason,
                added_by=added_by,
                added_at=datetime.utcnow().isoformat() + "Z",
            )
        )

    def remove_rule(self, ioc: str) -> bool:
        """Remove a rule by exact IOC match. Returns True if found."""
        before = len(self.rules)
        self.rules = [r for r in self.rules if r.ioc.lower() != ioc.lower()]
        return len(self.rules) < before

    def save(self, path: Path) -> None:
        """Persist current rules to YAML at the given path."""
        data = {
            "suppressions": [
                {
                    "ioc": r.ioc,
                    "reason": r.reason,
                    "added_by": r.added_by,
                    "added_at": r.added_at,
                }
                for r in self.rules
            ]
        }
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("w", encoding="utf-8") as fh:
            yaml.dump(data, fh, default_flow_style=False, allow_unicode=True)
        logger.info("Saved %d suppression rules to %s", len(self.rules), path)


def load_baseline(path: Path) -> SuppressionBaseline:
    """Load a suppression baseline from a YAML file.

    If the file does not exist, returns an empty baseline (no error).
    This allows the tool to work out-of-the-box without requiring a baseline.
    """
    baseline = SuppressionBaseline(source_path=path)

    if not path.exists():
        logger.debug("Baseline file not found at %s — starting with empty baseline", path)
        return baseline

    try:
        with path.open("r", encoding="utf-8") as fh:
            data = yaml.safe_load(fh) or {}

        for entry in data.get("suppressions", []):
            if not isinstance(entry, dict) or "ioc" not in entry:
                logger.warning("Skipping malformed baseline entry: %r", entry)
                continue
            baseline.rules.append(
                SuppressionRule(
                    ioc=entry["ioc"],
                    reason=entry.get("reason", ""),
                    added_by=entry.get("added_by", ""),
                    added_at=entry.get("added_at", ""),
                )
            )

        logger.info("Loaded %d suppression rules from %s", len(baseline.rules), path)
    except yaml.YAMLError as exc:
        logger.error("Failed to parse baseline YAML at %s: %s", path, exc)
    except OSError as exc:
        logger.error("Could not read baseline file at %s: %s", path, exc)

    return baseline