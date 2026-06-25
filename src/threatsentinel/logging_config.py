"""Structured logging configuration for ThreatSentinel."""

from __future__ import annotations

import logging
import sys


def configure_logging(level: str = "INFO") -> None:
    """Set up root logger with a clean console handler.

    Args:
        level: Log level string (DEBUG / INFO / WARNING / ERROR).
    """
    numeric_level = getattr(logging, level.upper(), logging.INFO)
    root = logging.getLogger("threatsentinel")
    root.setLevel(numeric_level)

    if not root.handlers:
        handler = logging.StreamHandler(sys.stderr)
        handler.setLevel(numeric_level)
        fmt = logging.Formatter(
            fmt="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
            datefmt="%Y-%m-%dT%H:%M:%S",
        )
        handler.setFormatter(fmt)
        root.addHandler(handler)

    # Suppress noisy third-party loggers
    for noisy in ("httpx", "httpcore", "asyncio"):
        logging.getLogger(noisy).setLevel(logging.WARNING)


def get_logger(name: str) -> logging.Logger:
    """Return a child logger under the threatsentinel namespace."""
    return logging.getLogger(f"threatsentinel.{name}")