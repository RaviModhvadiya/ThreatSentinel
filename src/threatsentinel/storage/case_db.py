"""SQLite-backed case management — aiosqlite for async operations.

All database queries use parameterised statements to prevent SQL injection.
The database file is auto-created at first use; no migrations required.
"""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any

import aiosqlite

from threatsentinel.logging_config import get_logger
from threatsentinel.models import CaseStatus, Disposition, InvestigationResult, Severity

logger = get_logger(__name__)

CREATE_CASES = """
CREATE TABLE IF NOT EXISTS cases (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    name        TEXT    NOT NULL UNIQUE,
    description TEXT    DEFAULT '',
    status      TEXT    NOT NULL DEFAULT 'open',
    created_at  TEXT    NOT NULL,
    updated_at  TEXT    NOT NULL
)
"""

CREATE_IOC_RECORDS = """
CREATE TABLE IF NOT EXISTS ioc_records (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id             INTEGER NOT NULL REFERENCES cases(id),
    value               TEXT    NOT NULL,
    ioc_type            TEXT    NOT NULL,
    risk_score          INTEGER NOT NULL DEFAULT 0,
    risk_label          TEXT    NOT NULL DEFAULT 'INFORMATIONAL',
    disposition         TEXT    NOT NULL DEFAULT 'new',
    analyst_note        TEXT    DEFAULT '',
    enrichment_json     TEXT    DEFAULT '{}',
    mitre_json          TEXT    DEFAULT '[]',
    campaign            TEXT,
    first_investigated  TEXT    NOT NULL,
    last_investigated   TEXT    NOT NULL,
    UNIQUE(case_id, value)
)
"""

CREATE_CASE_NOTES = """
CREATE TABLE IF NOT EXISTS case_notes (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id    INTEGER NOT NULL REFERENCES cases(id),
    note_text  TEXT    NOT NULL,
    added_by   TEXT    DEFAULT '',
    added_at   TEXT    NOT NULL
)
"""

CREATE_MITRE_FINDINGS = """
CREATE TABLE IF NOT EXISTS mitre_findings (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    ioc_record_id INTEGER NOT NULL REFERENCES ioc_records(id),
    technique_id  TEXT NOT NULL,
    name          TEXT NOT NULL,
    tactic        TEXT NOT NULL,
    confidence    REAL NOT NULL DEFAULT 0.5
)
"""


class CaseDB:
    """Async SQLite case management interface."""

    def __init__(self, db_path: Path) -> None:
        self.db_path = db_path

    async def _connect(self) -> aiosqlite.Connection:
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        conn = await aiosqlite.connect(str(self.db_path))
        await conn.execute("PRAGMA foreign_keys = ON")
        await conn.execute("PRAGMA journal_mode = WAL")
        return conn

    async def init_db(self) -> None:
        """Create all tables if they do not exist."""
        async with await self._connect() as conn:
            await conn.execute(CREATE_CASES)
            await conn.execute(CREATE_IOC_RECORDS)
            await conn.execute(CREATE_CASE_NOTES)
            await conn.execute(CREATE_MITRE_FINDINGS)
            await conn.commit()
        logger.debug("Database initialized at %s", self.db_path)

    # -----------------------------------------------------------------------
    # Case CRUD
    # -----------------------------------------------------------------------

    async def create_case(self, name: str, description: str = "") -> int:
        """Create a new case. Returns the new case ID."""
        now = datetime.utcnow().isoformat()
        async with await self._connect() as conn:
            cursor = await conn.execute(
                "INSERT INTO cases (name, description, status, created_at, updated_at) "
                "VALUES (?, ?, 'open', ?, ?)",
                (name, description, now, now),
            )
            await conn.commit()
            case_id = cursor.lastrowid
        logger.info("Created case %r (id=%d)", name, case_id)
        return case_id

    async def get_case(self, name: str) -> dict[str, Any] | None:
        """Fetch a case by name."""
        async with await self._connect() as conn:
            conn.row_factory = aiosqlite.Row
            async with conn.execute(
                "SELECT * FROM cases WHERE name = ?", (name,)
            ) as cursor:
                row = await cursor.fetchone()
                return dict(row) if row else None

    async def list_cases(self) -> list[dict[str, Any]]:
        """Return all cases ordered by updated_at descending."""
        async with await self._connect() as conn:
            conn.row_factory = aiosqlite.Row
            async with conn.execute(
                "SELECT c.*, COUNT(r.id) as ioc_count "
                "FROM cases c LEFT JOIN ioc_records r ON r.case_id = c.id "
                "GROUP BY c.id ORDER BY c.updated_at DESC"
            ) as cursor:
                rows = await cursor.fetchall()
                return [dict(r) for r in rows]

    async def update_case_status(self, name: str, status: CaseStatus) -> bool:
        """Update the status of a case. Returns True if found."""
        now = datetime.utcnow().isoformat()
        async with await self._connect() as conn:
            cursor = await conn.execute(
                "UPDATE cases SET status = ?, updated_at = ? WHERE name = ?",
                (status.value, now, name),
            )
            await conn.commit()
            return cursor.rowcount > 0

    async def delete_case(self, name: str) -> bool:
        """Delete a case and all associated records. Returns True if found."""
        async with await self._connect() as conn:
            case = await self.get_case(name)
            if not case:
                return False
            await conn.execute("DELETE FROM ioc_records WHERE case_id = ?", (case["id"],))
            await conn.execute("DELETE FROM case_notes WHERE case_id = ?", (case["id"],))
            await conn.execute("DELETE FROM cases WHERE id = ?", (case["id"],))
            await conn.commit()
        logger.info("Deleted case %r", name)
        return True

    # -----------------------------------------------------------------------
    # IOC Record CRUD
    # -----------------------------------------------------------------------

    async def upsert_ioc(self, case_name: str, result: InvestigationResult) -> None:
        """Insert or update an IOC record within a case."""
        case = await self.get_case(case_name)
        if not case:
            await self.create_case(case_name)
            case = await self.get_case(case_name)

        now = datetime.utcnow().isoformat()
        enrichment_json = json.dumps(result.enrichment.model_dump())
        mitre_json = json.dumps([t.model_dump() for t in result.mitre_techniques])

        async with await self._connect() as conn:
            await conn.execute(
                """
                INSERT INTO ioc_records
                    (case_id, value, ioc_type, risk_score, risk_label, disposition,
                     enrichment_json, mitre_json, campaign, first_investigated, last_investigated)
                VALUES (?, ?, ?, ?, ?, 'new', ?, ?, ?, ?, ?)
                ON CONFLICT(case_id, value) DO UPDATE SET
                    risk_score         = excluded.risk_score,
                    risk_label         = excluded.risk_label,
                    enrichment_json    = excluded.enrichment_json,
                    mitre_json         = excluded.mitre_json,
                    campaign           = excluded.campaign,
                    last_investigated  = excluded.last_investigated
                """,
                (
                    case["id"],
                    result.ioc.value,
                    result.ioc.ioc_type.value,
                    result.risk_score,
                    result.risk_label.value,
                    enrichment_json,
                    mitre_json,
                    result.campaign,
                    now,
                    now,
                ),
            )
            # Update case updated_at
            await conn.execute(
                "UPDATE cases SET updated_at = ? WHERE id = ?", (now, case["id"])
            )
            await conn.commit()

    async def update_disposition(
        self, case_name: str, ioc_value: str, disposition: Disposition
    ) -> bool:
        """Update the disposition of an IOC in a case."""
        case = await self.get_case(case_name)
        if not case:
            return False
        async with await self._connect() as conn:
            cursor = await conn.execute(
                "UPDATE ioc_records SET disposition = ? WHERE case_id = ? AND value = ?",
                (disposition.value, case["id"], ioc_value),
            )
            await conn.commit()
            return cursor.rowcount > 0

    async def update_analyst_note(
        self, case_name: str, ioc_value: str, note: str
    ) -> bool:
        """Update freeform analyst note on an IOC record."""
        case = await self.get_case(case_name)
        if not case:
            return False
        async with await self._connect() as conn:
            cursor = await conn.execute(
                "UPDATE ioc_records SET analyst_note = ? WHERE case_id = ? AND value = ?",
                (note, case["id"], ioc_value),
            )
            await conn.commit()
            return cursor.rowcount > 0

    async def get_case_iocs(self, case_name: str) -> list[dict[str, Any]]:
        """Return all IOC records for a case."""
        case = await self.get_case(case_name)
        if not case:
            return []
        async with await self._connect() as conn:
            conn.row_factory = aiosqlite.Row
            async with conn.execute(
                "SELECT * FROM ioc_records WHERE case_id = ? ORDER BY risk_score DESC",
                (case["id"],),
            ) as cursor:
                rows = await cursor.fetchall()
                return [dict(r) for r in rows]

    # -----------------------------------------------------------------------
    # Case notes
    # -----------------------------------------------------------------------

    async def add_note(self, case_name: str, text: str, added_by: str = "") -> None:
        """Add a freeform note to a case."""
        case = await self.get_case(case_name)
        if not case:
            raise ValueError(f"Case {case_name!r} not found")
        now = datetime.utcnow().isoformat()
        async with await self._connect() as conn:
            await conn.execute(
                "INSERT INTO case_notes (case_id, note_text, added_by, added_at) VALUES (?, ?, ?, ?)",
                (case["id"], text, added_by, now),
            )
            await conn.commit()

    # -----------------------------------------------------------------------
    # Threat hunting queries
    # -----------------------------------------------------------------------

    async def hunt_by_ttp(self, technique_id: str) -> list[dict[str, Any]]:
        """Find all IOC records that contain a specific ATT&CK technique."""
        async with await self._connect() as conn:
            conn.row_factory = aiosqlite.Row
            async with conn.execute(
                "SELECT r.*, c.name as case_name FROM ioc_records r "
                "JOIN cases c ON r.case_id = c.id "
                "WHERE r.mitre_json LIKE ?",
                (f'%{technique_id}%',),
            ) as cursor:
                rows = await cursor.fetchall()
                return [dict(r) for r in rows]

    async def hunt_by_min_risk(self, min_score: int) -> list[dict[str, Any]]:
        """Find all IOC records with risk_score >= min_score."""
        async with await self._connect() as conn:
            conn.row_factory = aiosqlite.Row
            async with conn.execute(
                "SELECT r.*, c.name as case_name FROM ioc_records r "
                "JOIN cases c ON r.case_id = c.id "
                "WHERE r.risk_score >= ? ORDER BY r.risk_score DESC",
                (min_score,),
            ) as cursor:
                rows = await cursor.fetchall()
                return [dict(r) for r in rows]

    async def hunt_by_actor(self, actor: str) -> list[dict[str, Any]]:
        """Find IOC records attributed to a threat actor (case-insensitive)."""
        async with await self._connect() as conn:
            conn.row_factory = aiosqlite.Row
            async with conn.execute(
                "SELECT r.*, c.name as case_name FROM ioc_records r "
                "JOIN cases c ON r.case_id = c.id "
                "WHERE LOWER(r.campaign) LIKE ?",
                (f'%{actor.lower()}%',),
            ) as cursor:
                rows = await cursor.fetchall()
                return [dict(r) for r in rows]

    async def hunt_by_date_range(self, after: str, before: str) -> list[dict[str, Any]]:
        """Find IOC records investigated within a date range (ISO strings)."""
        async with await self._connect() as conn:
            conn.row_factory = aiosqlite.Row
            async with conn.execute(
                "SELECT r.*, c.name as case_name FROM ioc_records r "
                "JOIN cases c ON r.case_id = c.id "
                "WHERE r.last_investigated BETWEEN ? AND ?",
                (after, before),
            ) as cursor:
                rows = await cursor.fetchall()
                return [dict(r) for r in rows]