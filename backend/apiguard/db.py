import aiosqlite
import json
import os
import time
import uuid
from pathlib import Path
from typing import Dict, Any, List, Optional
from apiguard.engine.models import Finding, ScanEvent

# Working directory, not the package dir: an installed package must never write into site-packages
DB_PATH = os.environ.get("APIGUARD_DB") or str(Path.cwd() / "apiguard.db")

async def init_db():
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute("PRAGMA journal_mode=WAL;")
        await db.execute("""
            CREATE TABLE IF NOT EXISTS scans (
                id TEXT PRIMARY KEY,
                target_url TEXT,
                status TEXT,
                started_at REAL,
                completed_at REAL,
                summary TEXT
            );
        """)
        await db.execute("""
            CREATE TABLE IF NOT EXISTS scan_events (
                id TEXT PRIMARY KEY,
                scan_id TEXT,
                timestamp REAL,
                event_type TEXT,
                phase TEXT,
                message TEXT,
                data TEXT
            );
        """)
        await db.execute("""
            CREATE TABLE IF NOT EXISTS findings (
                id TEXT PRIMARY KEY,
                scan_id TEXT,
                endpoint TEXT,
                method TEXT,
                resource_type TEXT,
                status TEXT,
                severity TEXT,
                confidence REAL,
                diff_fields TEXT,
                repro_curl TEXT,
                data TEXT
            );
        """)
        await db.execute("""
            CREATE TABLE IF NOT EXISTS remediations (
                id TEXT PRIMARY KEY,
                finding_id TEXT,
                timestamp REAL,
                mode TEXT,
                provider TEXT,
                model TEXT,
                v1_prompt TEXT,
                v1_output TEXT,
                v2_prompt TEXT,
                v2_output TEXT,
                code_patch TEXT,
                explanation TEXT,
                unit_test TEXT,
                error_reason TEXT,
                is_real INTEGER DEFAULT 0
            );
        """)
        try:
            await db.execute("ALTER TABLE remediations ADD COLUMN provider TEXT")
        except Exception:
            pass
        try:
            await db.execute("ALTER TABLE remediations ADD COLUMN is_real INTEGER DEFAULT 0")
        except Exception:
            pass
        await db.commit()

async def save_scan(scan_id: str, target_url: str, status: str = "running"):
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute(
            "INSERT OR REPLACE INTO scans (id, target_url, status, started_at) VALUES (?, ?, ?, ?)",
            (scan_id, target_url, status, time.time())
        )
        await db.commit()

async def save_scan_event(event: ScanEvent):
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute(
            "INSERT INTO scan_events (id, scan_id, timestamp, event_type, phase, message, data) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (event.event_id, event.scan_id, event.timestamp, event.event_type, event.phase, event.message, json.dumps(event.data or {}))
        )
        await db.commit()

async def save_finding(scan_id: str, finding: Finding):
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute(
            """INSERT OR REPLACE INTO findings 
               (id, scan_id, endpoint, method, resource_type, status, severity, confidence, diff_fields, repro_curl, data)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                finding.id, scan_id, finding.endpoint, finding.method, finding.resource_type,
                finding.status.value, finding.severity, finding.confidence,
                json.dumps(finding.diff_fields), finding.repro_curl, json.dumps(finding.model_dump())
            )
        )
        await db.commit()

async def clear_db():
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute("DELETE FROM findings")
        await db.execute("DELETE FROM scan_events")
        await db.execute("DELETE FROM scans")
        await db.execute("DELETE FROM remediations")
        await db.commit()

async def save_remediation(data: Dict[str, Any]):
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute(
            """INSERT OR REPLACE INTO remediations
               (id, finding_id, timestamp, mode, provider, model, v1_prompt, v1_output, v2_prompt, v2_output, code_patch, explanation, unit_test, error_reason, is_real)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                data.get("id", str(uuid.uuid4())),
                data.get("finding_id"),
                data.get("timestamp", time.time()),
                data.get("mode"),
                data.get("provider", "offline_template"),
                data.get("model"),
                data.get("v1_prompt"),
                data.get("v1_output"),
                data.get("v2_prompt"),
                data.get("v2_output"),
                data.get("code_patch"),
                data.get("explanation"),
                data.get("unit_test"),
                data.get("error_reason"),
                1 if data.get("is_real") else 0
            )
        )
        await db.commit()

async def get_last_real_remediation(finding_id: Optional[str] = None) -> Optional[Dict[str, Any]]:
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        query = "SELECT * FROM remediations WHERE is_real = 1"
        params: list = []
        if finding_id:
            query += " AND finding_id = ?"
            params.append(finding_id)
        query += " ORDER BY timestamp DESC LIMIT 1"
        async with db.execute(query, params) as cursor:
            row = await cursor.fetchone()
            if row:
                return dict(row)
            # If finding-specific not found, return any real recorded remediation
            if finding_id:
                async with db.execute("SELECT * FROM remediations WHERE is_real = 1 ORDER BY timestamp DESC LIMIT 1") as fallback_cur:
                    fallback_row = await fallback_cur.fetchone()
                    if fallback_row:
                        return dict(fallback_row)
    return None

async def get_findings(scan_id: Optional[str] = None) -> List[Dict[str, Any]]:
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        if scan_id:
            cursor = await db.execute("SELECT data FROM findings WHERE scan_id = ?", (scan_id,))
        else:
            cursor = await db.execute("SELECT data FROM findings")
        rows = await cursor.fetchall()
        return [json.loads(row["data"]) for row in rows]
