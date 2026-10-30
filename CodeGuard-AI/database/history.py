"""
CodeGuard AI 2.0 - SQLite History Manager
Robust persistent storage with auto-migration, parameterization, and record deletion.
"""
from __future__ import annotations
import sqlite3
import json
import uuid
import hashlib
from datetime import datetime
from typing import List, Optional, Dict, Any
from pathlib import Path
from config.settings import DB_PATH
from core.schemas import ReviewRecord, ReviewResult, CodeIssue


def _get_connection() -> sqlite3.Connection:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    """Initialize or migrate review database schema."""
    conn = _get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS review_history (
            review_id       TEXT PRIMARY KEY,
            timestamp       TEXT NOT NULL,
            language        TEXT,
            filename        TEXT,
            lines_of_code   INTEGER,
            total_issues    INTEGER,
            critical_count  INTEGER,
            high_count      INTEGER,
            overall_quality TEXT,
            analysis_mode   TEXT,
            summary         TEXT,
            source_hash     TEXT,
            duration_sec    REAL,
            issues_json     TEXT
        )
    """)
    conn.commit()

    # Migration check: Ensure new columns exist if migrating from v1
    cursor.execute("PRAGMA table_info(review_history)")
    columns = [row["name"] for row in cursor.fetchall()]
    if "source_hash" not in columns:
        cursor.execute("ALTER TABLE review_history ADD COLUMN source_hash TEXT")
    if "duration_sec" not in columns:
        cursor.execute("ALTER TABLE review_history ADD COLUMN duration_sec REAL")
    conn.commit()
    conn.close()


init_db()


def save_review(result: ReviewResult, filename: Optional[str], lines: int, source_code: Optional[str] = None) -> Optional[str]:
    """Persist a review result with source hash and duration."""
    try:
        rid = result.review_id or f"REV-{uuid.uuid4().hex[:8].upper()}"
        ts = datetime.now().isoformat(timespec="seconds")
        crit = sum(1 for i in result.issues if i.severity == "Critical")
        high = sum(1 for i in result.issues if i.severity == "High")

        src_hash = hashlib.sha256(source_code.encode("utf-8")).hexdigest()[:12] if source_code else None
        issues_json = json.dumps([i.model_dump() for i in result.issues])

        conn = _get_connection()
        conn.execute("""
            INSERT OR REPLACE INTO review_history
            (review_id, timestamp, language, filename, lines_of_code, total_issues,
             critical_count, high_count, overall_quality, analysis_mode, summary,
             source_hash, duration_sec, issues_json)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            rid, ts, result.language, filename, lines, len(result.issues),
            crit, high, result.overall_quality, result.analysis_mode,
            result.summary, src_hash, result.analysis_duration_sec, issues_json
        ))
        conn.commit()
        conn.close()
        return rid
    except Exception:
        return None


def get_all_reviews() -> List[ReviewRecord]:
    """Retrieve all saved review summaries sorted by latest first."""
    try:
        conn = _get_connection()
        rows = conn.execute("SELECT * FROM review_history ORDER BY timestamp DESC").fetchall()
        conn.close()
        records = []
        for r in rows:
            d = dict(r)
            d.pop("issues_json", None)
            records.append(ReviewRecord(**d))
        return records
    except Exception:
        return []


def get_review_by_id(review_id: str) -> Optional[Dict[str, Any]]:
    """Retrieve full review details and issues by ID."""
    try:
        conn = _get_connection()
        row = conn.execute("SELECT * FROM review_history WHERE review_id = ?", (review_id,)).fetchone()
        conn.close()
        if row:
            data = dict(row)
            data["issues"] = json.loads(data.get("issues_json", "[]"))
            return data
        return None
    except Exception:
        return None


def delete_review(review_id: str) -> bool:
    """Delete a single review record."""
    try:
        conn = _get_connection()
        conn.execute("DELETE FROM review_history WHERE review_id = ?", (review_id,))
        conn.commit()
        conn.close()
        return True
    except Exception:
        return False
