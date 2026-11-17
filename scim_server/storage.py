"""SQLite persistence layer for SCIM 2.0 Users, Groups, and audit events."""
import json
import sqlite3
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

DB_PATH = Path("scim_directory.db")


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def get_conn() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    with get_conn() as conn:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS users (
                id TEXT PRIMARY KEY,
                external_id TEXT,
                user_name TEXT UNIQUE NOT NULL,
                payload_json TEXT NOT NULL,
                active INTEGER NOT NULL DEFAULT 1,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS groups (
                id TEXT PRIMARY KEY,
                external_id TEXT,
                display_name TEXT UNIQUE NOT NULL,
                members_json TEXT NOT NULL DEFAULT '[]',
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS jml_audit_log (
                event_id TEXT PRIMARY KEY,
                timestamp TEXT NOT NULL,
                action TEXT NOT NULL,
                resource_type TEXT NOT NULL,
                resource_id TEXT NOT NULL,
                summary TEXT NOT NULL
            );
            """
        )


def log_jml_event(conn: sqlite3.Connection, action: str, resource_type: str, resource_id: str, summary: str) -> None:
    conn.execute(
        "INSERT INTO jml_audit_log (event_id, timestamp, action, resource_type, resource_id, summary) VALUES (?, ?, ?, ?, ?, ?)",
        (str(uuid.uuid4()), _utc_now(), action, resource_type, resource_id, summary),
    )


def format_user_resource(row: sqlite3.Row, base_url: str) -> Dict[str, Any]:
    data = json.loads(row["payload_json"])
    data["id"] = row["id"]
    data["active"] = bool(row["active"])
    data["meta"] = {
        "resourceType": "User",
        "created": row["created_at"],
        "lastModified": row["updated_at"],
        "location": f"{base_url}/scim/v2/Users/{row['id']}",
    }
    return data


def format_group_resource(row: sqlite3.Row, base_url: str) -> Dict[str, Any]:
    return {
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
        "id": row["id"],
        "externalId": row["external_id"],
        "displayName": row["display_name"],
        "members": json.loads(row["members_json"]),
        "meta": {
            "resourceType": "Group",
            "created": row["created_at"],
            "lastModified": row["updated_at"],
            "location": f"{base_url}/scim/v2/Groups/{row['id']}",
        },
    }


def list_audit_events(limit: int = 50) -> List[Dict[str, Any]]:
    with get_conn() as conn:
        rows = conn.execute(
            "SELECT * FROM jml_audit_log ORDER BY timestamp DESC LIMIT ?", (limit,)
        ).fetchall()
    return [dict(r) for r in rows]