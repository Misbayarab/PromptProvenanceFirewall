
import sqlite3
from pathlib import Path
from typing import Optional


# Keep the database in the project root, regardless of the launch directory.
DATABASE_NAME = str(
    Path(__file__).resolve().parent.parent / "security_events.db"
)


def create_database():
    """Create the security event table and migrate older databases safely."""
    with sqlite3.connect(DATABASE_NAME) as connection:
        cursor = connection.cursor()

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS security_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                source_name TEXT,
                trust_level TEXT,
                action TEXT,
                allowed INTEGER,
                reason TEXT,
                risk TEXT DEFAULT 'low',
                risk_score INTEGER DEFAULT 0,
                injection_detected INTEGER DEFAULT NULL
            )
        """)

        cursor.execute("PRAGMA table_info(security_events)")
        columns = {row[1] for row in cursor.fetchall()}

        # Add missing columns to an existing database without deleting events.
        migrations = {
            "risk": "ALTER TABLE security_events ADD COLUMN risk TEXT DEFAULT 'low'",
            "risk_score": "ALTER TABLE security_events ADD COLUMN risk_score INTEGER DEFAULT 0",
            "injection_detected": (
                "ALTER TABLE security_events "
                "ADD COLUMN injection_detected INTEGER DEFAULT NULL"
            ),
        }

        for column, statement in migrations.items():
            if column not in columns:
                cursor.execute(statement)


def save_security_event(
    timestamp: str,
    source_name: str,
    trust_level: str,
    action: str,
    allowed: bool,
    reason: str,
    risk: str = "low",
    risk_score: int = 0,
    injection_detected: Optional[bool] = None,
):
    """Save one event, including injection status when the caller supplies it."""
    with sqlite3.connect(DATABASE_NAME) as connection:
        connection.execute("""
            INSERT INTO security_events (
                timestamp,
                source_name,
                trust_level,
                action,
                allowed,
                reason,
                risk,
                risk_score,
                injection_detected
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            timestamp,
            source_name,
            trust_level,
            action,
            int(allowed),
            reason,
            risk,
            risk_score,
            (
                None if injection_detected is None
                else int(injection_detected)
            ),
        ))


def get_security_events():
    """Return saved events, newest first."""
    with sqlite3.connect(DATABASE_NAME) as connection:
        connection.row_factory = sqlite3.Row
        rows = connection.execute("""
            SELECT
                id,
                timestamp,
                source_name,
                trust_level,
                action,
                allowed,
                reason,
                risk,
                risk_score,
                injection_detected
            FROM security_events
            ORDER BY id DESC
        """).fetchall()

    events = []

    for row in rows:
        events.append({
            "id": row["id"],
            "timestamp": row["timestamp"],
            "source_name": row["source_name"],
            "trust_level": row["trust_level"],
            "action": row["action"],
            "allowed": (
                None if row["allowed"] is None
                else bool(row["allowed"])
            ),
            "reason": row["reason"],
            "risk": row["risk"],
            "risk_score": row["risk_score"],
            "injection_detected": (
                None
                if row["injection_detected"] is None
                else bool(row["injection_detected"])
            ),
        })

    return events
