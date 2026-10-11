import sqlite3


DATABASE_NAME = "security_events.db"


def create_database():

    connection = sqlite3.connect(DATABASE_NAME)

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
            risk TEXT,
            risk_score INTEGER
        )
    """)

    # Add risk columns if an older database already exists
    cursor.execute("""
        PRAGMA table_info(security_events)
    """)

    columns = [
        row[1]
        for row in cursor.fetchall()
    ]

    if "risk" not in columns:

        cursor.execute("""
            ALTER TABLE security_events
            ADD COLUMN risk TEXT DEFAULT 'low'
        """)

    if "risk_score" not in columns:

        cursor.execute("""
            ALTER TABLE security_events
            ADD COLUMN risk_score INTEGER DEFAULT 0
        """)

    connection.commit()
    connection.close()


def save_security_event(
    timestamp: str,
    source_name: str,
    trust_level: str,
    action: str,
    allowed: bool,
    reason: str,
    risk: str = "low",
    risk_score: int = 0
):

    connection = sqlite3.connect(
        DATABASE_NAME
    )

    cursor = connection.cursor()

    cursor.execute("""
        INSERT INTO security_events
        (
            timestamp,
            source_name,
            trust_level,
            action,
            allowed,
            reason,
            risk,
            risk_score
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        timestamp,
        source_name,
        trust_level,
        action,
        int(allowed),
        reason,
        risk,
        risk_score
    ))

    connection.commit()
    connection.close()


def get_security_events():

    connection = sqlite3.connect(
        DATABASE_NAME
    )

    cursor = connection.cursor()

    cursor.execute("""
        SELECT
            id,
            timestamp,
            source_name,
            trust_level,
            action,
            allowed,
            reason,
            risk,
            risk_score
        FROM security_events
        ORDER BY id DESC
    """)

    rows = cursor.fetchall()

    connection.close()

    events = []

    for row in rows:

        events.append({
            "id": row[0],
            "timestamp": row[1],
            "source_name": row[2],
            "trust_level": row[3],
            "action": row[4],
            "allowed": bool(row[5]),
            "reason": row[6],
            "risk": row[7],
            "risk_score": row[8]
        })

    return events