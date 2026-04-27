"""
database.py — SQLite database for SOC IDS
Creates and manages persistent storage for alerts, logs, and system stats.
"""

import sqlite3
import json
from datetime import datetime

DB_PATH = "soc_ids.db"


def get_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row  # allows dict-like access
    return conn


def init_db():
    """Create all tables if they don't exist."""
    conn = get_connection()
    c = conn.cursor()

    # Alerts table — stores every detected threat event
    c.execute("""
        CREATE TABLE IF NOT EXISTS alerts (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            alert_id    TEXT UNIQUE,
            timestamp   TEXT,
            threat_type TEXT,
            severity    TEXT,
            src_ip      TEXT,
            dst_ip      TEXT,
            src_port    INTEGER,
            dst_port    INTEGER,
            protocol    TEXT,
            description TEXT,
            mitre_id    TEXT,
            rule_id     TEXT,
            confidence  REAL,
            raw_data    TEXT,
            is_real     INTEGER DEFAULT 1
        )
    """)

    # Log entries table — stores uploaded or parsed log lines
    c.execute("""
        CREATE TABLE IF NOT EXISTS log_entries (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp   TEXT,
            source_file TEXT,
            level       TEXT,
            message     TEXT,
            flagged     INTEGER DEFAULT 0,
            flag_reason TEXT
        )
    """)

    # System stats table — stores periodic snapshots
    c.execute("""
        CREATE TABLE IF NOT EXISTS system_stats (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp       TEXT,
            packets_captured INTEGER,
            alerts_total    INTEGER,
            alerts_critical INTEGER,
            false_positives INTEGER,
            uptime_seconds  INTEGER
        )
    """)

    conn.commit()
    conn.close()
    print("[DB] Database initialized: soc_ids.db")


# ── Alert operations ──────────────────────────────────────────────────────────

def insert_alert(alert: dict):
    """Save an alert dict to the database."""
    conn = get_connection()
    c = conn.cursor()
    try:
        c.execute("""
            INSERT OR IGNORE INTO alerts
            (alert_id, timestamp, threat_type, severity, src_ip, dst_ip,
             src_port, dst_port, protocol, description, mitre_id, rule_id,
             confidence, raw_data, is_real)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
        """, (
            alert.get("id"),
            alert.get("timestamp"),
            alert.get("threat_type"),
            alert.get("severity"),
            alert.get("src_ip"),
            alert.get("dst_ip"),
            alert.get("src_port", 0),
            alert.get("dst_port", 0),
            alert.get("protocol", ""),
            alert.get("description"),
            alert.get("mitre_id"),
            alert.get("rule_id"),
            alert.get("confidence", 0.0),
            json.dumps(alert),
            1 if alert.get("is_real", True) else 0
        ))
        conn.commit()
    except Exception as e:
        print(f"[DB] Alert insert error: {e}")
    finally:
        conn.close()


def get_alerts(limit=100, severity=None, threat_type=None):
    """Fetch recent alerts with optional filters."""
    conn = get_connection()
    c = conn.cursor()
    query = "SELECT * FROM alerts WHERE 1=1"
    params = []
    if severity:
        query += " AND severity = ?"
        params.append(severity)
    if threat_type:
        query += " AND threat_type = ?"
        params.append(threat_type)
    query += " ORDER BY id DESC LIMIT ?"
    params.append(limit)
    rows = c.execute(query, params).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_alert_stats():
    """Return summary counts for the dashboard."""
    conn = get_connection()
    c = conn.cursor()
    total       = c.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
    critical    = c.execute("SELECT COUNT(*) FROM alerts WHERE severity='CRITICAL'").fetchone()[0]
    high        = c.execute("SELECT COUNT(*) FROM alerts WHERE severity='HIGH'").fetchone()[0]
    by_type_rows = c.execute(
        "SELECT threat_type, COUNT(*) as cnt FROM alerts GROUP BY threat_type ORDER BY cnt DESC"
    ).fetchall()
    conn.close()
    return {
        "total": total,
        "critical": critical,
        "high": high,
        "by_type": {r["threat_type"]: r["cnt"] for r in by_type_rows}
    }


# ── Log operations ────────────────────────────────────────────────────────────

def insert_log_entries(entries: list):
    """Bulk insert parsed log lines."""
    conn = get_connection()
    c = conn.cursor()
    c.executemany("""
        INSERT INTO log_entries (timestamp, source_file, level, message, flagged, flag_reason)
        VALUES (?,?,?,?,?,?)
    """, [
        (e["timestamp"], e["source_file"], e["level"],
         e["message"], e["flagged"], e.get("flag_reason", ""))
        for e in entries
    ])
    conn.commit()
    conn.close()


def get_log_entries(limit=200, flagged_only=False):
    conn = get_connection()
    c = conn.cursor()
    if flagged_only:
        rows = c.execute(
            "SELECT * FROM log_entries WHERE flagged=1 ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall()
    else:
        rows = c.execute(
            "SELECT * FROM log_entries ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


# ── Stats operations ──────────────────────────────────────────────────────────

def insert_stats(stats: dict):
    conn = get_connection()
    c = conn.cursor()
    c.execute("""
        INSERT INTO system_stats
        (timestamp, packets_captured, alerts_total, alerts_critical, false_positives, uptime_seconds)
        VALUES (?,?,?,?,?,?)
    """, (
        datetime.now().isoformat(),
        stats.get("packets_captured", 0),
        stats.get("alerts_total", 0),
        stats.get("alerts_critical", 0),
        stats.get("false_positives", 0),
        stats.get("uptime_seconds", 0)
    ))
    conn.commit()
    conn.close()
