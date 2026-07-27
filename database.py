"""
database.py
------------------------------------------------------------
SQLite persistence layer for the AI-Powered Digital Forensics
Assistant.

Responsibilities:
    * Create/initialize the SQLite schema on first run.
    * Store investigation (case) records.
    * Store per-investigation evidence file metadata.
    * Store detected forensic events/incidents.
    * Provide query helpers used by the dashboard and report
      generation modules.

All functions use parameterized queries to avoid SQL injection,
and every public function is wrapped in try/except with
meaningful errors so the Flask layer can handle failures
gracefully.
------------------------------------------------------------
"""

import sqlite3
import os
import json
from contextlib import contextmanager
from datetime import datetime

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "forensics.db")


@contextmanager
def get_connection():
    """
    Context manager that yields a SQLite connection with
    row factory set to sqlite3.Row (dict-like access), and
    guarantees the connection is closed even on error.
    """
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON;")
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def init_db():
    """
    Creates all required tables if they do not already exist.
    Safe to call every time the app starts.
    """
    with get_connection() as conn:
        cur = conn.cursor()

        cur.execute("""
            CREATE TABLE IF NOT EXISTS investigations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                case_name TEXT NOT NULL,
                investigator TEXT,
                created_at TEXT NOT NULL,
                status TEXT DEFAULT 'Open',
                risk_score INTEGER DEFAULT 0,
                risk_level TEXT DEFAULT 'Safe',
                ai_summary TEXT,
                total_events INTEGER DEFAULT 0,
                total_incidents INTEGER DEFAULT 0
            )
        """)

        cur.execute("""
            CREATE TABLE IF NOT EXISTS evidence (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                investigation_id INTEGER NOT NULL,
                filename TEXT NOT NULL,
                file_type TEXT,
                file_size INTEGER,
                uploaded_at TEXT NOT NULL,
                row_count INTEGER DEFAULT 0,
                FOREIGN KEY (investigation_id) REFERENCES investigations (id)
                    ON DELETE CASCADE
            )
        """)

        cur.execute("""
            CREATE TABLE IF NOT EXISTS incidents (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                investigation_id INTEGER NOT NULL,
                evidence_id INTEGER,
                timestamp TEXT,
                category TEXT NOT NULL,
                severity TEXT NOT NULL,
                source_ip TEXT,
                destination_ip TEXT,
                username TEXT,
                description TEXT,
                raw_line TEXT,
                FOREIGN KEY (investigation_id) REFERENCES investigations (id)
                    ON DELETE CASCADE,
                FOREIGN KEY (evidence_id) REFERENCES evidence (id)
                    ON DELETE CASCADE
            )
        """)

        cur.execute("""
            CREATE INDEX IF NOT EXISTS idx_incidents_investigation
            ON incidents (investigation_id)
        """)
        cur.execute("""
            CREATE INDEX IF NOT EXISTS idx_incidents_severity
            ON incidents (severity)
        """)


# ----------------------------------------------------------------
# Investigation CRUD
# ----------------------------------------------------------------

def create_investigation(case_name, investigator="Unknown"):
    """Creates a new investigation record and returns its ID."""
    with get_connection() as conn:
        cur = conn.cursor()
        cur.execute(
            """INSERT INTO investigations (case_name, investigator, created_at, status)
               VALUES (?, ?, ?, ?)""",
            (case_name, investigator, datetime.utcnow().isoformat(), "Open"),
        )
        return cur.lastrowid


def update_investigation_results(investigation_id, risk_score, risk_level,
                                  ai_summary, total_events, total_incidents):
    """Updates an investigation with computed analysis results."""
    with get_connection() as conn:
        cur = conn.cursor()
        cur.execute(
            """UPDATE investigations
               SET risk_score = ?, risk_level = ?, ai_summary = ?,
                   total_events = ?, total_incidents = ?, status = ?
               WHERE id = ?""",
            (risk_score, risk_level, ai_summary, total_events,
             total_incidents, "Analyzed", investigation_id),
        )


def get_investigation(investigation_id):
    with get_connection() as conn:
        cur = conn.cursor()
        cur.execute("SELECT * FROM investigations WHERE id = ?", (investigation_id,))
        row = cur.fetchone()
        return dict(row) if row else None


def get_all_investigations(limit=50):
    with get_connection() as conn:
        cur = conn.cursor()
        cur.execute(
            "SELECT * FROM investigations ORDER BY created_at DESC LIMIT ?",
            (limit,),
        )
        return [dict(r) for r in cur.fetchall()]


def delete_investigation(investigation_id):
    with get_connection() as conn:
        cur = conn.cursor()
        cur.execute("DELETE FROM incidents WHERE investigation_id = ?", (investigation_id,))
        cur.execute("DELETE FROM evidence WHERE investigation_id = ?", (investigation_id,))
        cur.execute("DELETE FROM investigations WHERE id = ?", (investigation_id,))


# ----------------------------------------------------------------
# Evidence CRUD
# ----------------------------------------------------------------

def add_evidence(investigation_id, filename, file_type, file_size, row_count=0):
    with get_connection() as conn:
        cur = conn.cursor()
        cur.execute(
            """INSERT INTO evidence
               (investigation_id, filename, file_type, file_size, uploaded_at, row_count)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (investigation_id, filename, file_type, file_size,
             datetime.utcnow().isoformat(), row_count),
        )
        return cur.lastrowid


def get_evidence_for_investigation(investigation_id):
    with get_connection() as conn:
        cur = conn.cursor()
        cur.execute(
            "SELECT * FROM evidence WHERE investigation_id = ? ORDER BY uploaded_at DESC",
            (investigation_id,),
        )
        return [dict(r) for r in cur.fetchall()]


def get_recent_evidence(limit=10):
    with get_connection() as conn:
        cur = conn.cursor()
        cur.execute("SELECT * FROM evidence ORDER BY uploaded_at DESC LIMIT ?", (limit,))
        return [dict(r) for r in cur.fetchall()]


# ----------------------------------------------------------------
# Incident CRUD
# ----------------------------------------------------------------

def add_incidents_bulk(investigation_id, evidence_id, incidents):
    """
    Bulk-inserts a list of incident dicts. Each dict may contain:
    timestamp, category, severity, source_ip, destination_ip,
    username, description, raw_line
    """
    with get_connection() as conn:
        cur = conn.cursor()
        cur.executemany(
            """INSERT INTO incidents
               (investigation_id, evidence_id, timestamp, category, severity,
                source_ip, destination_ip, username, description, raw_line)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            [
                (
                    investigation_id, evidence_id,
                    i.get("timestamp"), i.get("category"), i.get("severity"),
                    i.get("source_ip"), i.get("destination_ip"), i.get("username"),
                    i.get("description"), i.get("raw_line"),
                )
                for i in incidents
            ],
        )


def get_incidents_for_investigation(investigation_id, limit=None):
    with get_connection() as conn:
        cur = conn.cursor()
        query = "SELECT * FROM incidents WHERE investigation_id = ? ORDER BY timestamp"
        params = [investigation_id]
        if limit:
            query += " LIMIT ?"
            params.append(limit)
        cur.execute(query, params)
        return [dict(r) for r in cur.fetchall()]


def get_dashboard_stats():
    """
    Aggregates statistics used across the dashboard cards and charts.
    """
    with get_connection() as conn:
        cur = conn.cursor()

        cur.execute("SELECT COUNT(*) AS c FROM investigations")
        total_cases = cur.fetchone()["c"]

        cur.execute("SELECT COUNT(*) AS c FROM evidence")
        total_evidence = cur.fetchone()["c"]

        severity_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
        cur.execute("SELECT severity, COUNT(*) AS c FROM incidents GROUP BY severity")
        for row in cur.fetchall():
            sev = row["severity"]
            if sev in severity_counts:
                severity_counts[sev] = row["c"]

        cur.execute("""
            SELECT category, COUNT(*) as c FROM incidents
            GROUP BY category ORDER BY c DESC LIMIT 10
        """)
        event_distribution = [dict(r) for r in cur.fetchall()]

        cur.execute("""
            SELECT source_ip, COUNT(*) as c FROM incidents
            WHERE source_ip IS NOT NULL AND source_ip != ''
            GROUP BY source_ip ORDER BY c DESC LIMIT 5
        """)
        top_source_ips = [dict(r) for r in cur.fetchall()]

        cur.execute("""
            SELECT destination_ip, COUNT(*) as c FROM incidents
            WHERE destination_ip IS NOT NULL AND destination_ip != ''
            GROUP BY destination_ip ORDER BY c DESC LIMIT 5
        """)
        top_destination_ips = [dict(r) for r in cur.fetchall()]

        cur.execute("""
            SELECT username, COUNT(*) as c FROM incidents
            WHERE username IS NOT NULL AND username != ''
            GROUP BY username ORDER BY c DESC LIMIT 5
        """)
        top_users = [dict(r) for r in cur.fetchall()]

        cur.execute("""
            SELECT timestamp, category, severity, description
            FROM incidents ORDER BY id DESC LIMIT 15
        """)
        recent_activities = [dict(r) for r in cur.fetchall()]

        cur.execute("""
            SELECT id, case_name, risk_level, risk_score, created_at, status
            FROM investigations ORDER BY created_at DESC LIMIT 5
        """)
        latest_investigations = [dict(r) for r in cur.fetchall()]

        recent_evidence = get_recent_evidence(limit=8)

        return {
            "total_cases": total_cases,
            "total_evidence": total_evidence,
            "critical_alerts": severity_counts["Critical"],
            "high_risk": severity_counts["High"],
            "medium_risk": severity_counts["Medium"],
            "low_risk": severity_counts["Low"],
            "event_distribution": event_distribution,
            "top_source_ips": top_source_ips,
            "top_destination_ips": top_destination_ips,
            "top_users": top_users,
            "recent_activities": recent_activities,
            "latest_investigations": latest_investigations,
            "recent_evidence": recent_evidence,
        }
