import sqlite3
import json
from pathlib import Path

DB_PATH = Path(__file__).parent.parent / "data" / "analyses.db"


def _conn():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    return sqlite3.connect(str(DB_PATH))


def init_db():
    with _conn() as c:
        c.execute("""
            CREATE TABLE IF NOT EXISTS analyses (
                id            TEXT PRIMARY KEY,
                filename      TEXT NOT NULL,
                timestamp     REAL NOT NULL,
                total_packets INTEGER NOT NULL,
                report_json   TEXT NOT NULL
            )
        """)
        c.commit()


def save_report(report_dict: dict):
    with _conn() as c:
        c.execute(
            "INSERT OR REPLACE INTO analyses (id, filename, timestamp, total_packets, report_json) VALUES (?,?,?,?,?)",
            (
                report_dict["analysis_id"],
                report_dict["filename"],
                report_dict.get("start_time") or 0.0,
                report_dict["total_packets"],
                json.dumps(report_dict),
            ),
        )
        c.commit()


def list_reports():
    with _conn() as c:
        rows = c.execute(
            "SELECT id, filename, timestamp, total_packets FROM analyses ORDER BY timestamp DESC"
        ).fetchall()
    return [
        {"id": r[0], "filename": r[1], "timestamp": r[2], "total_packets": r[3]}
        for r in rows
    ]


def get_report(analysis_id: str):
    with _conn() as c:
        row = c.execute(
            "SELECT report_json FROM analyses WHERE id=?", (analysis_id,)
        ).fetchone()
    if row is None:
        return None
    return json.loads(row[0])


def delete_report(analysis_id: str) -> bool:
    with _conn() as c:
        cur = c.execute("DELETE FROM analyses WHERE id=?", (analysis_id,))
        c.commit()
    return cur.rowcount > 0
