import aiosqlite
import json
from pathlib import Path

DB_PATH = Path(__file__).parent.parent / "data" / "analyses.db"


async def init_db():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    async with aiosqlite.connect(str(DB_PATH)) as c:
        await c.execute("""
            CREATE TABLE IF NOT EXISTS analyses (
                id            TEXT PRIMARY KEY,
                filename      TEXT NOT NULL,
                timestamp     REAL NOT NULL,
                total_packets INTEGER NOT NULL,
                report_json   TEXT NOT NULL
            )
        """)
        await c.commit()


async def save_report(report_dict: dict):
    async with aiosqlite.connect(str(DB_PATH)) as c:
        await c.execute(
            "INSERT OR REPLACE INTO analyses (id, filename, timestamp, total_packets, report_json) VALUES (?,?,?,?,?)",
            (
                report_dict["analysis_id"],
                report_dict["filename"],
                report_dict.get("start_time") or 0.0,
                report_dict["total_packets"],
                json.dumps(report_dict),
            ),
        )
        await c.commit()


async def list_reports():
    async with aiosqlite.connect(str(DB_PATH)) as c:
        async with c.execute(
            "SELECT id, filename, timestamp, total_packets FROM analyses ORDER BY timestamp DESC"
        ) as cursor:
            rows = await cursor.fetchall()
    return [
        {"id": r[0], "filename": r[1], "timestamp": r[2], "total_packets": r[3]}
        for r in rows
    ]


async def get_report(analysis_id: str):
    async with aiosqlite.connect(str(DB_PATH)) as c:
        async with c.execute(
            "SELECT report_json FROM analyses WHERE id=?", (analysis_id,)
        ) as cursor:
            row = await cursor.fetchone()
    if row is None:
        return None
    return json.loads(row[0])


async def delete_report(analysis_id: str) -> bool:
    async with aiosqlite.connect(str(DB_PATH)) as c:
        cursor = await c.execute("DELETE FROM analyses WHERE id=?", (analysis_id,))
        await c.commit()
    return cursor.rowcount > 0


async def delete_all_reports() -> int:
    async with aiosqlite.connect(str(DB_PATH)) as c:
        cursor = await c.execute("DELETE FROM analyses")
        await c.commit()
    return cursor.rowcount
