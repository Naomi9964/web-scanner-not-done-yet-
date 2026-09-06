"""Thread-safe SQLite storage for scan reports."""
import json
import sqlite3
import threading
import uuid


class ScanStore:
    def __init__(self, path):
        self.lock = threading.Lock()
        self.connection = sqlite3.connect(path, check_same_thread=False)
        self.connection.execute("""
            CREATE TABLE IF NOT EXISTS scans (
                id TEXT PRIMARY KEY, checked_at TEXT NOT NULL, host TEXT NOT NULL,
                url TEXT NOT NULL, score INTEGER NOT NULL, risk TEXT NOT NULL,
                report_json TEXT NOT NULL
            )
        """)
        self.connection.commit()

    def save(self, report):
        scan_id = uuid.uuid4().hex[:12]
        host = __import__("urllib.parse", fromlist=["urlsplit"]).urlsplit(report["final_url"]).hostname or ""
        with self.lock:
            self.connection.execute(
                "INSERT INTO scans VALUES (?, ?, ?, ?, ?, ?, ?)",
                (scan_id, report["checked_at"], host, report["final_url"],
                 report["score"], report["risk"], json.dumps(report, ensure_ascii=False)))
            self.connection.commit()
        return scan_id

    def list(self, limit=100):
        with self.lock:
            rows = self.connection.execute(
                "SELECT id, checked_at, host, url, score, risk FROM scans ORDER BY checked_at DESC LIMIT ?",
                (min(max(int(limit), 1), 200),)).fetchall()
        keys = ("id", "checked_at", "host", "url", "score", "risk")
        return [dict(zip(keys, row)) for row in rows]

    def get(self, scan_id):
        if not isinstance(scan_id, str) or not __import__("re").fullmatch(r"[0-9a-f]{12}", scan_id):
            return None
        with self.lock:
            row = self.connection.execute("SELECT report_json FROM scans WHERE id = ?", (scan_id,)).fetchone()
        if not row:
            return None
        report = json.loads(row[0])
        report["scan_id"] = scan_id
        return report

    def close(self):
        with self.lock:
            self.connection.close()
