"""SQLite persistence layer for PortSentinel scan history and metrics."""

import json
import sqlite3
import threading
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from utils.logger import get_logger


class HistoryRepository:
    """Manages persistent SQLite storage of scan jobs, findings, and metrics."""

    def __init__(self, db_path: str = "data/portsentinel.db"):
        self.logger = get_logger()
        self.db_path_str = str(db_path)
        self.is_memory = (self.db_path_str == ":memory:")
        self._lock = threading.Lock()

        if not self.is_memory:
            self.db_path = Path(db_path)
            self.db_path.parent.mkdir(parents=True, exist_ok=True)
            self._shared_conn = None
        else:
            self.db_path = Path(":memory:")
            self._shared_conn = sqlite3.connect(":memory:", check_same_thread=False)
            self._shared_conn.row_factory = sqlite3.Row

        self._init_db()

    @contextmanager
    def _get_connection(self):
        """Get a thread-safe connection to SQLite with dictionary-like rows."""
        if self.is_memory:
            with self._lock:
                yield self._shared_conn
        else:
            conn = sqlite3.connect(str(self.db_path), timeout=10.0)
            conn.row_factory = sqlite3.Row
            try:
                yield conn
            finally:
                conn.close()

    def close(self) -> None:
        """Close shared connection if using in-memory mode."""
        if self.is_memory and self._shared_conn:
            with self._lock:
                try:
                    self._shared_conn.close()
                except Exception:
                    pass

    def _init_db(self) -> None:
        """Initialize the database schema if it doesn't already exist."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS scans (
                    scan_id TEXT PRIMARY KEY,
                    target TEXT NOT NULL,
                    resolved_ip TEXT,
                    target_type TEXT DEFAULT 'single',
                    scan_type TEXT DEFAULT 'tcp',
                    status TEXT NOT NULL,
                    current_phase TEXT,
                    created_at TEXT NOT NULL,
                    start_time TEXT,
                    end_time TEXT,
                    duration REAL DEFAULT 0.0,
                    host_status TEXT DEFAULT 'unknown',
                    open_ports_count INTEGER DEFAULT 0,
                    services_count INTEGER DEFAULT 0,
                    nmap_version TEXT,
                    error_message TEXT,
                    txt_report_path TEXT,
                    json_report_path TEXT,
                    result_json TEXT
                );
                """
            )
            cursor.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_scans_created_at 
                ON scans(created_at DESC);
                """
            )
            cursor.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_scans_status 
                ON scans(status);
                """
            )
            conn.commit()

        # Handle application restart recovery
        self.recover_interrupted_scans()

    def recover_interrupted_scans(self) -> int:
        """Mark any scans left in queued/running states from a previous process as interrupted.

        Returns:
            Number of recovered/marked scans.
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                UPDATE scans
                SET status = 'failed',
                    current_phase = 'Interrupted (Server restart)',
                    error_message = 'Scan was interrupted by server restart or shutdown.'
                WHERE status IN ('queued', 'running');
                """
            )
            affected = cursor.rowcount
            conn.commit()
            if affected > 0:
                self.logger.warning(
                    f"Recovered {affected} interrupted scan(s) from previous server execution."
                )
            return affected

    def create_scan(
        self,
        scan_id: str,
        target: str,
        resolved_ip: Optional[str] = None,
        target_type: str = "single",
        scan_type: str = "tcp",
        status: str = "queued",
        current_phase: str = "Queued",
    ) -> Dict[str, Any]:
        """Record a newly queued scan."""
        now_iso = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO scans (
                    scan_id, target, resolved_ip, target_type, scan_type,
                    status, current_phase, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?);
                """,
                (
                    scan_id,
                    target,
                    resolved_ip or target,
                    target_type,
                    scan_type,
                    status,
                    current_phase,
                    now_iso,
                ),
            )
            conn.commit()

        return self.get_scan(scan_id) or {}

    def update_scan_progress(
        self,
        scan_id: str,
        status: Optional[str] = None,
        current_phase: Optional[str] = None,
        resolved_ip: Optional[str] = None,
        start_time: Optional[str] = None,
        error_message: Optional[str] = None,
    ) -> None:
        """Update progress metadata for an in-flight scan."""
        updates = []
        params = []

        if status is not None:
            updates.append("status = ?")
            params.append(status)
        if current_phase is not None:
            updates.append("current_phase = ?")
            params.append(current_phase)
        if resolved_ip is not None:
            updates.append("resolved_ip = ?")
            params.append(resolved_ip)
        if start_time is not None:
            updates.append("start_time = ?")
            params.append(start_time)
        if error_message is not None:
            updates.append("error_message = ?")
            params.append(error_message)

        if not updates:
            return

        params.append(scan_id)
        sql = f"UPDATE scans SET {', '.join(updates)} WHERE scan_id = ?;"

        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(sql, params)
            conn.commit()

    def complete_scan(
        self,
        scan_id: str,
        host_status: str,
        duration: float,
        end_time: str,
        open_ports_count: int,
        services_count: int,
        nmap_version: str,
        result_json: str,
        txt_report_path: Optional[str] = None,
        json_report_path: Optional[str] = None,
        error_message: Optional[str] = None,
        resolved_ip: Optional[str] = None,
    ) -> None:
        """Record completed scan results."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                UPDATE scans
                SET status = 'completed',
                    current_phase = 'Completed',
                    host_status = ?,
                    duration = ?,
                    end_time = ?,
                    open_ports_count = ?,
                    services_count = ?,
                    nmap_version = ?,
                    result_json = ?,
                    txt_report_path = ?,
                    json_report_path = ?,
                    error_message = ?,
                    resolved_ip = COALESCE(?, resolved_ip)
                WHERE scan_id = ?;
                """,
                (
                    host_status,
                    duration,
                    end_time,
                    open_ports_count,
                    services_count,
                    nmap_version,
                    result_json,
                    txt_report_path,
                    json_report_path,
                    error_message,
                    resolved_ip,
                    scan_id,
                ),
            )
            conn.commit()

    def fail_scan(self, scan_id: str, error_message: str, duration: float = 0.0) -> None:
        """Mark a scan as failed."""
        now_iso = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                UPDATE scans
                SET status = 'failed',
                    current_phase = 'Failed',
                    end_time = ?,
                    duration = ?,
                    error_message = ?
                WHERE scan_id = ?;
                """,
                (now_iso, duration, error_message, scan_id),
            )
            conn.commit()

    def get_scan(self, scan_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve a scan record by scan_id."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM scans WHERE scan_id = ?;", (scan_id,))
            row = cursor.fetchone()
            if not row:
                return None
            return self._row_to_dict(row)

    def list_scans(self, limit: int = 50, offset: int = 0) -> List[Dict[str, Any]]:
        """List recent scans ordered by creation date descending."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT * FROM scans
                ORDER BY created_at DESC, rowid DESC
                LIMIT ? OFFSET ?;
                """,
                (limit, offset),
            )
            rows = cursor.fetchall()
            return [self._row_to_dict(r) for r in rows]

    def get_metrics(self) -> Dict[str, Any]:
        """Compute aggregated dashboard metrics from the database."""
        with self._get_connection() as conn:
            cursor = conn.cursor()

            # 1. Total Scans
            cursor.execute("SELECT COUNT(*) FROM scans;")
            total_scans = cursor.fetchone()[0] or 0

            # 2. Unique Targets
            cursor.execute("SELECT COUNT(DISTINCT target) FROM scans;")
            unique_targets = cursor.fetchone()[0] or 0

            # 3. Hosts UP
            cursor.execute("SELECT COUNT(*) FROM scans WHERE LOWER(host_status) = 'up';")
            hosts_up = cursor.fetchone()[0] or 0

            # 4. Open ports in most recent completed scan
            cursor.execute(
                """
                SELECT open_ports_count FROM scans
                WHERE status = 'completed'
                ORDER BY created_at DESC, rowid DESC
                LIMIT 1;
                """
            )
            latest_row = cursor.fetchone()
            latest_open_ports = latest_row[0] if latest_row else 0

            return {
                "total_scans": total_scans,
                "unique_targets": unique_targets,
                "hosts_up": hosts_up,
                "latest_open_ports": latest_open_ports,
            }

    def list_reports(self, limit: int = 10) -> List[Dict[str, Any]]:
        """List generated reports that currently exist on the filesystem."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT scan_id, target, resolved_ip, created_at, 
                       txt_report_path, json_report_path
                FROM scans
                WHERE status = 'completed' AND (txt_report_path IS NOT NULL OR json_report_path IS NOT NULL)
                ORDER BY created_at DESC, rowid DESC
                LIMIT ?;
                """,
                (limit,),
            )
            rows = cursor.fetchall()
            valid_reports = []
            for r in rows:
                item = self._row_to_dict(r)
                txt_exists = item.get("txt_report_path") and Path(item["txt_report_path"]).is_file()
                json_exists = item.get("json_report_path") and Path(item["json_report_path"]).is_file()
                if txt_exists or json_exists:
                    item["has_txt"] = bool(txt_exists)
                    item["has_json"] = bool(json_exists)
                    valid_reports.append(item)
            return valid_reports

    def _row_to_dict(self, row: sqlite3.Row) -> Dict[str, Any]:
        """Convert a sqlite3.Row into a clean dictionary with parsed result_json if present."""
        d = dict(row)
        if d.get("result_json"):
            try:
                d["result_data"] = json.loads(d["result_json"])
            except Exception:
                d["result_data"] = None
        else:
            d["result_data"] = None
        return d
