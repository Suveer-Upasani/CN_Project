"""Unit tests for SQLite history persistence and process recovery."""

import os
import tempfile
import unittest
from services.history_repository import HistoryRepository


class TestHistoryRepository(unittest.TestCase):
    """Test suite for HistoryRepository operations and data recovery."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self.temp_dir.name, "test_scans.db")
        self.repo = HistoryRepository(db_path=self.db_path)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_create_and_get_scan(self):
        """Test inserting and retrieving a scan."""
        scan = self.repo.create_scan(
            scan_id="scan_test_001",
            target="192.168.1.1",
            resolved_ip="192.168.1.1",
            status="queued",
            current_phase="Queued",
        )
        self.assertIsNotNone(scan)
        self.assertEqual(scan["scan_id"], "scan_test_001")
        self.assertEqual(scan["target"], "192.168.1.1")
        self.assertEqual(scan["status"], "queued")

        fetched = self.repo.get_scan("scan_test_001")
        self.assertEqual(fetched["target"], "192.168.1.1")

    def test_update_progress(self):
        """Test updating progress metadata."""
        self.repo.create_scan(
            scan_id="scan_test_002",
            target="localhost",
            status="queued",
        )
        self.repo.update_scan_progress(
            scan_id="scan_test_002",
            status="running",
            current_phase="Discovering host",
            resolved_ip="127.0.0.1",
            start_time="2026-10-27 12:00:00",
        )
        scan = self.repo.get_scan("scan_test_002")
        self.assertEqual(scan["status"], "running")
        self.assertEqual(scan["current_phase"], "Discovering host")
        self.assertEqual(scan["resolved_ip"], "127.0.0.1")

    def test_complete_scan(self):
        """Test completing a scan with findings and json result."""
        self.repo.create_scan(scan_id="scan_test_003", target="10.0.0.1")
        self.repo.complete_scan(
            scan_id="scan_test_003",
            host_status="up",
            duration=4.5,
            end_time="2026-10-27 12:05:00",
            open_ports_count=2,
            services_count=2,
            nmap_version="7.991",
            result_json='{"target": "10.0.0.1", "ports": [{"port": 80}]}',
            resolved_ip="10.0.0.1",
        )
        scan = self.repo.get_scan("scan_test_003")
        self.assertEqual(scan["status"], "completed")
        self.assertEqual(scan["open_ports_count"], 2)
        self.assertIsNotNone(scan["result_data"])
        self.assertEqual(scan["result_data"]["ports"][0]["port"], 80)

    def test_restart_recovery_of_interrupted_scans(self):
        """Verify that queued or running scans are automatically marked interrupted on restart."""
        # Create scans in queued and running states
        self.repo.create_scan(scan_id="scan_interrupted_1", target="192.168.1.10", status="running")
        self.repo.create_scan(scan_id="scan_interrupted_2", target="192.168.1.20", status="queued")

        # Simulate server restart by creating new repository instance on same DB file
        new_repo = HistoryRepository(db_path=self.db_path)

        scan1 = new_repo.get_scan("scan_interrupted_1")
        scan2 = new_repo.get_scan("scan_interrupted_2")

        self.assertEqual(scan1["status"], "failed")
        self.assertIn("interrupted", scan1["error_message"].lower())
        self.assertEqual(scan2["status"], "failed")

    def test_metrics_calculation(self):
        """Test calculation of metrics."""
        self.repo.create_scan(scan_id="s1", target="192.168.1.1")
        self.repo.complete_scan("s1", "up", 2.0, "2026-10-27", 3, 3, "7.991", "{}")

        self.repo.create_scan(scan_id="s2", target="192.168.1.2")
        self.repo.complete_scan("s2", "down", 1.0, "2026-10-27", 0, 0, "7.991", "{}")

        metrics = self.repo.get_metrics()
        self.assertEqual(metrics["total_scans"], 2)
        self.assertEqual(metrics["unique_targets"], 2)
        self.assertEqual(metrics["hosts_up"], 1)
        self.assertEqual(metrics["latest_open_ports"], 0)


if __name__ == "__main__":
    unittest.main()
