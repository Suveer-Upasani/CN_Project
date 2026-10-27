"""Automated tests for PortSentinel REST API endpoints."""

import json
import os
import tempfile
import unittest
from unittest.mock import patch

from app import create_app


class TestScanAPI(unittest.TestCase):
    """Test suite for API endpoints."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self.temp_dir.name, "test_api.db")
        self.output_dir = os.path.join(self.temp_dir.name, "output")
        os.makedirs(self.output_dir, exist_ok=True)

        self.app = create_app({
            "TESTING": True,
            "WTF_CSRF_ENABLED": False,
            "DB_PATH": self.db_path,
            "OUTPUT_DIR": self.output_dir,
            "MAX_CONCURRENT_SCANS": 2,
        })
        self.client = self.app.test_client()

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_health_check(self):
        """Verify /api/health returns 200 with engine status."""
        res = self.client.get("/api/health")
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertEqual(data["status"], "ok")
        self.assertIn("nmap_available", data)
        self.assertIn("active_scans", data)

    def test_submit_scan_missing_target(self):
        """Verify 400 when target is missing."""
        res = self.client.post("/api/scans", json={"target": "", "authorized": True})
        self.assertEqual(res.status_code, 400)
        data = res.get_json()
        self.assertIn("error", data)

    def test_submit_scan_unauthorized(self):
        """Verify 400 when authorization is False."""
        res = self.client.post(
            "/api/scans", json={"target": "192.168.1.1", "authorized": False}
        )
        self.assertEqual(res.status_code, 400)
        data = res.get_json()
        self.assertIn("authorization", data["error"].lower())

    def test_submit_scan_invalid_ip_format(self):
        """Verify 400 when IP octets exceed 255."""
        res = self.client.post(
            "/api/scans", json={"target": "192.168.1.999", "authorized": True}
        )
        self.assertEqual(res.status_code, 400)
        data = res.get_json()
        self.assertIn("error", data)

    def test_submit_scan_invalid_characters(self):
        """Verify 400 when shell injection characters are provided."""
        res = self.client.post(
            "/api/scans", json={"target": "127.0.0.1; whoami", "authorized": True}
        )
        self.assertEqual(res.status_code, 400)

    def test_submit_scan_invalid_port_range(self):
        """Verify 400 when port range is invalid."""
        res = self.client.post(
            "/api/scans",
            json={"target": "127.0.0.1", "authorized": True, "ports": "99999"},
        )
        self.assertEqual(res.status_code, 400)
        self.assertIn("out of bounds", res.get_json()["error"])

    @patch("services.scan_service.ScanService._execute_scan_worker")
    def test_submit_scan_valid_ip_success(self, mock_worker):
        """Verify 201 Created for valid LAN IP with authorization."""
        res = self.client.post(
            "/api/scans",
            json={"target": "192.168.1.10", "authorized": True, "ports": "22,80,443"},
        )
        self.assertEqual(res.status_code, 201)
        data = res.get_json()
        self.assertTrue(data["success"])
        self.assertEqual(data["target"], "192.168.1.10")
        self.assertEqual(data["resolved_ip"], "192.168.1.10")
        self.assertEqual(data["status"], "queued")
        self.assertIn("scan_id", data)

    def test_get_scan_not_found(self):
        """Verify 404 for unknown scan_id."""
        res = self.client.get("/api/scans/unknown_scan_id_999")
        self.assertEqual(res.status_code, 404)

    def test_get_scan_status(self):
        """Verify scan status endpoint."""
        service = self.app.config["SCAN_SERVICE"]
        service.repo.create_scan(
            scan_id="scan_stat_01",
            target="10.0.0.1",
            status="running",
            current_phase="Discovering TCP ports",
        )
        res = self.client.get("/api/scans/scan_stat_01/status")
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertEqual(data["scan_id"], "scan_stat_01")
        self.assertEqual(data["current_phase"], "Discovering TCP ports")

    def test_get_metrics(self):
        """Verify /api/metrics endpoint returns metrics dictionary."""
        res = self.client.get("/api/metrics")
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertIn("total_scans", data)
        self.assertIn("unique_targets", data)
        self.assertIn("hosts_up", data)

    def test_get_scan_results_in_progress(self):
        """Verify /api/scans/<id>/results returns 202 while scan is running."""
        service = self.app.config["SCAN_SERVICE"]
        service.repo.create_scan(
            scan_id="scan_running_res",
            target="10.0.0.5",
            status="running",
            current_phase="Scanning TCP ports",
        )
        res = self.client.get("/api/scans/scan_running_res/results")
        self.assertEqual(res.status_code, 202)
        data = res.get_json()
        self.assertEqual(data["status"], "running")

    def test_get_scan_results_completed(self):
        """Verify /api/scans/<id>/results returns 200 with data when completed."""
        service = self.app.config["SCAN_SERVICE"]
        service.repo.create_scan(
            scan_id="scan_comp_res",
            target="192.168.1.1",
            status="completed",
        )
        service.repo.complete_scan(
            scan_id="scan_comp_res",
            host_status="up",
            duration=1.5,
            end_time="2026-10-27 12:00:00",
            open_ports_count=1,
            services_count=1,
            nmap_version="7.991",
            result_json='{"target": "192.168.1.1", "ports": [{"port": 80}]}',
            resolved_ip="192.168.1.1",
        )
        res = self.client.get("/api/scans/scan_comp_res/results")
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertEqual(data["scan_id"], "scan_comp_res")
        self.assertEqual(data["status"], "completed")
        self.assertEqual(data["open_ports_count"], 1)

    def test_list_scans_api(self):
        """Verify /api/scans returns recent scans list."""
        service = self.app.config["SCAN_SERVICE"]
        service.repo.create_scan(scan_id="scan_list_1", target="192.168.1.1")
        res = self.client.get("/api/scans")
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertIn("scans", data)
        self.assertTrue(any(s["scan_id"] == "scan_list_1" for s in data["scans"]))


if __name__ == "__main__":
    unittest.main()
