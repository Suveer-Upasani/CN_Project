"""Automated tests for web page routes and safe report downloads."""

import os
import tempfile
import unittest
from pathlib import Path

from app import create_app


class TestWebRoutes(unittest.TestCase):
    """Test suite for web routes and safe report downloading."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self.temp_dir.name, "test_routes.db")
        self.output_dir = os.path.join(self.temp_dir.name, "output")
        os.makedirs(self.output_dir, exist_ok=True)

        self.app = create_app({
            "TESTING": True,
            "WTF_CSRF_ENABLED": False,
            "DB_PATH": self.db_path,
            "OUTPUT_DIR": self.output_dir,
        })
        self.client = self.app.test_client()
        self.service = self.app.config["SCAN_SERVICE"]

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_dashboard_renders(self):
        """Verify dashboard page renders HTML with metric cards."""
        res = self.client.get("/dashboard")
        self.assertEqual(res.status_code, 200)
        self.assertIn(b"Network Reconnaissance Dashboard", res.data)
        self.assertIn(b"Initiate Individual Host Reconnaissance", res.data)

    def test_history_page_renders(self):
        """Verify history page renders."""
        res = self.client.get("/history")
        self.assertEqual(res.status_code, 200)
        self.assertIn(b"Reconnaissance Scan History", res.data)

    def test_scan_details_renders_for_existing_scan(self):
        """Verify scan details page renders for existing scan."""
        self.service.repo.create_scan(
            scan_id="scan_view_01",
            target="192.168.1.1",
            resolved_ip="192.168.1.1",
            status="completed",
        )
        res = self.client.get("/scans/scan_view_01")
        self.assertEqual(res.status_code, 200)
        self.assertIn(b"192.168.1.1", res.data)

    def test_scan_details_404_for_unknown_scan(self):
        """Verify 404 rendered when scan ID does not exist."""
        res = self.client.get("/scans/non_existent_scan_id")
        self.assertEqual(res.status_code, 404)
        self.assertIn(b"Page Not Found", res.data)

    def test_safe_report_download_txt_and_json(self):
        """Verify authorized report downloading for both text and JSON formats."""
        # Create dummy report files in output directory
        scan_id = "scan_download_01"
        txt_file = Path(self.output_dir) / f"{scan_id}.txt"
        json_file = Path(self.output_dir) / f"{scan_id}.json"

        txt_file.write_text("PortSentinel Text Report Content", encoding="utf-8")
        json_file.write_text('{"status": "completed"}', encoding="utf-8")

        self.service.repo.create_scan(
            scan_id=scan_id,
            target="192.168.1.1",
            status="completed",
        )
        self.service.repo.complete_scan(
            scan_id=scan_id,
            host_status="up",
            duration=3.2,
            end_time="2026-10-27",
            open_ports_count=1,
            services_count=1,
            nmap_version="7.991",
            result_json='{"ports": []}',
            txt_report_path=str(txt_file.resolve()),
            json_report_path=str(json_file.resolve()),
        )

        # 1. Download Text Report
        res_txt = self.client.get(f"/reports/{scan_id}/download?format=txt")
        self.assertEqual(res_txt.status_code, 200)
        self.assertIn(b"PortSentinel Text Report Content", res_txt.data)
        self.assertIn("text/plain", res_txt.headers.get("Content-Type", ""))

        # 2. Download JSON Report
        res_json = self.client.get(f"/reports/{scan_id}/download?format=json")
        self.assertEqual(res_json.status_code, 200)
        self.assertIn(b'"status": "completed"', res_json.data)
        self.assertIn("application/json", res_json.headers.get("Content-Type", ""))

    def test_download_report_invalid_format(self):
        """Verify 400 when invalid format is requested."""
        res = self.client.get("/reports/some_scan/download?format=exe")
        self.assertEqual(res.status_code, 400)

    def test_download_report_non_existent(self):
        """Verify 404 when report file is missing."""
        res = self.client.get("/reports/missing_scan/download?format=txt")
        self.assertEqual(res.status_code, 404)

    def test_download_report_path_traversal_blocked(self):
        """Verify path traversal attempt outside output directory is blocked."""
        # Create a file outside output_dir
        evil_file = Path(self.temp_dir.name) / "secret.txt"
        evil_file.write_text("sensitive data", encoding="utf-8")

        scan_id = "scan_traversal_01"
        self.service.repo.create_scan(scan_id=scan_id, target="127.0.0.1")
        # Manually inject evil path into DB
        with self.service.repo._get_connection() as conn:
            conn.execute(
                "UPDATE scans SET txt_report_path = ? WHERE scan_id = ?",
                (str(evil_file), scan_id),
            )
            conn.commit()

        res = self.client.get(f"/reports/{scan_id}/download?format=txt")
        self.assertEqual(res.status_code, 404)


if __name__ == "__main__":
    unittest.main()
