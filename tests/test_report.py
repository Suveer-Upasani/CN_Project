"""Unit tests for report generation (Text and JSON output)."""

import json
import shutil
import tempfile
import unittest
from pathlib import Path

from models.scan_result import HostResult, PortInfo
from reports.report_generator import ReportGenerator


class TestReportGenerator(unittest.TestCase):
    """Test suite for text and JSON report generation."""

    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        self.generator = ReportGenerator(output_dir=self.test_dir)

        self.sample_result = HostResult(
            target="lab.local",
            resolved_ip="192.168.1.50",
            host_status="up",
            scan_duration=8.45,
            start_time="2026-09-24 11:00:00",
            end_time="2026-09-24 11:00:08",
            nmap_version="7.94",
            ports=[
                PortInfo(
                    port=22,
                    protocol="tcp",
                    state="open",
                    service="ssh",
                    product="OpenSSH",
                    version="8.9p1",
                    extra_info="Ubuntu Linux",
                    category="Remote Access",
                ),
                PortInfo(
                    port=80,
                    protocol="tcp",
                    state="open",
                    service="http",
                    product="nginx",
                    version="1.18.0",
                    extra_info="",
                    category="Web",
                ),
            ],
        )

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_build_text_report(self):
        """Verify text report contains required sections and values."""
        text = self.generator.build_text_report(self.sample_result)
        self.assertIn("PortSentinel Network Reconnaissance Report", text)
        self.assertIn("Target:           lab.local", text)
        self.assertIn("Resolved IP:      192.168.1.50", text)
        self.assertIn("Total open ports:         2", text)
        self.assertIn("Remote Access", text)
        self.assertIn("Web", text)

    def test_save_reports_creates_files(self):
        """Verify reports are saved as both .txt and .json files with correct content."""
        txt_path, json_path = self.generator.save_reports(self.sample_result, base_name="test_scan")

        self.assertTrue(txt_path.exists())
        self.assertTrue(json_path.exists())

        # Verify JSON content
        with open(json_path, "r", encoding="utf-8") as f:
            data = json.load(f)

        self.assertEqual(data["target"], "lab.local")
        self.assertEqual(data["resolved_ip"], "192.168.1.50")
        self.assertEqual(data["total_open_ports"], 2)
        self.assertEqual(len(data["ports"]), 2)
        self.assertEqual(data["ports"][0]["port"], 22)
        self.assertEqual(data["ports"][0]["service"], "ssh")


if __name__ == "__main__":
    unittest.main()
