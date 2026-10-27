"""Unit and integration tests for background ScanService orchestration and job transitions."""

import os
import tempfile
import time
import unittest
from unittest.mock import MagicMock, patch

from models.scan_result import HostResult, PortInfo
from scanner.nmap_manager import NmapExecutionError, NmapNotFoundError, NmapTimeoutError
from services.scan_service import ScanJob, ScanService, validate_port_specification


class TestScanService(unittest.TestCase):
    """Test suite for ScanService orchestration."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self.temp_dir.name, "service_test.db")
        self.output_dir = os.path.join(self.temp_dir.name, "output")
        os.makedirs(self.output_dir, exist_ok=True)

        self.service = ScanService(
            max_concurrent_scans=2,
            output_dir=self.output_dir,
            db_path=self.db_path,
            timeout=10,
        )

    def tearDown(self):
        self.service._executor.shutdown(wait=False)
        self.temp_dir.cleanup()

    def test_validate_port_specification(self):
        """Test port specification syntax validator."""
        # Valid cases
        valid_cases = [None, "", "   ", "80", "1-1024", "22,80,443", "80,443,8000-8080"]
        for c in valid_cases:
            is_valid, err = validate_port_specification(c)
            self.assertTrue(is_valid, f"Port spec '{c}' should be valid, got: {err}")

        # Invalid cases
        invalid_cases = [
            "abc",
            "80; ls",
            "99999",
            "0",
            "1000-500",
            "80-",
            "-80",
            ",,,",
            "80,abc,443",
        ]
        for c in invalid_cases:
            is_valid, err = validate_port_specification(c)
            self.assertFalse(is_valid, f"Port spec '{c}' should be invalid")

    def test_submit_scan_concurrency_limit(self):
        """Verify concurrency limits reject excessive scans."""
        self.service.max_concurrent_scans = 1

        # Simulate 1 active job
        fake_job = ScanJob("fake_01", "127.0.0.1")
        fake_job.status = "running"
        with self.service._lock:
            self.service._active_jobs["fake_01"] = fake_job

        success, res, code = self.service.submit_scan(
            target_input="192.168.1.1", authorized=True
        )
        self.assertFalse(success)
        self.assertEqual(code, 429)
        self.assertIn("limit reached", res["error"].lower())

    @patch("scanner.discovery.HostDiscovery.discover")
    @patch("scanner.port_scanner.PortScanner.scan_ports")
    @patch("scanner.service_detector.ServiceDetector.detect_services")
    def test_successful_scan_worker_execution(
        self, mock_detect, mock_ports, mock_discover
    ):
        """Verify end-to-end background execution with mocked Nmap."""
        mock_discover.return_value = (
            True,
            HostResult(target="192.168.1.50", resolved_ip="192.168.1.50", host_status="up"),
        )
        mock_ports.return_value = [
            PortInfo(port=22, protocol="tcp", state="open", service="ssh"),
            PortInfo(port=80, protocol="tcp", state="open", service="http"),
        ]
        mock_detect.return_value = [
            PortInfo(
                port=22,
                protocol="tcp",
                state="open",
                service="ssh",
                product="OpenSSH",
                version="9.0",
                category="Remote Access",
            ),
            PortInfo(
                port=80,
                protocol="tcp",
                state="open",
                service="http",
                product="nginx",
                version="1.24",
                category="Web",
            ),
        ]

        # Submit scan synchronously running worker
        job = ScanJob(
            scan_id="scan_mock_success",
            target="192.168.1.50",
            resolved_ip="192.168.1.50",
        )
        self.service.repo.create_scan(job.scan_id, job.target, job.resolved_ip)

        # Run worker directly to test logic
        self.service._execute_scan_worker(job)

        self.assertEqual(job.status, "completed")
        self.assertEqual(job.current_phase, "Completed")
        self.assertIsNotNone(job.result)
        self.assertEqual(job.result.total_open_ports, 2)
        self.assertTrue(os.path.isfile(job.txt_report_path))
        self.assertTrue(os.path.isfile(job.json_report_path))

        # Check persistence
        db_scan = self.service.repo.get_scan("scan_mock_success")
        self.assertEqual(db_scan["status"], "completed")
        self.assertEqual(db_scan["open_ports_count"], 2)

    @patch("scanner.discovery.HostDiscovery.discover")
    def test_unreachable_host_execution(self, mock_discover):
        """Verify that an unreachable host completes gracefully without crashing."""
        mock_discover.return_value = (
            False,
            HostResult(
                target="192.168.1.254",
                resolved_ip="192.168.1.254",
                host_status="unreachable",
            ),
        )

        job = ScanJob(
            scan_id="scan_mock_unreach",
            target="192.168.1.254",
            resolved_ip="192.168.1.254",
        )
        self.service.repo.create_scan(job.scan_id, job.target, job.resolved_ip)

        self.service._execute_scan_worker(job)

        self.assertEqual(job.status, "completed")
        self.assertIn("Unreachable", job.current_phase)
        self.assertEqual(job.result.host_status, "unreachable")
        self.assertEqual(job.result.total_open_ports, 0)
        self.assertTrue(os.path.isfile(job.txt_report_path))

    @patch("scanner.nmap_manager.NmapManager.is_available")
    def test_missing_nmap_handling(self, mock_is_avail):
        """Verify graceful error recording when Nmap binary is missing."""
        mock_is_avail.return_value = False

        job = ScanJob(
            scan_id="scan_mock_no_nmap",
            target="127.0.0.1",
            resolved_ip="127.0.0.1",
        )
        self.service.repo.create_scan(job.scan_id, job.target, job.resolved_ip)

        self.service._execute_scan_worker(job)

        self.assertEqual(job.status, "failed")
        self.assertIn("not installed", job.error_message.lower())

    @patch("scanner.discovery.HostDiscovery.discover")
    def test_nmap_timeout_handling(self, mock_discover):
        """Verify graceful error recording when Nmap times out."""
        mock_discover.side_effect = NmapTimeoutError("Scan timed out after 10 seconds.")

        job = ScanJob(
            scan_id="scan_mock_timeout",
            target="10.0.0.1",
            resolved_ip="10.0.0.1",
        )
        self.service.repo.create_scan(job.scan_id, job.target, job.resolved_ip)

        self.service._execute_scan_worker(job)

        self.assertEqual(job.status, "failed")
        self.assertIn("timed out", job.error_message.lower())


if __name__ == "__main__":
    unittest.main()
