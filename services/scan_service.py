"""Background scan orchestration service for PortSentinel."""

import concurrent.futures
import re
import threading
import time
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from models.scan_result import HostResult, PortInfo
from reports.report_generator import ReportGenerator
from scanner.discovery import HostDiscovery
from scanner.nmap_manager import (
    NmapExecutionError,
    NmapManager,
    NmapNotFoundError,
    NmapTimeoutError,
)
from scanner.port_scanner import PortScanner
from scanner.service_detector import ServiceDetector
from services.history_repository import HistoryRepository
from utils.logger import get_logger
from utils.validator import validate_target


def validate_port_specification(port_str: Optional[str]) -> Tuple[bool, Optional[str]]:
    """Validate user-supplied port range string.

    Supports:
        - None or empty (defaults to Nmap top 1000)
        - Single port: '80'
        - Range: '1-1000'
        - Comma-separated: '22,80,443'
        - Combined: '80,443,8000-8080'

    Returns:
        Tuple of (is_valid: bool, error_message: Optional[str])
    """
    if not port_str:
        return True, None

    clean = port_str.strip()
    if not clean:
        return True, None

    # Check for illegal characters (only digits, commas, and hyphens allowed)
    if not re.match(r"^[0-9,\-]+$", clean):
        return (
            False,
            "Port specification contains invalid characters. Use digits, commas, and hyphens only (e.g. 22,80,443 or 1-1024).",
        )

    parts = [p.strip() for p in clean.split(",") if p.strip()]
    if not parts:
        return False, "Port specification cannot be empty commas."

    for item in parts:
        if "-" in item:
            sub = item.split("-")
            if len(sub) != 2:
                return False, f"Invalid port range format: '{item}'."
            try:
                start, end = int(sub[0]), int(sub[1])
            except ValueError:
                return False, f"Non-numeric port in range: '{item}'."

            if start < 1 or end > 65535 or start > end:
                return (
                    False,
                    f"Port range '{item}' is out of bounds (valid: 1-65535 with start <= end).",
                )
        else:
            try:
                p = int(item)
            except ValueError:
                return False, f"Non-numeric port: '{item}'."
            if p < 1 or p > 65535:
                return False, f"Port '{p}' is out of bounds (valid: 1-65535)."

    return True, None


class ScanJob:
    """Represents an active in-memory scan job."""

    def __init__(
        self,
        scan_id: str,
        target: str,
        resolved_ip: Optional[str] = None,
        port_range: Optional[str] = None,
    ):
        self.scan_id = scan_id
        self.target = target
        self.resolved_ip = resolved_ip or target
        self.port_range = port_range
        self.status = "queued"  # queued, running, completed, failed
        self.current_phase = "Queued"
        self.created_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.start_time: Optional[str] = None
        self.end_time: Optional[str] = None
        self.start_epoch: Optional[float] = None
        self.duration: float = 0.0
        self.error_message: Optional[str] = None
        self.result: Optional[HostResult] = None
        self.txt_report_path: Optional[str] = None
        self.json_report_path: Optional[str] = None
        self.nmap_version: str = ""

    @property
    def elapsed_seconds(self) -> float:
        """Calculate current elapsed time in seconds."""
        if self.duration > 0:
            return round(self.duration, 2)
        if self.start_epoch:
            return round(time.time() - self.start_epoch, 2)
        return 0.0

    def to_status_dict(self) -> Dict[str, Any]:
        """Convert job to lightweight status dictionary for polling."""
        return {
            "scan_id": self.scan_id,
            "target": self.target,
            "resolved_ip": self.resolved_ip,
            "status": self.status,
            "current_phase": self.current_phase,
            "created_at": self.created_at,
            "start_time": self.start_time,
            "end_time": self.end_time,
            "elapsed_seconds": self.elapsed_seconds,
            "duration": round(self.duration, 2),
            "error_message": self.error_message,
            "is_complete": self.status in ("completed", "failed"),
        }


class ScanService:
    """Coordinates target scanning, background execution, and report delivery."""

    def __init__(
        self,
        max_concurrent_scans: int = 2,
        output_dir: str = "output",
        db_path: str = "data/portsentinel.db",
        timeout: int = 300,
    ):
        self.logger = get_logger()
        self.max_concurrent_scans = max_concurrent_scans
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.timeout = timeout

        self.repo = HistoryRepository(db_path=db_path)
        self.nmap_mgr = NmapManager()
        self.report_gen = ReportGenerator(output_dir=str(self.output_dir))

        self._active_jobs: Dict[str, ScanJob] = {}
        self._lock = threading.Lock()
        self._executor = concurrent.futures.ThreadPoolExecutor(
            max_workers=self.max_concurrent_scans,
            thread_name_prefix="PortSentinelWorker",
        )

    def get_active_scans_count(self) -> int:
        """Count active jobs currently queued or running."""
        with self._lock:
            return sum(
                1 for j in self._active_jobs.values() if j.status in ("queued", "running")
            )

    def submit_scan(
        self,
        target_input: str,
        authorized: bool,
        port_range: Optional[str] = None,
    ) -> Tuple[bool, Dict[str, Any], int]:
        """Validate input and enqueue a new scan job.

        Returns:
            Tuple of (success_bool, response_dict, http_status_code)
        """
        # 1. Authorization check
        if not authorized:
            return (
                False,
                {
                    "error": "Scan authorization not confirmed. You must confirm explicit permission to scan the target."
                },
                400,
            )

        # 2. Concurrency limit check
        if self.get_active_scans_count() >= self.max_concurrent_scans:
            return (
                False,
                {
                    "error": f"Maximum concurrent scans limit reached ({self.max_concurrent_scans}). Please wait for an existing scan to finish."
                },
                429,
            )

        # 3. Port range syntax check
        valid_ports, port_err = validate_port_specification(port_range)
        if not valid_ports:
            return False, {"error": port_err}, 400

        # 4. Target validation using existing validator
        val_result = validate_target(target_input)
        if not val_result.is_valid:
            return (
                False,
                {"error": val_result.error_message or "Invalid target syntax."},
                400,
            )

        # 5. Generate Scan ID
        now_ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        unique_suffix = uuid.uuid4().hex[:6]
        scan_id = f"scan_{now_ts}_{unique_suffix}"

        resolved_ip = val_result.resolved_ip or val_result.target
        job = ScanJob(
            scan_id=scan_id,
            target=val_result.target,
            resolved_ip=resolved_ip,
            port_range=port_range.strip() if port_range else None,
        )

        with self._lock:
            self._active_jobs[scan_id] = job

        # Save initial queued record in SQLite
        self.repo.create_scan(
            scan_id=scan_id,
            target=val_result.target,
            resolved_ip=resolved_ip,
            status="queued",
            current_phase="Queued",
        )

        # Dispatch background worker
        self._executor.submit(self._execute_scan_worker, job)

        self.logger.info(
            f"Submitted scan {scan_id} for {job.target} (resolved: {job.resolved_ip})"
        )

        return (
            True,
            {
                "success": True,
                "scan_id": scan_id,
                "target": job.target,
                "resolved_ip": job.resolved_ip,
                "status": "queued",
                "current_phase": "Queued",
                "status_url": f"/api/scans/{scan_id}/status",
                "details_url": f"/scans/{scan_id}",
            },
            201,
        )

    def _execute_scan_worker(self, job: ScanJob) -> None:
        """Worker thread executing the real reconnaissance pipeline."""
        job.status = "running"
        job.start_epoch = time.time()
        job.start_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        self.repo.update_scan_progress(
            scan_id=job.scan_id,
            status="running",
            current_phase="Validating target",
            start_time=job.start_time,
        )

        try:
            # Step 1: Target Validation & DNS confirmation
            job.current_phase = "Validating target"
            self.repo.update_scan_progress(job.scan_id, current_phase=job.current_phase)

            val_res = validate_target(job.target)
            if not val_res.is_valid:
                raise ValueError(val_res.error_message or "Target validation failed.")

            job.resolved_ip = val_res.resolved_ip or job.target
            self.repo.update_scan_progress(job.scan_id, resolved_ip=job.resolved_ip)

            # Step 2: Nmap Dependency Check
            job.current_phase = "Checking Nmap engine"
            self.repo.update_scan_progress(job.scan_id, current_phase=job.current_phase)

            if not self.nmap_mgr.is_available():
                raise NmapNotFoundError(
                    "Nmap is not installed or not available in the system PATH."
                )

            has_ver, ver_str = self.nmap_mgr.get_version()
            if not has_ver:
                raise NmapExecutionError(f"Unable to verify Nmap installation: {ver_str}")
            job.nmap_version = ver_str

            # Step 3: Host Discovery
            job.current_phase = "Discovering host"
            self.repo.update_scan_progress(job.scan_id, current_phase=job.current_phase)

            discovery = HostDiscovery(self.nmap_mgr)
            is_up, disc_result = discovery.discover(
                target=job.target,
                resolved_ip=job.resolved_ip,
                timeout=min(self.timeout, 60),
            )

            if not is_up:
                # Target host is unreachable or filtered
                duration = time.time() - job.start_epoch
                job.duration = duration
                job.end_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                job.status = "completed"
                job.current_phase = "Completed (Host Unreachable)"

                unreach_result = HostResult(
                    target=job.target,
                    resolved_ip=job.resolved_ip,
                    host_status="unreachable",
                    scan_duration=duration,
                    start_time=job.start_time,
                    end_time=job.end_time,
                    nmap_version=job.nmap_version,
                    error_message=f"Target host '{job.resolved_ip}' could not be reached or is filtering discovery probes.",
                    ports=[],
                )
                job.result = unreach_result

                # Generate reports explaining host unreachability
                txt_path, json_path = self.report_gen.save_reports(
                    unreach_result, base_name=job.scan_id
                )
                job.txt_report_path = str(txt_path.resolve())
                job.json_report_path = str(json_path.resolve())

                self.repo.complete_scan(
                    scan_id=job.scan_id,
                    host_status="unreachable",
                    duration=duration,
                    end_time=job.end_time,
                    open_ports_count=0,
                    services_count=0,
                    nmap_version=job.nmap_version,
                    result_json=unreach_result.to_json(),
                    txt_report_path=job.txt_report_path,
                    json_report_path=job.json_report_path,
                    error_message=unreach_result.error_message,
                    resolved_ip=job.resolved_ip,
                )
                self.logger.info(
                    f"Scan {job.scan_id} finished: host unreachable for {job.resolved_ip}"
                )
                return

            # Step 4: TCP Port Discovery
            job.current_phase = "Discovering TCP ports"
            self.repo.update_scan_progress(job.scan_id, current_phase=job.current_phase)

            port_scanner = PortScanner(self.nmap_mgr)
            discovered_ports = port_scanner.scan_ports(
                target=job.target,
                resolved_ip=job.resolved_ip,
                port_range=job.port_range,
                timeout=self.timeout,
            )

            open_ports = [p for p in discovered_ports if p.state.lower() == "open"]

            enriched_ports: List[PortInfo] = []
            if open_ports:
                # Step 5: Service & Version Detection
                job.current_phase = "Detecting services and versions"
                self.repo.update_scan_progress(job.scan_id, current_phase=job.current_phase)

                service_detector = ServiceDetector(self.nmap_mgr)
                open_nums = [p.port for p in open_ports]

                try:
                    enriched_ports = service_detector.detect_services(
                        target=job.target,
                        resolved_ip=job.resolved_ip,
                        open_ports=open_nums,
                        timeout=self.timeout,
                    )
                except (NmapTimeoutError, NmapExecutionError) as exc:
                    self.logger.warning(
                        f"Service detection failed ({exc}). Retaining basic port discoveries."
                    )
                    enriched_ports = open_ports
            else:
                enriched_ports = []

            # Step 6: Generate Reports
            job.current_phase = "Generating reports"
            self.repo.update_scan_progress(job.scan_id, current_phase=job.current_phase)

            duration = time.time() - job.start_epoch
            job.duration = duration
            job.end_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

            final_ports = enriched_ports or open_ports
            final_result = HostResult(
                target=job.target,
                resolved_ip=job.resolved_ip,
                host_status="up",
                scan_duration=duration,
                start_time=job.start_time,
                end_time=job.end_time,
                nmap_version=job.nmap_version,
                ports=final_ports,
            )
            job.result = final_result

            txt_path, json_path = self.report_gen.save_reports(
                final_result, base_name=job.scan_id
            )
            job.txt_report_path = str(txt_path.resolve())
            job.json_report_path = str(json_path.resolve())

            # Step 7: Completed
            job.status = "completed"
            job.current_phase = "Completed"

            self.repo.complete_scan(
                scan_id=job.scan_id,
                host_status="up",
                duration=duration,
                end_time=job.end_time,
                open_ports_count=final_result.total_open_ports,
                services_count=final_result.total_services_detected,
                nmap_version=job.nmap_version,
                result_json=final_result.to_json(),
                txt_report_path=job.txt_report_path,
                json_report_path=job.json_report_path,
                resolved_ip=job.resolved_ip,
            )
            self.logger.info(
                f"Scan {job.scan_id} completed successfully for {job.resolved_ip}. Open ports: {final_result.total_open_ports}"
            )

        except NmapNotFoundError as exc:
            self._handle_failure(job, f"Nmap engine error: {exc}")
        except NmapTimeoutError as exc:
            self._handle_failure(job, f"Scan operation timed out: {exc}")
        except NmapExecutionError as exc:
            self._handle_failure(job, f"Nmap execution failed: {exc}")
        except Exception as exc:
            self.logger.exception(f"Unexpected error executing scan {job.scan_id}:")
            self._handle_failure(job, f"Scan error: {str(exc)}")

    def _handle_failure(self, job: ScanJob, error_message: str) -> None:
        """Handle worker failure by recording safe error state."""
        duration = time.time() - (job.start_epoch or time.time())
        job.duration = duration
        job.status = "failed"
        job.current_phase = "Failed"
        job.error_message = error_message
        job.end_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        self.repo.fail_scan(job.scan_id, error_message=error_message, duration=duration)
        self.logger.error(f"Scan {job.scan_id} failed: {error_message}")

    def get_scan(self, scan_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve full scan details from active cache or SQLite."""
        # Check active in-memory job first for live progress
        with self._lock:
            active = self._active_jobs.get(scan_id)
            if active and active.status in ("queued", "running"):
                d = active.to_status_dict()
                d["host_status"] = "scanning"
                d["ports"] = []
                d["service_groups"] = {}
                d["exposure_breakdown"] = {}
                d["txt_report_url"] = None
                d["json_report_url"] = None
                return d

        # Retrieve from SQLite repository
        db_record = self.repo.get_scan(scan_id)
        if not db_record:
            return None

        # Build report download URLs if reports exist
        if db_record.get("status") == "completed":
            db_record["txt_report_url"] = f"/reports/{scan_id}/download?format=txt"
            db_record["json_report_url"] = f"/reports/{scan_id}/download?format=json"
        else:
            db_record["txt_report_url"] = None
            db_record["json_report_url"] = None

        return db_record

    def get_scan_status(self, scan_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve lightweight scan status for frontend polling."""
        with self._lock:
            active = self._active_jobs.get(scan_id)
            if active:
                return active.to_status_dict()

        db_record = self.repo.get_scan(scan_id)
        if not db_record:
            return None

        return {
            "scan_id": db_record["scan_id"],
            "target": db_record["target"],
            "resolved_ip": db_record["resolved_ip"],
            "status": db_record["status"],
            "current_phase": db_record["current_phase"],
            "created_at": db_record["created_at"],
            "start_time": db_record["start_time"],
            "end_time": db_record["end_time"],
            "elapsed_seconds": round(db_record["duration"], 2),
            "duration": round(db_record["duration"], 2),
            "error_message": db_record["error_message"],
            "is_complete": db_record["status"] in ("completed", "failed"),
        }

    def get_recent_scans(self, limit: int = 10) -> List[Dict[str, Any]]:
        """Get list of recent scans for dashboard display."""
        return self.repo.list_scans(limit=limit)

    def list_all_scans(self, limit: int = 100, offset: int = 0) -> List[Dict[str, Any]]:
        """Get scan history records."""
        return self.repo.list_scans(limit=limit, offset=offset)

    def get_metrics(self) -> Dict[str, Any]:
        """Get dashboard overview metrics."""
        return self.repo.get_metrics()

    def list_reports(self, limit: int = 10) -> List[Dict[str, Any]]:
        """List generated reports that exist on disk."""
        return self.repo.list_reports(limit=limit)

    def get_report_path(self, scan_id: str, format_type: str) -> Optional[Path]:
        """Safely resolve report file path, verifying scan ownership and preventing traversal."""
        format_type = format_type.lower().strip()
        if format_type not in ("txt", "json"):
            return None

        scan = self.repo.get_scan(scan_id)
        if not scan:
            return None

        report_str = (
            scan.get("txt_report_path")
            if format_type == "txt"
            else scan.get("json_report_path")
        )
        if not report_str:
            return None

        file_path = Path(report_str).resolve()
        base_dir = self.output_dir.resolve()

        # Security check: must reside strictly inside the output directory
        try:
            file_path.relative_to(base_dir)
        except ValueError:
            self.logger.warning(
                f"Path traversal attempt or invalid report path: {file_path}"
            )
            return None

        if not file_path.is_file():
            self.logger.warning(f"Report file not found on disk: {file_path}")
            return None

        return file_path
