"""Report generator producing clean human-readable text and structured JSON outputs."""

import json
from datetime import datetime
from pathlib import Path
from typing import Dict, Tuple

from models.scan_result import HostResult
from utils.logger import get_logger


class ReportGenerator:
    """Generates text and JSON reports from HostResult scan objects."""

    def __init__(self, output_dir: str = "output"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.logger = get_logger()

    def generate_timestamp(self) -> str:
        """Return standardized timestamp string for report filenames."""
        return datetime.now().strftime("%Y%m%d_%H%M%S")

    def build_text_report(self, result: HostResult) -> str:
        """Construct a formatted plain text summary report.

        Args:
            result: HostResult containing scan findings.

        Returns:
            Formatted multiline string.
        """
        scan_date = result.start_time or datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        lines = [
            "PortSentinel Network Reconnaissance Report",
            "==========================================",
            f"Scan Date:        {scan_date}",
            f"Target:           {result.target}",
            f"Resolved IP:      {result.resolved_ip}",
            f"Host Status:      {result.host_status.upper()}",
            f"Nmap Engine:      {result.nmap_version or 'N/A'}",
            "",
            "Open Ports",
            "----------",
        ]

        open_ports = result.open_ports
        if not open_ports:
            lines.append("No open TCP ports were detected.")
        else:
            header = f"{'Port':<8}{'Protocol':<10}{'State':<8}{'Service':<14}{'Category':<18}{'Version / Product'}"
            lines.append(header)
            lines.append("-" * 80)
            for p in open_ports:
                # Combine product, version, and extra info nicely
                ver_parts = []
                if p.product and p.product != "Not detected":
                    ver_parts.append(p.product)
                if p.version and p.version != "Not detected":
                    ver_parts.append(p.version)
                if p.extra_info:
                    ver_parts.append(f"({p.extra_info})")

                ver_str = " ".join(ver_parts) if ver_parts else (p.version or "Not detected")
                lines.append(
                    f"{str(p.port):<8}{p.protocol.upper():<10}{p.state.upper():<8}{p.service:<14}{p.category:<18}{ver_str}"
                )

        # Service Groups
        lines.append("")
        lines.append("Service Groups")
        lines.append("--------------")
        groups = result.service_groups
        if groups:
            for group, count in sorted(groups.items()):
                lines.append(f"{group:<20}: {count}")
        else:
            lines.append("None")

        # Summary
        lines.append("")
        lines.append("Summary")
        lines.append("-------")
        lines.append(f"Total open ports:         {result.total_open_ports}")
        lines.append(f"Total services detected:  {result.total_services_detected}")
        lines.append(f"Scan duration:            {round(result.scan_duration, 2)}s")

        if result.error_message:
            lines.append(f"Note / Error:             {result.error_message}")

        lines.append("")
        lines.append("=" * 80)
        lines.append("Notice: PortSentinel is intended for authorized security testing and research.")
        lines.append("=" * 80)
        lines.append("")

        return "\n".join(lines)

    def save_reports(self, result: HostResult, base_name: str = "") -> Tuple[Path, Path]:
        """Save both human-readable text and structured JSON reports to disk.

        Args:
            result: HostResult object containing the completed scan.
            base_name: Optional custom base filename prefix.

        Returns:
            Tuple of (txt_filepath, json_filepath)
        """
        ts = self.generate_timestamp()
        prefix = f"scan_{ts}" if not base_name else f"{base_name}_{ts}"

        txt_file = self.output_dir / f"{prefix}.txt"
        json_file = self.output_dir / f"{prefix}.json"

        # 1. Write Text Report
        text_content = self.build_text_report(result)
        txt_file.write_text(text_content, encoding="utf-8")
        self.logger.info(f"Saved text report to {txt_file}")

        # 2. Write JSON Report
        json_content = result.to_json(indent=2)
        json_file.write_text(json_content, encoding="utf-8")
        self.logger.info(f"Saved JSON report to {json_file}")

        return txt_file, json_file
