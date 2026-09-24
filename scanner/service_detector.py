"""Targeted service and version detection module for PortSentinel."""

from typing import List
from models.scan_result import PortInfo
from scanner.nmap_manager import NmapManager
from scanner.parser import NmapXMLParser
from utils.logger import get_logger


class ServiceDetector:
    """Performs targeted service and version detection on discovered open ports."""

    def __init__(self, nmap_manager: NmapManager):
        self.nmap_manager = nmap_manager
        self.parser = NmapXMLParser()
        self.logger = get_logger()

    def detect_services(
        self,
        target: str,
        resolved_ip: str,
        open_ports: List[int],
        timing_template: str = "-T4",
        timeout: int = 180,
    ) -> List[PortInfo]:
        """Perform service & version detection on the specified open ports.

        Args:
            target: Original target string.
            resolved_ip: Resolved IP address.
            open_ports: List of integer open port numbers (e.g. [22, 80, 443]).
            timing_template: Nmap timing template (default '-T4').
            timeout: Maximum scan duration in seconds.

        Returns:
            List of PortInfo objects with enriched service, product, and version metadata.
        """
        if not open_ports:
            self.logger.info("No open ports provided for service detection.")
            return []

        port_str = ",".join(str(p) for p in sorted(open_ports))
        self.logger.info(
            f"Starting service/version detection for {target} on port(s): {port_str}"
        )

        args = ["-sV", "-sT", "-Pn", timing_template, "-p", port_str, "-oX", "-", resolved_ip]

        xml_output = self.nmap_manager.run_scan(args, timeout=timeout)
        host_result = self.parser.parse_xml_string(xml_output, default_target=target, default_ip=resolved_ip)

        self.logger.info(
            f"Service detection complete for {target}. Processed {len(host_result.ports)} port(s)."
        )
        return host_result.ports
