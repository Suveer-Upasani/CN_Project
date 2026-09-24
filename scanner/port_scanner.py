"""TCP Port discovery module for PortSentinel."""

from typing import List, Optional
from models.scan_result import PortInfo, HostResult
from scanner.nmap_manager import NmapManager
from scanner.parser import NmapXMLParser
from utils.logger import get_logger


class PortScanner:
    """Performs TCP port discovery against an authorized target."""

    def __init__(self, nmap_manager: NmapManager):
        self.nmap_manager = nmap_manager
        self.parser = NmapXMLParser()
        self.logger = get_logger()

    def scan_ports(
        self,
        target: str,
        resolved_ip: str,
        port_range: Optional[str] = None,
        top_ports: Optional[int] = 1000,
        timing_template: str = "-T4",
        timeout: int = 180,
    ) -> List[PortInfo]:
        """Perform a TCP port scan.

        Uses -sT (TCP connect scan) and -Pn (treat host as online) with -oX -
        for reliable, non-root execution and machine-readable output.

        Args:
            target: Original target string.
            resolved_ip: Resolved IP address.
            port_range: Specific ports (e.g., '1-1024' or '22,80,443').
            top_ports: Scan top N ports if port_range is not specified (default 1000).
            timing_template: Nmap timing template (default '-T4').
            timeout: Maximum scan duration in seconds.

        Returns:
            List of discovered PortInfo objects.
        """
        self.logger.info(f"Starting TCP port discovery for {target} ({resolved_ip})")

        args = ["-sT", "-Pn", timing_template]

        if port_range:
            args.extend(["-p", port_range])
        elif top_ports:
            args.extend(["--top-ports", str(top_ports)])

        args.extend(["-oX", "-", resolved_ip])

        xml_output = self.nmap_manager.run_scan(args, timeout=timeout)
        host_result = self.parser.parse_xml_string(xml_output, default_target=target, default_ip=resolved_ip)

        open_ports = [p for p in host_result.ports if p.state.lower() == "open"]
        self.logger.info(
            f"Port discovery complete for {target}. Found {len(open_ports)} open port(s)."
        )
        return host_result.ports
