"""UDP Port scanning module for PortSentinel.

Performs UDP port reconnaissance using Nmap (-sU) against authorized targets.
"""

from typing import List, Optional
from models.scan_result import PortInfo
from scanner.nmap_manager import NmapManager
from scanner.parser import NmapXMLParser
from utils.logger import get_logger

# Sensible default common UDP ports for practical educational scanning
DEFAULT_COMMON_UDP_PORTS = "53,67,68,69,123,137,138,161,162,500,514,520,631,1434,1900,4500,5353"


class UDPScanner:
    """Performs UDP port discovery against authorized targets."""

    def __init__(self, nmap_manager: NmapManager):
        self.nmap_manager = nmap_manager
        self.parser = NmapXMLParser()
        self.logger = get_logger()

    def scan_ports(
        self,
        target: str,
        resolved_ip: str,
        udp_ports: Optional[str] = None,
        top_ports: Optional[int] = None,
        timing_template: str = "-T4",
        timeout: int = 180,
    ) -> List[PortInfo]:
        """Perform a UDP port scan.

        Uses -sU and -Pn with XML output.

        Args:
            target: Original target string.
            resolved_ip: Resolved IP address.
            udp_ports: Specific UDP ports (e.g., '53,123,161' or '53-100').
            top_ports: Scan top N UDP ports if specified.
            timing_template: Nmap timing template (default '-T4').
            timeout: Maximum scan duration in seconds.

        Returns:
            List of discovered PortInfo objects with protocol='udp'.
        """
        self.logger.info(f"Starting UDP port discovery for {target} ({resolved_ip})")

        args = ["-sU", "-Pn", timing_template]

        if udp_ports:
            args.extend(["-p", udp_ports])
        elif top_ports:
            args.extend(["--top-ports", str(top_ports)])
        else:
            args.extend(["-p", DEFAULT_COMMON_UDP_PORTS])

        args.extend(["-oX", "-", resolved_ip])

        xml_output = self.nmap_manager.run_scan(args, timeout=timeout)
        host_result = self.parser.parse_xml_string(xml_output, default_target=target, default_ip=resolved_ip)

        active_udp = [p for p in host_result.ports if p.state.lower() in ("open", "open|filtered")]
        self.logger.info(
            f"UDP discovery complete for {target}. Found {len(active_udp)} active UDP finding(s)."
        )
        return host_result.ports
