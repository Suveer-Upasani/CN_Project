"""Host discovery module for PortSentinel."""

from typing import Tuple
from models.scan_result import HostResult
from scanner.nmap_manager import NmapManager
from scanner.parser import NmapXMLParser
from utils.logger import get_logger


class HostDiscovery:
    """Performs host discovery to determine if a target is reachable (UP) or UNREACHABLE."""

    def __init__(self, nmap_manager: NmapManager):
        self.nmap_manager = nmap_manager
        self.parser = NmapXMLParser()
        self.logger = get_logger()

    def discover(self, target: str, resolved_ip: str, timeout: int = 60) -> Tuple[bool, HostResult]:
        """Perform host discovery scan on the target.

        Uses Nmap's host discovery (-sn) with XML output.

        Args:
            target: Original target string/hostname.
            resolved_ip: Resolved IP address.
            timeout: Maximum scan duration in seconds.

        Returns:
            Tuple of (is_up: bool, HostResult)
        """
        self.logger.info(f"Starting host discovery for {target} ({resolved_ip})")

        # Use -sn (No port scan, host discovery only)
        # Note: -PE, -PS22,80,443, -PA80,443 or standard -sn
        args = ["-sn", "-oX", "-", resolved_ip]

        try:
            xml_output = self.nmap_manager.run_scan(args, timeout=timeout)
            result = self.parser.parse_xml_string(xml_output, default_target=target, default_ip=resolved_ip)

            is_up = result.host_status.lower() == "up"
            self.logger.info(f"Host discovery result for {target}: {'UP' if is_up else 'DOWN'}")
            return is_up, result

        except Exception as exc:
            self.logger.warning(f"Host discovery encounter: {exc}. Attempting fallback check.")
            # If standard ping scan is blocked by ICMP filters, check if target is localhost or reachable
            if resolved_ip in ("127.0.0.1", "::1", "localhost"):
                res = HostResult(target=target, resolved_ip=resolved_ip, host_status="up")
                return True, res
            raise
