"""Robust Nmap XML parser using standard library xml.etree.ElementTree.

Supports single-host and multi-host XML outputs, TCP/UDP protocols,
extended port states (open, open|filtered, filtered, closed), and NSE script results.
"""

import xml.etree.ElementTree as ET
from typing import List, Dict, Any, Optional

from models.scan_result import PortInfo, HostResult
from utils.categorizer import categorize_service
from utils.logger import get_logger


class NmapXMLParser:
    """Parses machine-readable Nmap XML outputs into structured Python models."""

    def __init__(self):
        self.logger = get_logger()

    def _parse_host_element(self, host_elem: ET.Element, nmap_version: str = "", start_str: str = "", default_target: str = "", default_ip: str = "") -> HostResult:
        """Parse an individual <host> XML element into a HostResult."""
        # 1. Parse Status
        status_elem = host_elem.find("status")
        host_status = "down"
        if status_elem is not None:
            host_status = status_elem.get("state", "down").lower()

        # 2. Parse Address
        resolved_ip = default_ip
        for addr_elem in host_elem.findall("address"):
            if addr_elem.get("addrtype") in ("ipv4", "ipv6"):
                resolved_ip = addr_elem.get("addr", resolved_ip)
                break

        # 3. Parse Hostname
        hostname = ""
        hostnames_elem = host_elem.find("hostnames")
        if hostnames_elem is not None:
            hn_elem = hostnames_elem.find("hostname")
            if hn_elem is not None:
                hostname = hn_elem.get("name", "")

        # 4. Parse Ports
        ports_list: List[PortInfo] = []
        ports_elem = host_elem.find("ports")
        if ports_elem is not None:
            for port_elem in ports_elem.findall("port"):
                port_id_str = port_elem.get("portid")
                protocol = port_elem.get("protocol", "tcp").lower()

                if not port_id_str or not port_id_str.isdigit():
                    continue
                port_id = int(port_id_str)

                # State (supports open, closed, filtered, open|filtered)
                state_elem = port_elem.find("state")
                state = state_elem.get("state", "unknown").lower() if state_elem is not None else "unknown"

                # Service & Version details
                service_elem = port_elem.find("service")
                service_name = "unknown"
                product = "Not detected"
                version = "Not detected"
                extra_info = ""

                if service_elem is not None:
                    service_name = service_elem.get("name", "unknown") or "unknown"
                    prod_val = service_elem.get("product")
                    if prod_val:
                        product = prod_val.strip()

                    ver_val = service_elem.get("version")
                    if ver_val:
                        version = ver_val.strip()

                    extra_val = service_elem.get("extrainfo")
                    if extra_val:
                        extra_info = extra_val.strip()

                category = categorize_service(service_name, product)

                # Parse NSE script tags inside port
                nse_results: Dict[str, str] = {}
                for script_elem in port_elem.findall("script"):
                    s_id = script_elem.get("id")
                    s_output = script_elem.get("output", "")
                    if s_id:
                        nse_results[s_id] = s_output.strip()

                port_info = PortInfo(
                    port=port_id,
                    protocol=protocol,
                    state=state,
                    service=service_name,
                    product=product,
                    version=version,
                    extra_info=extra_info,
                    category=category,
                    nse_results=nse_results,
                )
                ports_list.append(port_info)

        return HostResult(
            target=hostname or default_target or resolved_ip,
            resolved_ip=resolved_ip,
            hostname=hostname,
            host_status=host_status,
            nmap_version=nmap_version,
            start_time=start_str,
            ports=ports_list,
        )

    def parse_xml_string(self, xml_content: str, default_target: str = "", default_ip: str = "") -> HostResult:
        """Parse single-host Nmap XML string into a structured HostResult object (Phase 1 compatible).

        Args:
            xml_content: The raw XML string from 'nmap -oX -'.
            default_target: Target name/input to fall back to.
            default_ip: Resolved IP to fall back to.

        Returns:
            HostResult object populated with host status, open ports, and detected services.
        """
        if not xml_content or not xml_content.strip():
            return HostResult(
                target=default_target,
                resolved_ip=default_ip,
                host_status="unreachable",
                error_message="Empty XML output received from Nmap.",
            )

        try:
            root = ET.fromstring(xml_content.strip())
        except ET.ParseError as exc:
            self.logger.error(f"XML parse error: {exc}")
            return HostResult(
                target=default_target,
                resolved_ip=default_ip,
                host_status="unreachable",
                error_message=f"Failed to parse Nmap XML output: {exc}",
            )

        nmap_version = root.get("version", "")
        start_str = root.get("startstr", "")

        host_elem = root.find("host")
        if host_elem is None:
            return HostResult(
                target=default_target,
                resolved_ip=default_ip,
                host_status="unreachable",
                nmap_version=nmap_version,
                start_time=start_str,
            )

        return self._parse_host_element(
            host_elem,
            nmap_version=nmap_version,
            start_str=start_str,
            default_target=default_target,
            default_ip=default_ip,
        )

    def parse_all_hosts(self, xml_content: str, default_target: str = "") -> List[HostResult]:
        """Parse multi-host Nmap XML string into a list of HostResult objects.

        Args:
            xml_content: The raw XML string from 'nmap -oX -'.
            default_target: Target name/CIDR prefix to fall back to.

        Returns:
            List of HostResult objects for each host discovered.
        """
        if not xml_content or not xml_content.strip():
            return []

        try:
            root = ET.fromstring(xml_content.strip())
        except ET.ParseError as exc:
            self.logger.error(f"XML parse error in parse_all_hosts: {exc}")
            return []

        nmap_version = root.get("version", "")
        start_str = root.get("startstr", "")

        results: List[HostResult] = []
        for host_elem in root.findall("host"):
            host_res = self._parse_host_element(
                host_elem,
                nmap_version=nmap_version,
                start_str=start_str,
                default_target=default_target,
            )
            results.append(host_res)

        return results
