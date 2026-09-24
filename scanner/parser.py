"""Robust Nmap XML parser using standard library xml.etree.ElementTree."""

import xml.etree.ElementTree as ET
from typing import List, Dict, Any, Optional

from models.scan_result import PortInfo, HostResult
from utils.categorizer import categorize_service
from utils.logger import get_logger


class NmapXMLParser:
    """Parses machine-readable Nmap XML outputs into structured Python models."""

    def __init__(self):
        self.logger = get_logger()

    def parse_xml_string(self, xml_content: str, default_target: str = "", default_ip: str = "") -> HostResult:
        """Parse Nmap XML string into a structured HostResult object.

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

        # Look for host element
        host_elem = root.find("host")
        if host_elem is None:
            # Host might be down or not responding
            return HostResult(
                target=default_target,
                resolved_ip=default_ip,
                host_status="unreachable",
                nmap_version=nmap_version,
                start_time=start_str,
            )

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

        # 3. Parse Ports
        ports_list: List[PortInfo] = []
        ports_elem = host_elem.find("ports")
        if ports_elem is not None:
            for port_elem in ports_elem.findall("port"):
                port_id_str = port_elem.get("portid")
                protocol = port_elem.get("protocol", "tcp").lower()

                if not port_id_str or not port_id_str.isdigit():
                    continue
                port_id = int(port_id_str)

                # State
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

                port_info = PortInfo(
                    port=port_id,
                    protocol=protocol,
                    state=state,
                    service=service_name,
                    product=product,
                    version=version,
                    extra_info=extra_info,
                    category=category,
                )
                ports_list.append(port_info)

        return HostResult(
            target=default_target or resolved_ip,
            resolved_ip=resolved_ip,
            host_status=host_status,
            nmap_version=nmap_version,
            start_time=start_str,
            ports=ports_list,
        )
