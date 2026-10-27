"""Service exposure analyzer for PortSentinel.

Evaluates discovered services against transparent exposure rating rules.
"""

from typing import List, Tuple
from models.scan_result import PortInfo, HostResult, ScanResult
from analysis.service_rules import SERVICE_EXPOSURE_RULES, PORT_FALLBACK_RULES


class ExposureAnalyzer:
    """Evaluates exposure level and rationale for ports and services."""

    def evaluate_port(self, port_info: PortInfo) -> PortInfo:
        """Assign exposure_rating and exposure_reason to a PortInfo instance.

        Args:
            port_info: PortInfo object to evaluate.

        Returns:
            Enriched PortInfo object.
        """
        svc = (port_info.service or "").lower().strip()
        prod = (port_info.product or "").lower().strip()

        # 1. Match by exact service name
        if svc in SERVICE_EXPOSURE_RULES:
            rule = SERVICE_EXPOSURE_RULES[svc]
            port_info.exposure_rating = rule["rating"]
            port_info.exposure_reason = rule["reason"]
            if port_info.category in ("Unknown", "") and "category" in rule:
                port_info.category = rule["category"]
            return port_info

        # 2. Match by partial service or product keyword
        for rule_key, rule in SERVICE_EXPOSURE_RULES.items():
            if rule_key in svc or (prod and rule_key in prod):
                port_info.exposure_rating = rule["rating"]
                port_info.exposure_reason = rule["reason"]
                if port_info.category in ("Unknown", "") and "category" in rule:
                    port_info.category = rule["category"]
                return port_info

        # 3. Fallback to known port number
        if port_info.port in PORT_FALLBACK_RULES:
            rule = PORT_FALLBACK_RULES[port_info.port]
            port_info.exposure_rating = rule["rating"]
            port_info.exposure_reason = rule["reason"]
            return port_info

        # 4. Default baseline rating
        if port_info.state.lower() in ("open", "open|filtered"):
            port_info.exposure_rating = "INFO"
            port_info.exposure_reason = f"Port {port_info.port}/{port_info.protocol} detected in active state."
        else:
            port_info.exposure_rating = "INFO"
            port_info.exposure_reason = f"Port {port_info.port}/{port_info.protocol} in {port_info.state} state."

        return port_info

    def analyze_host(self, host_result: HostResult) -> HostResult:
        """Evaluate all ports on a HostResult object."""
        for port in host_result.ports:
            self.evaluate_port(port)
        return host_result

    def analyze_scan(self, scan_result: ScanResult) -> ScanResult:
        """Evaluate all hosts and ports within a ScanResult object."""
        for host in scan_result.hosts:
            self.analyze_host(host)
        return scan_result
