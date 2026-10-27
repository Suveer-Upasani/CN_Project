"""Structured data models representing ports, services, and complete scan results."""

from dataclasses import dataclass, field, asdict
from typing import List, Dict, Any, Optional
import json


@dataclass
class PortInfo:
    """Represents the state, service, version, and exposure details of a single network port."""
    port: int
    protocol: str = "tcp"
    state: str = "open"  # 'open', 'closed', 'filtered', 'open|filtered'
    service: str = "unknown"
    product: str = "Not detected"
    version: str = "Not detected"
    extra_info: str = ""
    category: str = "Unknown"
    exposure_rating: str = "INFO"  # 'INFO', 'LOW', 'MEDIUM', 'HIGH'
    exposure_reason: str = ""
    nse_results: Dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert the port data to a JSON-serializable dictionary."""
        return {
            "port": self.port,
            "protocol": self.protocol,
            "state": self.state,
            "service": self.service,
            "product": self.product,
            "version": self.version,
            "extra_info": self.extra_info,
            "category": self.category,
            "exposure_rating": self.exposure_rating,
            "exposure_reason": self.exposure_reason,
            "nse_results": self.nse_results,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "PortInfo":
        """Reconstruct PortInfo from a dictionary."""
        return cls(
            port=int(data.get("port", 0)),
            protocol=data.get("protocol", "tcp"),
            state=data.get("state", "open"),
            service=data.get("service", "unknown"),
            product=data.get("product", "Not detected"),
            version=data.get("version", "Not detected"),
            extra_info=data.get("extra_info", ""),
            category=data.get("category", "Unknown"),
            exposure_rating=data.get("exposure_rating", "INFO"),
            exposure_reason=data.get("exposure_reason", ""),
            nse_results=data.get("nse_results", {}) or {},
        )


@dataclass
class HostResult:
    """Represents the full reconnaissance result for a single target host."""
    target: str
    resolved_ip: str
    host_status: str = "down"  # 'up', 'down', or 'unreachable'
    scan_duration: float = 0.0
    ports: List[PortInfo] = field(default_factory=list)
    start_time: str = ""
    end_time: str = ""
    nmap_version: str = ""
    error_message: Optional[str] = None
    hostname: str = ""

    @property
    def open_ports(self) -> List[PortInfo]:
        """Return all ports that are in the 'open' state."""
        return [p for p in self.ports if p.state.lower() == "open"]

    @property
    def open_or_filtered_ports(self) -> List[PortInfo]:
        """Return all ports that are open or open|filtered (useful for UDP)."""
        return [p for p in self.ports if p.state.lower() in ("open", "open|filtered")]

    @property
    def tcp_open_ports(self) -> List[PortInfo]:
        """Return all TCP open ports."""
        return [p for p in self.ports if p.protocol.lower() == "tcp" and p.state.lower() == "open"]

    @property
    def udp_findings(self) -> List[PortInfo]:
        """Return all UDP findings (open or open|filtered)."""
        return [p for p in self.ports if p.protocol.lower() == "udp" and p.state.lower() in ("open", "open|filtered")]

    @property
    def total_open_ports(self) -> int:
        """Count of strictly open ports."""
        return len(self.open_ports)

    @property
    def total_findings(self) -> int:
        """Count of active port findings (open + open|filtered)."""
        return len(self.open_or_filtered_ports)

    @property
    def total_services_detected(self) -> int:
        """Count of open/active ports with identified services."""
        return len([p for p in self.open_or_filtered_ports if p.service and p.service.lower() != "unknown"])

    @property
    def service_groups(self) -> Dict[str, int]:
        """Group count of detected services by category."""
        counts: Dict[str, int] = {}
        for p in self.open_or_filtered_ports:
            cat = p.category or "Unknown"
            counts[cat] = counts.get(cat, 0) + 1
        return counts

    @property
    def exposure_breakdown(self) -> Dict[str, int]:
        """Count of findings by exposure risk rating."""
        counts: Dict[str, int] = {"HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        for p in self.open_or_filtered_ports:
            rating = (p.exposure_rating or "INFO").upper()
            if rating in counts:
                counts[rating] += 1
            else:
                counts["INFO"] += 1
        return counts

    def to_dict(self) -> Dict[str, Any]:
        """Convert host result to a structured dictionary."""
        return {
            "target": self.target,
            "resolved_ip": self.resolved_ip,
            "hostname": self.hostname,
            "host_status": self.host_status,
            "scan_duration": round(self.scan_duration, 2),
            "start_time": self.start_time,
            "end_time": self.end_time,
            "nmap_version": self.nmap_version,
            "total_open_ports": self.total_open_ports,
            "total_findings": self.total_findings,
            "total_services_detected": self.total_services_detected,
            "service_groups": self.service_groups,
            "exposure_breakdown": self.exposure_breakdown,
            "ports": [p.to_dict() for p in self.ports],
            "error_message": self.error_message,
        }

    def to_json(self, indent: int = 2) -> str:
        """Serialize host result to JSON string."""
        return json.dumps(self.to_dict(), indent=indent)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "HostResult":
        """Reconstruct HostResult from a dictionary."""
        ports = [PortInfo.from_dict(p) for p in data.get("ports", [])]
        return cls(
            target=data.get("target", ""),
            resolved_ip=data.get("resolved_ip", ""),
            hostname=data.get("hostname", ""),
            host_status=data.get("host_status", "down"),
            scan_duration=float(data.get("scan_duration", 0.0)),
            ports=ports,
            start_time=data.get("start_time", ""),
            end_time=data.get("end_time", ""),
            nmap_version=data.get("nmap_version", ""),
            error_message=data.get("error_message"),
        )


@dataclass
class ScanResult:
    """Unified container for full reconnaissance scans (single host or CIDR range)."""
    target: str
    target_type: str = "single"  # 'single' or 'cidr'
    scan_type: str = "tcp"        # 'tcp', 'udp', 'both'
    resolved_ip: str = ""
    scan_id: Optional[int] = None
    hosts: List[HostResult] = field(default_factory=list)
    host_status: str = "up"
    scan_duration: float = 0.0
    start_time: str = ""
    end_time: str = ""
    nmap_version: str = ""
    nse_profile: Optional[str] = None
    error_message: Optional[str] = None

    @property
    def total_hosts_scanned(self) -> int:
        """Total number of targets evaluated in this scan."""
        return len(self.hosts)

    @property
    def live_hosts(self) -> List[HostResult]:
        """List of hosts that were discovered UP."""
        return [h for h in self.hosts if h.host_status.lower() == "up"]

    @property
    def total_hosts_discovered(self) -> int:
        """Count of live hosts discovered."""
        return len(self.live_hosts)

    @property
    def hosts_with_open_ports(self) -> List[HostResult]:
        """List of live hosts having one or more open or open|filtered ports."""
        return [h for h in self.live_hosts if len(h.open_or_filtered_ports) > 0]

    @property
    def total_hosts_with_open_ports(self) -> int:
        """Count of hosts with open ports."""
        return len(self.hosts_with_open_ports)

    @property
    def all_ports(self) -> List[PortInfo]:
        """Aggregated list of all ports across all hosts."""
        all_p = []
        for h in self.hosts:
            all_p.extend(h.ports)
        return all_p

    @property
    def all_open_ports(self) -> List[PortInfo]:
        """Aggregated list of open/active ports across all hosts."""
        all_p = []
        for h in self.live_hosts:
            all_p.extend(h.open_or_filtered_ports)
        return all_p

    @property
    def total_open_ports(self) -> int:
        """Total count of open ports across all hosts."""
        return sum(h.total_open_ports for h in self.live_hosts)

    @property
    def total_tcp_open_ports(self) -> int:
        """Total count of open TCP ports across all hosts."""
        return sum(len(h.tcp_open_ports) for h in self.live_hosts)

    @property
    def total_udp_findings(self) -> int:
        """Total count of UDP findings across all hosts."""
        return sum(len(h.udp_findings) for h in self.live_hosts)

    @property
    def total_services_detected(self) -> int:
        """Total count of identified services across all hosts."""
        return sum(h.total_services_detected for h in self.live_hosts)

    @property
    def service_groups(self) -> Dict[str, int]:
        """Aggregated service groups across all live hosts."""
        counts: Dict[str, int] = {}
        for h in self.live_hosts:
            for cat, count in h.service_groups.items():
                counts[cat] = counts.get(cat, 0) + count
        return counts

    @property
    def exposure_breakdown(self) -> Dict[str, int]:
        """Aggregated exposure ratings across all live hosts."""
        counts: Dict[str, int] = {"HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        for h in self.live_hosts:
            for rating, count in h.exposure_breakdown.items():
                counts[rating] = counts.get(rating, 0) + count
        return counts

    def to_dict(self) -> Dict[str, Any]:
        """Convert ScanResult to structured dictionary."""
        # For single target backward compatibility, also expose root port stats
        primary_host = self.hosts[0] if self.hosts else None
        return {
            "scan_id": self.scan_id,
            "target": self.target,
            "target_type": self.target_type,
            "scan_type": self.scan_type,
            "resolved_ip": self.resolved_ip or (primary_host.resolved_ip if primary_host else ""),
            "host_status": self.host_status if self.target_type == "single" else ("up" if self.total_hosts_discovered > 0 else "down"),
            "scan_duration": round(self.scan_duration, 2),
            "start_time": self.start_time,
            "end_time": self.end_time,
            "nmap_version": self.nmap_version,
            "nse_profile": self.nse_profile,
            "total_hosts_scanned": self.total_hosts_scanned,
            "total_hosts_discovered": self.total_hosts_discovered,
            "total_hosts_with_open_ports": self.total_hosts_with_open_ports,
            "total_open_ports": self.total_open_ports,
            "total_tcp_open_ports": self.total_tcp_open_ports,
            "total_udp_findings": self.total_udp_findings,
            "total_services_detected": self.total_services_detected,
            "service_groups": self.service_groups,
            "exposure_breakdown": self.exposure_breakdown,
            "hosts": [h.to_dict() for h in self.hosts],
            # If single host, mirror the ports directly for 100% Phase 1 JSON report compatibility
            "ports": [p.to_dict() for p in (primary_host.ports if primary_host else [])],
            "error_message": self.error_message,
        }

    def to_json(self, indent: int = 2) -> str:
        """Serialize ScanResult to JSON string."""
        return json.dumps(self.to_dict(), indent=indent)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ScanResult":
        """Reconstruct ScanResult from a dictionary."""
        hosts_data = data.get("hosts", [])
        if hosts_data:
            hosts = [HostResult.from_dict(h) for h in hosts_data]
        elif "ports" in data:
            # Single host format fallback
            host = HostResult.from_dict(data)
            hosts = [host]
        else:
            hosts = []

        return cls(
            target=data.get("target", ""),
            target_type=data.get("target_type", "cidr" if "/" in data.get("target", "") else "single"),
            scan_type=data.get("scan_type", "tcp"),
            resolved_ip=data.get("resolved_ip", ""),
            scan_id=data.get("scan_id"),
            hosts=hosts,
            host_status=data.get("host_status", "up"),
            scan_duration=float(data.get("scan_duration", 0.0)),
            start_time=data.get("start_time", ""),
            end_time=data.get("end_time", ""),
            nmap_version=data.get("nmap_version", ""),
            nse_profile=data.get("nse_profile"),
            error_message=data.get("error_message"),
        )
