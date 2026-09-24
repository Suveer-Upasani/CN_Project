"""Structured data models representing ports, services, and complete scan results."""

from dataclasses import dataclass, field, asdict
from typing import List, Dict, Any, Optional
import json


@dataclass
class PortInfo:
    """Represents the state, service, and version details of a single network port."""
    port: int
    protocol: str = "tcp"
    state: str = "open"
    service: str = "unknown"
    product: str = "Not detected"
    version: str = "Not detected"
    extra_info: str = ""
    category: str = "Unknown"

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
        }


@dataclass
class HostResult:
    """Represents the full reconnaissance result for a single target."""
    target: str
    resolved_ip: str
    host_status: str = "down"  # 'up' or 'down' / 'unreachable'
    scan_duration: float = 0.0
    ports: List[PortInfo] = field(default_factory=list)
    start_time: str = ""
    end_time: str = ""
    nmap_version: str = ""
    error_message: Optional[str] = None

    @property
    def open_ports(self) -> List[PortInfo]:
        """Return all ports that are in the 'open' state."""
        return [p for p in self.ports if p.state.lower() == "open"]

    @property
    def total_open_ports(self) -> int:
        """Count of open ports."""
        return len(self.open_ports)

    @property
    def total_services_detected(self) -> int:
        """Count of open ports with identified services."""
        return len([p for p in self.open_ports if p.service and p.service.lower() != "unknown"])

    @property
    def service_groups(self) -> Dict[str, int]:
        """Group count of detected services by category."""
        counts: Dict[str, int] = {}
        for p in self.open_ports:
            cat = p.category or "Unknown"
            counts[cat] = counts.get(cat, 0) + 1
        return counts

    def to_dict(self) -> Dict[str, Any]:
        """Convert host result to a structured dictionary."""
        return {
            "target": self.target,
            "resolved_ip": self.resolved_ip,
            "host_status": self.host_status,
            "scan_duration": round(self.scan_duration, 2),
            "start_time": self.start_time,
            "end_time": self.end_time,
            "nmap_version": self.nmap_version,
            "total_open_ports": self.total_open_ports,
            "total_services_detected": self.total_services_detected,
            "service_groups": self.service_groups,
            "ports": [p.to_dict() for p in self.ports],
            "error_message": self.error_message,
        }

    def to_json(self, indent: int = 2) -> str:
        """Serialize host result to JSON string."""
        return json.dumps(self.to_dict(), indent=indent)
