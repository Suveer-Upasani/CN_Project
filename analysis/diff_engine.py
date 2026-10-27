"""Historical scan comparison and diff engine for PortSentinel.

Identifies changes between past and present scans:
- New open ports
- Closed ports
- Service transitions (e.g. Apache -> nginx)
- Version changes (e.g. OpenSSH 8.9 -> OpenSSH 9.0)
- State changes (e.g. filtered -> open)
- New / missing hosts in CIDR ranges
"""

from dataclasses import dataclass, field, asdict
from typing import List, Dict, Any, Optional, Tuple, Union
from models.scan_result import PortInfo, HostResult, ScanResult


@dataclass
class PortChange:
    """Represents a specific port-level change."""
    port: int
    protocol: str
    change_type: str  # 'new', 'closed', 'service_change', 'version_change', 'state_change'
    service: str = "unknown"
    previous_value: Optional[str] = None
    current_value: Optional[str] = None
    exposure_rating: str = "INFO"
    category: str = "Unknown"

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ScanDiff:
    """Structured result of comparing two scans."""
    target: str
    previous_scan_id: Optional[int] = None
    previous_timestamp: str = ""
    current_scan_id: Optional[int] = None
    current_timestamp: str = ""
    new_ports: List[PortChange] = field(default_factory=list)
    closed_ports: List[PortChange] = field(default_factory=list)
    service_changes: List[PortChange] = field(default_factory=list)
    version_changes: List[PortChange] = field(default_factory=list)
    state_changes: List[PortChange] = field(default_factory=list)
    new_hosts: List[str] = field(default_factory=list)
    missing_hosts: List[str] = field(default_factory=list)

    @property
    def has_changes(self) -> bool:
        """True if any changes were detected between the two scans."""
        return any([
            self.new_ports,
            self.closed_ports,
            self.service_changes,
            self.version_changes,
            self.state_changes,
            self.new_hosts,
            self.missing_hosts,
        ])

    @property
    def total_changes_count(self) -> int:
        """Total count of individual changes detected."""
        return (
            len(self.new_ports)
            + len(self.closed_ports)
            + len(self.service_changes)
            + len(self.version_changes)
            + len(self.state_changes)
            + len(self.new_hosts)
            + len(self.missing_hosts)
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target": self.target,
            "previous_scan_id": self.previous_scan_id,
            "previous_timestamp": self.previous_timestamp,
            "current_scan_id": self.current_scan_id,
            "current_timestamp": self.current_timestamp,
            "has_changes": self.has_changes,
            "total_changes": self.total_changes_count,
            "new_ports": [p.to_dict() for p in self.new_ports],
            "closed_ports": [p.to_dict() for p in self.closed_ports],
            "service_changes": [p.to_dict() for p in self.service_changes],
            "version_changes": [p.to_dict() for p in self.version_changes],
            "state_changes": [p.to_dict() for p in self.state_changes],
            "new_hosts": self.new_hosts,
            "missing_hosts": self.missing_hosts,
        }


class DiffEngine:
    """Compares historical and current scan results to detect infrastructure evolution."""

    def compare_hosts(self, prev_host: HostResult, curr_host: HostResult) -> ScanDiff:
        """Compare two HostResult objects for the same host."""
        diff = ScanDiff(
            target=curr_host.target or prev_host.target,
            previous_timestamp=prev_host.start_time,
            current_timestamp=curr_host.start_time,
        )

        prev_port_map: Dict[Tuple[int, str], PortInfo] = {
            (p.port, p.protocol.lower()): p for p in prev_host.ports
        }
        curr_port_map: Dict[Tuple[int, str], PortInfo] = {
            (p.port, p.protocol.lower()): p for p in curr_host.ports
        }

        # Active ports set (open or open|filtered)
        prev_active = {k: p for k, p in prev_port_map.items() if p.state.lower() in ("open", "open|filtered")}
        curr_active = {k: p for k, p in curr_port_map.items() if p.state.lower() in ("open", "open|filtered")}

        # 1. Detect New Ports
        for key, p in curr_active.items():
            if key not in prev_active:
                diff.new_ports.append(
                    PortChange(
                        port=p.port,
                        protocol=p.protocol,
                        change_type="new",
                        service=p.service,
                        current_value=f"{p.service} ({p.product} {p.version})".strip(),
                        exposure_rating=p.exposure_rating,
                        category=p.category,
                    )
                )

        # 2. Detect Closed Ports
        for key, p in prev_active.items():
            if key not in curr_active:
                curr_p = curr_port_map.get(key)
                curr_state = curr_p.state if curr_p else "closed/unresponsive"
                diff.closed_ports.append(
                    PortChange(
                        port=p.port,
                        protocol=p.protocol,
                        change_type="closed",
                        service=p.service,
                        previous_value=f"{p.service} ({p.product} {p.version})".strip(),
                        current_value=curr_state,
                        category=p.category,
                    )
                )

        # 3. Detect Service, Version, and State changes for mutual active ports
        mutual_keys = set(prev_active.keys()) & set(curr_active.keys())
        for key in mutual_keys:
            prev_p = prev_active[key]
            curr_p = curr_active[key]

            # Service name change
            if prev_p.service.lower() != curr_p.service.lower() and "unknown" not in (prev_p.service.lower(), curr_p.service.lower()):
                diff.service_changes.append(
                    PortChange(
                        port=curr_p.port,
                        protocol=curr_p.protocol,
                        change_type="service_change",
                        service=curr_p.service,
                        previous_value=prev_p.service,
                        current_value=curr_p.service,
                        exposure_rating=curr_p.exposure_rating,
                        category=curr_p.category,
                    )
                )

            # Version/Product change
            prev_ver = f"{prev_p.product} {prev_p.version}".replace("Not detected", "").strip()
            curr_ver = f"{curr_p.product} {curr_p.version}".replace("Not detected", "").strip()
            if prev_ver and curr_ver and prev_ver != curr_ver:
                diff.version_changes.append(
                    PortChange(
                        port=curr_p.port,
                        protocol=curr_p.protocol,
                        change_type="version_change",
                        service=curr_p.service,
                        previous_value=prev_ver,
                        current_value=curr_ver,
                        exposure_rating=curr_p.exposure_rating,
                        category=curr_p.category,
                    )
                )

            # State change (e.g. open|filtered to open)
            if prev_p.state.lower() != curr_p.state.lower():
                diff.state_changes.append(
                    PortChange(
                        port=curr_p.port,
                        protocol=curr_p.protocol,
                        change_type="state_change",
                        service=curr_p.service,
                        previous_value=prev_p.state,
                        current_value=curr_p.state,
                        exposure_rating=curr_p.exposure_rating,
                        category=curr_p.category,
                    )
                )

        return diff

    def compare_scans(self, prev_scan: ScanResult, curr_scan: ScanResult) -> ScanDiff:
        """Compare two complete ScanResult objects."""
        diff = ScanDiff(
            target=curr_scan.target,
            previous_scan_id=prev_scan.scan_id,
            previous_timestamp=prev_scan.start_time,
            current_scan_id=curr_scan.scan_id,
            current_timestamp=curr_scan.start_time,
        )

        prev_host_map = {h.resolved_ip or h.target: h for h in prev_scan.live_hosts}
        curr_host_map = {h.resolved_ip or h.target: h for h in curr_scan.live_hosts}

        # CIDR Host discovery changes
        if curr_scan.target_type == "cidr" or prev_scan.target_type == "cidr":
            for ip in curr_host_map:
                if ip not in prev_host_map:
                    diff.new_hosts.append(ip)
            for ip in prev_host_map:
                if ip not in curr_host_map:
                    diff.missing_hosts.append(ip)

        # Single target fast path or combined target evaluation
        if curr_scan.target_type == "single" and prev_scan.target_type == "single":
            p_host = prev_scan.hosts[0] if prev_scan.hosts else HostResult(target=prev_scan.target, resolved_ip=prev_scan.resolved_ip)
            c_host = curr_scan.hosts[0] if curr_scan.hosts else HostResult(target=curr_scan.target, resolved_ip=curr_scan.resolved_ip)
            host_diff = self.compare_hosts(p_host, c_host)
            host_diff.previous_scan_id = prev_scan.scan_id
            host_diff.current_scan_id = curr_scan.scan_id
            return host_diff

        # Aggregate port changes across mutual live hosts
        mutual_ips = set(prev_host_map.keys()) & set(curr_host_map.keys())
        for ip in mutual_ips:
            h_diff = self.compare_hosts(prev_host_map[ip], curr_host_map[ip])
            diff.new_ports.extend(h_diff.new_ports)
            diff.closed_ports.extend(h_diff.closed_ports)
            diff.service_changes.extend(h_diff.service_changes)
            diff.version_changes.extend(h_diff.version_changes)
            diff.state_changes.extend(h_diff.state_changes)

        return diff

    def format_diff_text(self, diff: ScanDiff) -> str:
        """Render a clean CLI representation of scan differences."""
        lines = [
            "═" * 60,
            f"{'SCAN COMPARISON':^60}",
            "═" * 60,
            f"Target          : {diff.target}",
            f"Previous scan   : {diff.previous_timestamp or 'N/A'}" + (f" (ID #{diff.previous_scan_id})" if diff.previous_scan_id else ""),
            f"Current scan    : {diff.current_timestamp or 'N/A'}" + (f" (ID #{diff.current_scan_id})" if diff.current_scan_id else ""),
            "─" * 60,
        ]

        if not diff.has_changes:
            lines.append("No changes detected since previous scan.")
            lines.append("═" * 60)
            return "\n".join(lines)

        if diff.new_hosts:
            lines.append("NEW HOSTS DISCOVERED")
            lines.append("─" * 30)
            for h in diff.new_hosts:
                lines.append(f"  • {h}")
            lines.append("")

        if diff.missing_hosts:
            lines.append("HOSTS NO LONGER REACHABLE")
            lines.append("─" * 30)
            for h in diff.missing_hosts:
                lines.append(f"  • {h}")
            lines.append("")

        if diff.new_ports:
            lines.append("NEW PORTS")
            lines.append("─" * 30)
            for p in diff.new_ports:
                lines.append(f"  • {p.port}/{p.protocol:<4}  {p.service.upper():<12} [Exposure: {p.exposure_rating}]")
            lines.append("")

        if diff.closed_ports:
            lines.append("CLOSED SINCE PREVIOUS SCAN")
            lines.append("─" * 30)
            for p in diff.closed_ports:
                lines.append(f"  • {p.port}/{p.protocol:<4}  {p.service.upper()}")
            lines.append("")

        if diff.service_changes:
            lines.append("SERVICE CHANGES")
            lines.append("─" * 30)
            for p in diff.service_changes:
                lines.append(f"  • {p.port}/{p.protocol:<4}  {p.previous_value} → {p.current_value}")
            lines.append("")

        if diff.version_changes:
            lines.append("VERSION CHANGES")
            lines.append("─" * 30)
            for p in diff.version_changes:
                lines.append(f"  • {p.port}/{p.protocol:<4}  {p.previous_value} → {p.current_value}")
            lines.append("")

        if diff.state_changes:
            lines.append("STATE CHANGES")
            lines.append("─" * 30)
            for p in diff.state_changes:
                lines.append(f"  • {p.port}/{p.protocol:<4}  {p.previous_value.upper()} → {p.current_value.upper()}")
            lines.append("")

        lines.append("═" * 60)
        return "\n".join(lines)
