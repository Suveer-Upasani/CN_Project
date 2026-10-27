"""Target validation and DNS resolution utilities for PortSentinel."""

import ipaddress
import re
import socket
from dataclasses import dataclass
from typing import Optional


@dataclass
class ValidationResult:
    """Result of validating and resolving a target."""
    is_valid: bool
    target: str
    resolved_ip: Optional[str] = None
    is_ip: bool = False
    is_cidr: bool = False
    network_str: Optional[str] = None
    total_hosts: int = 1
    error_message: Optional[str] = None


# Basic regex for valid hostname syntax (RFC 1123)
HOSTNAME_REGEX = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.[A-Za-z0-9-]{1,63})*\.?$"
)

# Reject unsafe shell or illegal characters (excluding / for CIDR notation)
DISALLOWED_CHARS = re.compile(r"[\s;`&|$<>!^%*()\"'\[\]{}]")


def validate_target(raw_target: str) -> ValidationResult:
    """Validate target syntax and resolve hostname to IP address or validate CIDR range.

    Args:
        raw_target: User-provided IP address, CIDR range, or hostname string.

    Returns:
        ValidationResult containing validation status, resolved IP / network, or error message.
    """
    if not raw_target or not isinstance(raw_target, str):
        return ValidationResult(
            is_valid=False,
            target="",
            error_message="Target cannot be empty. Please enter a valid IP address, CIDR range, or hostname.",
        )

    target = raw_target.strip()

    if not target:
        return ValidationResult(
            is_valid=False,
            target="",
            error_message="Target cannot be empty. Please enter a valid IP address, CIDR range, or hostname.",
        )

    if DISALLOWED_CHARS.search(target):
        return ValidationResult(
            is_valid=False,
            target=target,
            error_message="Target contains invalid characters or whitespace.",
        )

    # 1. Check if it is a CIDR network range (e.g. 192.168.1.0/24)
    if "/" in target:
        try:
            net_obj = ipaddress.ip_network(target, strict=False)
            if net_obj.version != 4:
                return ValidationResult(
                    is_valid=False,
                    target=target,
                    error_message=f"IPv6 network ranges are not currently supported: '{target}'.",
                )
            # Usable host count calculation
            usable_hosts = net_obj.num_addresses - 2 if net_obj.prefixlen < 31 else net_obj.num_addresses
            return ValidationResult(
                is_valid=True,
                target=target,
                resolved_ip=str(net_obj.network_address),
                is_ip=False,
                is_cidr=True,
                network_str=str(net_obj),
                total_hosts=max(1, usable_hosts),
            )
        except ValueError as exc:
            return ValidationResult(
                is_valid=False,
                target=target,
                error_message=f"Invalid network range format: '{target}'. Expected format e.g. 192.168.1.0/24 ({exc})",
            )

    # 2. Check if it looks like a 4-part numeric IP address
    parts = target.split(".")
    if len(parts) == 4 and all(p.isdigit() for p in parts):
        try:
            ip_obj = ipaddress.ip_address(target)
            return ValidationResult(
                is_valid=True,
                target=target,
                resolved_ip=str(ip_obj),
                is_ip=True,
                is_cidr=False,
                total_hosts=1,
            )
        except ValueError:
            return ValidationResult(
                is_valid=False,
                target=target,
                error_message=f"Invalid IPv4 address format: '{target}' (octets must be 0-255).",
            )

    # Check if it's another valid IP format (e.g. IPv6)
    try:
        ip_obj = ipaddress.ip_address(target)
        return ValidationResult(
            is_valid=True,
            target=target,
            resolved_ip=str(ip_obj),
            is_ip=True,
            is_cidr=False,
            total_hosts=1,
        )
    except ValueError:
        pass  # Not an IP, proceed to hostname check

    # 3. Check if hostname syntax is valid
    if not HOSTNAME_REGEX.match(target):
        return ValidationResult(
            is_valid=False,
            target=target,
            error_message=f"Invalid target format: '{target}'. Please enter a valid IP address, CIDR range, or hostname.",
        )

    # 4. Attempt DNS resolution
    try:
        addr_info = socket.getaddrinfo(target, None, socket.AF_INET, socket.SOCK_STREAM)
        if not addr_info:
            return ValidationResult(
                is_valid=False,
                target=target,
                error_message=f"Unable to resolve hostname '{target}'. No IPv4 address found.",
            )
        resolved_ip = addr_info[0][4][0]
        return ValidationResult(
            is_valid=True,
            target=target,
            resolved_ip=resolved_ip,
            is_ip=False,
            is_cidr=False,
            total_hosts=1,
        )
    except (socket.gaierror, socket.herror, socket.timeout) as exc:
        return ValidationResult(
            is_valid=False,
            target=target,
            error_message=f"Unable to resolve target '{target}': {exc}",
        )
    except Exception as exc:
        return ValidationResult(
            is_valid=False,
            target=target,
            error_message=f"DNS resolution error for '{target}': {str(exc)}",
        )
