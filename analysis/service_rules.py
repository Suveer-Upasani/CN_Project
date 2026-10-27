"""Service exposure evaluation rules and risk ratings for PortSentinel.

Important: An open port or service is NOT automatically a vulnerability.
This module classifies exposure level (INFO, LOW, MEDIUM, HIGH) and provides
transparent, rule-based rationale for operational risk awareness.
"""

from typing import Dict, Any, Optional

# Default rule definitions for service exposure evaluation
SERVICE_EXPOSURE_RULES: Dict[str, Dict[str, Any]] = {
    # High Exposure (Cleartext admin, unauthenticated data stores, exposed legacy services)
    "telnet": {
        "rating": "HIGH",
        "reason": "Legacy cleartext remote administration protocol exposed without transport encryption.",
        "category": "Remote Access",
    },
    "rlogin": {
        "rating": "HIGH",
        "reason": "Legacy BSD remote login protocol exposed without strong authentication or encryption.",
        "category": "Remote Access",
    },
    "rsh": {
        "rating": "HIGH",
        "reason": "Legacy remote shell protocol with IP-based trust model exposed.",
        "category": "Remote Access",
    },
    "rexec": {
        "rating": "HIGH",
        "reason": "Legacy remote execution protocol sending credentials in cleartext.",
        "category": "Remote Access",
    },
    "ftp": {
        "rating": "HIGH",
        "reason": "Unencrypted file transfer service exposed; credentials and payloads transmitted in plaintext.",
        "category": "File Sharing",
    },
    "tftp": {
        "rating": "HIGH",
        "reason": "Trivial File Transfer Protocol exposed without authentication mechanism.",
        "category": "File Sharing",
    },
    "smb": {
        "rating": "HIGH",
        "reason": "Server Message Block (SMB) file sharing exposed; potential risk for network lateral movement.",
        "category": "File Sharing",
    },
    "microsoft-ds": {
        "rating": "HIGH",
        "reason": "Direct SMB file sharing port 445 exposed to network.",
        "category": "File Sharing",
    },
    "netbios-ssn": {
        "rating": "HIGH",
        "reason": "NetBIOS Session Service exposed to network.",
        "category": "File Sharing",
    },
    "redis": {
        "rating": "HIGH",
        "reason": "In-memory key-value database exposed; often configured without authentication by default.",
        "category": "Database",
    },
    "memcached": {
        "rating": "HIGH",
        "reason": "Memcached caching server exposed without default access controls.",
        "category": "Database",
    },
    "elasticsearch": {
        "rating": "HIGH",
        "reason": "Elasticsearch REST API exposed; verify cluster security and authentication policies.",
        "category": "Database",
    },
    "mongodb": {
        "rating": "HIGH",
        "reason": "MongoDB database engine exposed to network.",
        "category": "Database",
    },

    # Medium Exposure (Remote administrative services, SQL databases, directory services)
    "ssh": {
        "rating": "MEDIUM",
        "reason": "Secure remote administration shell exposed; ensure strong public key authentication is enforced.",
        "category": "Remote Access",
    },
    "rdp": {
        "rating": "MEDIUM",
        "reason": "Remote Desktop Protocol (RDP) exposed; verify Network Level Authentication (NLA) is enabled.",
        "category": "Remote Access",
    },
    "ms-wbt-server": {
        "rating": "MEDIUM",
        "reason": "Windows Remote Desktop service exposed on standard port.",
        "category": "Remote Access",
    },
    "vnc": {
        "rating": "MEDIUM",
        "reason": "Virtual Network Computing (VNC) remote graphical desktop service exposed.",
        "category": "Remote Access",
    },
    "winrm": {
        "rating": "MEDIUM",
        "reason": "Windows Remote Management (WinRM) HTTP/HTTPS service exposed.",
        "category": "Remote Access",
    },
    "mysql": {
        "rating": "MEDIUM",
        "reason": "MySQL relational database listening on network interface; verify access restriction rules.",
        "category": "Database",
    },
    "mariadb": {
        "rating": "MEDIUM",
        "reason": "MariaDB database engine exposed; ensure external network access is restricted.",
        "category": "Database",
    },
    "postgresql": {
        "rating": "MEDIUM",
        "reason": "PostgreSQL database engine exposed to network connections.",
        "category": "Database",
    },
    "postgres": {
        "rating": "MEDIUM",
        "reason": "PostgreSQL database engine exposed to network connections.",
        "category": "Database",
    },
    "oracle": {
        "rating": "MEDIUM",
        "reason": "Oracle TNS database listener exposed to network.",
        "category": "Database",
    },
    "ms-sql-s": {
        "rating": "MEDIUM",
        "reason": "Microsoft SQL Server listening on network.",
        "category": "Database",
    },
    "ldap": {
        "rating": "MEDIUM",
        "reason": "Lightweight Directory Access Protocol exposed; ensure StartTLS or LDAPS is required.",
        "category": "Directory / Identity",
    },
    "snmp": {
        "rating": "MEDIUM",
        "reason": "Simple Network Management Protocol (SNMP) exposed; verify community strings or v3 encryption.",
        "category": "Network / Infrastructure",
    },

    # Low Exposure (Standard Web services, encrypted protocols)
    "http": {
        "rating": "LOW",
        "reason": "Standard HTTP web service exposed in unencrypted mode; recommended to redirect to HTTPS.",
        "category": "Web",
    },
    "http-alt": {
        "rating": "LOW",
        "reason": "Alternate HTTP web server or proxy port exposed.",
        "category": "Web",
    },
    "http-proxy": {
        "rating": "LOW",
        "reason": "HTTP proxy service exposed.",
        "category": "Web",
    },
    "smtp": {
        "rating": "LOW",
        "reason": "Mail transfer service (SMTP) exposed; verify open-relay protections.",
        "category": "Mail",
    },
    "pop3": {
        "rating": "LOW",
        "reason": "POP3 email retrieval service exposed.",
        "category": "Mail",
    },
    "imap": {
        "rating": "LOW",
        "reason": "IMAP email access service exposed.",
        "category": "Mail",
    },
    "dns": {
        "rating": "LOW",
        "reason": "Domain Name System (DNS) server exposed; verify recursion controls.",
        "category": "Network / Infrastructure",
    },
    "domain": {
        "rating": "LOW",
        "reason": "DNS resolution service listening on port.",
        "category": "Network / Infrastructure",
    },

    # Informational (Standard encrypted Web, infrastructure)
    "https": {
        "rating": "INFO",
        "reason": "Standard encrypted HTTPS web service exposed.",
        "category": "Web",
    },
    "https-alt": {
        "rating": "INFO",
        "reason": "Alternate HTTPS web server port exposed.",
        "category": "Web",
    },
    "ftps": {
        "rating": "INFO",
        "reason": "FTP over TLS secure file transfer service.",
        "category": "File Sharing",
    },
    "ldaps": {
        "rating": "INFO",
        "reason": "LDAP over TLS directory service.",
        "category": "Directory / Identity",
    },
    "ntp": {
        "rating": "INFO",
        "reason": "Network Time Protocol synchronization service.",
        "category": "Network / Infrastructure",
    },
    "dhcp": {
        "rating": "INFO",
        "reason": "Dynamic Host Configuration Protocol service.",
        "category": "Network / Infrastructure",
    },
}

# Port number based fallback rules when service name is unknown
PORT_FALLBACK_RULES: Dict[int, Dict[str, Any]] = {
    21: {"rating": "HIGH", "reason": "Standard FTP port exposed (potential cleartext file transfer)."},
    23: {"rating": "HIGH", "reason": "Standard Telnet port exposed (unencrypted remote access)."},
    445: {"rating": "HIGH", "reason": "SMB / Microsoft-DS port 445 exposed to network."},
    3389: {"rating": "MEDIUM", "reason": "Standard RDP port 3389 exposed."},
    22: {"rating": "MEDIUM", "reason": "Standard SSH port 22 exposed."},
    3306: {"rating": "MEDIUM", "reason": "Standard MySQL port 3306 exposed."},
    5432: {"rating": "MEDIUM", "reason": "Standard PostgreSQL port 5432 exposed."},
    6379: {"rating": "HIGH", "reason": "Standard Redis port 6379 exposed."},
    27017: {"rating": "HIGH", "reason": "Standard MongoDB port 27017 exposed."},
    9200: {"rating": "HIGH", "reason": "Standard Elasticsearch port 9200 exposed."},
    80: {"rating": "LOW", "reason": "Standard HTTP web port 80 exposed."},
    443: {"rating": "INFO", "reason": "Standard HTTPS secure web port 443 exposed."},
    53: {"rating": "LOW", "reason": "Standard DNS port 53 exposed."},
    123: {"rating": "INFO", "reason": "Standard NTP port 123 exposed."},
    161: {"rating": "MEDIUM", "reason": "Standard SNMP port 161 exposed."},
}
