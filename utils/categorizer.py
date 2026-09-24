"""Network service categorization mapping for PortSentinel.

Groups services (SSH, HTTP, MySQL, SMB, etc.) into functional operational categories
for the exposure summary and reporting.
"""

from typing import Dict, Set

# Mapping of standard service names / keywords to categories
SERVICE_CATEGORY_MAP: Dict[str, Set[str]] = {
    "Remote Access": {
        "ssh", "telnet", "rdp", "ms-wbt-server", "vnc", "vnc-http", "winrm",
        "pcanywhere", "teamviewer", "anydesk", "x11", "rlogin", "rsh", "rexec",
    },
    "Web": {
        "http", "https", "http-alt", "http-proxy", "https-alt", "apache", "nginx",
        "lighttpd", "tomcat", "caddy", "jetty", "squid-http", "http-mgmt",
    },
    "Database": {
        "mysql", "mariadb", "postgresql", "postgres", "oracle", "oracle-tns",
        "ms-sql-s", "ms-sql-m", "mssql", "mongodb", "redis", "memcached",
        "elasticsearch", "couchdb", "cassandra", "influxdb", "neo4j",
    },
    "File Sharing": {
        "ftp", "ftps", "ftp-data", "sftp", "tftp", "smb", "microsoft-ds",
        "netbios-ssn", "nfs", "samba", "afp", "rsync", "iscsi",
    },
    "Mail": {
        "smtp", "smtps", "submission", "pop3", "pop3s", "imap", "imaps",
    },
    "Directory / Identity": {
        "ldap", "ldaps", "kerberos", "kerberos-sec", "kpasswd", "ms-directory-services",
    },
    "Network / Infrastructure": {
        "dns", "domain", "ntp", "snmp", "snmptrap", "dhcp", "dhcps", "radius",
        "syslog", "bgp", "rip", "ospf", "upnp", "stun",
    },
    "DevOps / Container": {
        "docker", "kubernetes", "k8s", "etcd", "consul", "vault", "jenkins",
        "gitlab", "prometheus", "grafana",
    },
}


def categorize_service(service_name: str, product_name: str = "") -> str:
    """Categorize a service based on its identified service name or product.

    Args:
        service_name: Nmap identified service string (e.g. 'ssh', 'http', 'mysql').
        product_name: Product details string (e.g. 'OpenSSH', 'Apache httpd').

    Returns:
        Categorization string such as 'Remote Access', 'Web', 'Database', or 'Unknown'.
    """
    svc = (service_name or "").lower().strip()
    prod = (product_name or "").lower().strip()

    if not svc and not prod:
        return "Unknown"

    # Match by service name
    for category, service_set in SERVICE_CATEGORY_MAP.items():
        if svc in service_set:
            return category
        for s in service_set:
            if s in svc or (prod and s in prod):
                return category

    return "Unknown"
