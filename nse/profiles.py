"""NSE Script profiles for safe reconnaissance and information gathering."""

from typing import Dict, List, Any

# Safe NSE profiles. Destructive, brute-force, DoS, and exploit scripts are strictly disallowed.
NSE_PROFILES: Dict[str, Dict[str, Any]] = {
    "none": {
        "name": "None",
        "description": "No additional NSE scripts (standard service detection only).",
        "scripts": [],
    },
    "basic": {
        "name": "Basic",
        "description": "Minimal banner grabbing and standard service identity verification.",
        "scripts": ["banner"],
    },
    "service-info": {
        "name": "Service Information",
        "description": "Safe enumeration of HTTP titles, TLS/SSL certificates, and SSH algorithms.",
        "scripts": [
            "banner",
            "http-title",
            "http-server-header",
            "ssl-cert",
            "ssh2-enum-algos",
            "dns-nsid",
        ],
    },
    "safe": {
        "name": "Safe",
        "description": "Standard Nmap 'safe' category (non-intrusive, safe discovery scripts).",
        "scripts": ["safe"],
    },
}
