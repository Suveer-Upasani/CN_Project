# PortSentinel (Phase 1)

> **Automated Network Reconnaissance and Open-Port Analysis Engine**

PortSentinel is a modular, Python-based network reconnaissance and security analysis tool designed for **authorized systems, educational cybersecurity labs, and controlled penetration testing environments**. 

Phase 1 automates the sequence of Nmap-based host discovery, open-port discovery, and targeted service/version identification. It parses machine-readable XML results into structured Python models and outputs both clean terminal summaries and persistent text and JSON reports.

---

## Legal & Safety Notice

> **IMPORTANT**: PortSentinel is intended strictly for authorized security testing, educational labs, and systems owned or explicitly authorized by the user. Do **not** scan systems, networks, or digital assets without prior explicit written permission. Unauthorized network scanning may violate local, national, and international laws.
>
> *PortSentinel does NOT attempt exploitation, password cracking, denial-of-service, or unauthorized access. An open port simply indicates a reachable network service, not necessarily an active vulnerability.*

---

## Features (Phase 1)

- **Target Input & Validation**:
  - Validates IPv4 addresses, IPv6 addresses, and hostnames (including `localhost` and internal lab domains).
  - Robust DNS resolution with graceful handling of DNS errors and invalid formats without crashing.
- **Nmap Dependency & Engine Verification**:
  - Auto-locates system Nmap binary across environment PATH and standard system paths (`/opt/homebrew/bin`, `/usr/local/bin`, `/usr/bin`, Windows Program Files).
  - Displays engine version and terminates gracefully if Nmap is absent.
- **Automated Host Discovery**:
  - Verifies whether the target host is reachable (`UP`) or unreachable (`DOWN`) prior to intensive scanning.
- **TCP Port Discovery**:
  - Performs non-intrusive TCP connect scanning (`-sT`) without requiring root/superuser privileges.
  - Extracts open, closed, and filtered states.
- **Targeted Service & Version Detection**:
  - Dynamically runs targeted service detection (`-sV`) only on discovered open ports.
  - Accurately captures service name, product banner, version string, and protocol details without fabricating missing data.
- **Service Categorization**:
  - Groups identified network services into logical functional categories (e.g., *Remote Access*, *Web*, *Database*, *File Sharing*, *Mail*, *Directory / Identity*, *Network / Infrastructure*).
- **Multi-Format Reporting**:
  - **Human-Readable Text Report**: Saved to `output/scan_YYYYMMDD_HHMMSS.txt`.
  - **Structured JSON Report**: Saved to `output/scan_YYYYMMDD_HHMMSS.json` (ready for dashboard ingestion in Phase 2).
- **Persistent Activity Logging**:
  - Detailed execution, command execution parameters, and error tracing recorded in `logs/portsentinel.log`.

---

## Architecture & Reconnaissance Workflow

```text
                    Target (IP / Hostname)
                              │
                              ▼
                      Input Validation
                              │
                              ▼
                       Host Discovery
                              │
                              ▼
                        TCP Port Scan
                              │
                              ▼
                     Open Port Extraction
                              │
                              ▼
                  Service/Version Detection
                              │
                              ▼
                     Nmap XML Result Parsing
                              │
                              ▼
                     Exposure Categorization
                              │
                              ▼
                    Terminal Summary & Reports
                     (output/*.txt, output/*.json)
```

---

## Project Structure

```text
PortSentinel/
│
├── main.py                     # CLI entrypoint and pipeline orchestrator
├── requirements.txt            # Project dependencies and test frameworks
├── README.md                   # Documentation and user guide
├── .gitignore                  # Git ignore rules for logs, reports, and bytecode
│
├── models/                     # Data models
│   ├── __init__.py
│   └── scan_result.py          # PortInfo and HostResult dataclasses
│
├── scanner/                    # Scanning and parsing logic
│   ├── __init__.py
│   ├── nmap_manager.py         # Nmap dependency checking and subprocess manager
│   ├── parser.py               # Machine-readable Nmap XML parser (ElementTree)
│   ├── discovery.py            # Host discovery logic (-sn)
│   ├── port_scanner.py         # TCP port discovery (-sT)
│   └── service_detector.py     # Targeted service/version detection (-sV)
│
├── reports/                    # Report generation
│   ├── __init__.py
│   └── report_generator.py     # Text and JSON report exporter
│
├── utils/                      # Helper utilities
│   ├── __init__.py
│   ├── validator.py            # Target syntax and DNS resolution validator
│   ├── categorizer.py          # Service categorization mapping
│   └── logger.py               # File logging configuration
│
├── output/                     # Generated scan reports (.txt, .json)
│   └── .gitkeep
│
├── logs/                       # Application logs (portsentinel.log)
│   └── .gitkeep
│
└── tests/                      # Unit test suite
    ├── __init__.py
    ├── test_validator.py       # Validation and DNS unit tests
    ├── test_parser.py          # XML parsing and data extraction unit tests
    ├── test_report.py          # Text and JSON report tests
    └── test_categorizer.py     # Service category mapping tests
```

---

## System Requirements

- **Python**: Python 3.8 or newer.
- **Nmap**: Version 7.x or newer installed and accessible.
  - *macOS*: `brew install nmap`
  - *Debian / Ubuntu / Kali*: `sudo apt install nmap`
  - *RHEL / Fedora*: `sudo dnf install nmap`
  - *Windows*: Download from [nmap.org/download](https://nmap.org/download.html) and add to PATH.

---

## Installation

1. **Clone or navigate to the repository**:
   ```bash
   git clone <repository-url>
   cd PortSentinel
   ```

2. **Create and activate a virtual environment**:
   - On macOS/Linux:
     ```bash
     python3 -m venv venv
     source venv/bin/activate
     ```
   - On Windows:
     ```cmd
     python -m venv venv
     venv\Scripts\activate
     ```

3. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

---

## Usage

### 1. Interactive Mode

Run the tool without arguments to enter interactive mode:

```bash
python main.py
```

Prompt:
```text
╔══════════════════════════════════════════════════════════════════╗
║                       PORTSENTINEL v1.0                          ║
║           Automated Port & Service Reconnaissance Engine         ║
║          [ For Authorized Systems & Controlled Lab Tests ]       ║
╚══════════════════════════════════════════════════════════════════╝

Enter target IP/hostname:
> 127.0.0.1
```

### 2. Command-Line Arguments

Run reconnaissance directly against a specific target:

```bash
python main.py --target 192.168.1.10
```

Scan a custom port range:

```bash
python main.py --target 192.168.1.10 --ports 22,80,443,8080
```

Specify a custom output directory:

```bash
python main.py --target 192.168.1.10 --output custom_reports/
```

Enable verbose debug logging to `logs/portsentinel.log`:

```bash
python main.py --target 192.168.1.10 --verbose
```

View all command-line options:

```bash
python main.py --help
```

---

## Example Output

```text
$ python main.py --target 192.168.56.10

╔══════════════════════════════════════════════════════════════════╗
║                       PORTSENTINEL v1.0                          ║
║           Automated Port & Service Reconnaissance Engine         ║
║          [ For Authorized Systems & Controlled Lab Tests ]       ║
╚══════════════════════════════════════════════════════════════════╝


[1/5] Target validation       ✓
      Target:      192.168.56.10
      Resolved IP: 192.168.56.10

[2/5] Nmap availability       ✓
      Nmap Engine: 7.991

[3/5] Host discovery          ✓
      Status: UP ✓

[4/5] Discovering TCP ports   ✓
      Open ports found (3):
        • 22/tcp
        • 80/tcp
        • 443/tcp

[5/5] Detecting services      ✓
      Identified Services:
        • 22/tcp   -> SSH (OpenSSH 8.9p1 Ubuntu)
        • 80/tcp   -> HTTP (Apache httpd 2.4.52)
        • 443/tcp  -> HTTPS (Apache httpd 2.4.52)

════════════════════════════════════════════════════════════
                      EXPOSURE SUMMARY                      
════════════════════════════════════════════════════════════
Target          : 192.168.56.10
Resolved IP     : 192.168.56.10
Host Status     : UP
Scan Duration   : 8.42s
Open TCP Ports  : 3
------------------------------------------------------------
Port/Proto      Service           Category
------------------------------------------------------------
22/tcp          SSH               Remote Access
80/tcp          HTTP              Web
443/tcp         HTTPS             Web
------------------------------------------------------------
Service Groups
------------------------------------------------------------
Remote Access           : 1
Web                     : 2
════════════════════════════════════════════════════════════
Reports Generated:
  [Text Report] -> output/scan_20260924_114854.txt
  [JSON Report] -> output/scan_20260924_114854.json
════════════════════════════════════════════════════════════

Scan completed successfully.
```

---

## Running Unit Tests

Execute the automated test suite without requiring a live network:

```bash
python3 -m unittest discover -s tests -p "test_*.py" -v
```

Or using `pytest`:

```bash
pytest -v
```

---

## Roadmap

### Phase 2 (Planned)
- UDP port scanning support (`-sU`)
- Network CIDR range scanning (e.g. `192.168.1.0/24`)
- Historical scan comparison & diff engine
- Flask web dashboard for visual reconnaissance reporting
- Service exposure risk rating & NSE script integration

### Phase 3 (Planned)
- PCAP packet analysis & Scapy integration
- Network traffic anomaly detection & alerting
- Advanced compliance export (HTML, PDF)

### Phase 4 (Planned)
- Relational database persistence (PostgreSQL / SQLite)
- Multi-user authentication & role-based access
- Automated scheduled reconnaissance runs
