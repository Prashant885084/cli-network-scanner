# CLI Network Scanner + Packet Analyzer

> An educational cybersecurity lab that demonstrates port scanning, process mapping, packet capture, and suspicious-port detection — all running safely on your own machine.

![Python](https://img.shields.io/badge/Python-3.11+-blue)
![Platform](https://img.shields.io/badge/Platform-Linux-green)
![License](https://img.shields.io/badge/License-Educational-orange)

---

## Table of Contents

- [Project Overview](#project-overview)
- [Architecture](#architecture)
- [Requirements](#requirements)
- [Installation](#installation)
- [Usage](#usage)
- [Example Output](#example-output)
- [Understanding Nmap Results](#understanding-nmap-results)
- [Understanding Packet Capture](#understanding-packet-capture)
- [Security Concepts](#security-concepts)
- [Suspicious Port Detection](#suspicious-port-detection)
- [Configuration](#configuration)
- [Testing](#testing)
- [Module Documentation](#module-documentation)
- [How to Demonstrate (Viva Guide)](#how-to-demonstrate-viva-guide)
- [Screenshots for Project Report](#screenshots-for-project-report)
- [Limitations](#limitations)
- [Future Improvements](#future-improvements)

---

## Project Overview

This project is a **complete cybersecurity mini-lab** that automatically:

1. **Starts safe local services** — an HTTP server and a TCP listener on localhost
2. **Detects network information** — hostname, IP address, active interface, gateway
3. **Scans for open ports** — using Nmap with XML output parsing
4. **Maps ports to processes** — using psutil to identify which program owns each port
5. **Captures network packets** — using tshark (Wireshark CLI) on the loopback interface
6. **Generates test traffic** — HTTP requests and TCP connections for analysis
7. **Analyzes captured traffic** — protocol statistics, conversations, TCP behavior
8. **Detects suspicious ports** — rule-based classification (EXPECTED / UNKNOWN / REVIEW)
9. **Generates a JSON report** — structured security assessment

Everything runs on **localhost only** — no external scanning, no offensive features.

---

## Architecture

```
┌─────────────────────────────────────────────────┐
│                   main.py (CLI)                 │
│            argparse: full|lab|scan|...          │
└──────────────────────┬──────────────────────────┘
                       │
       ┌───────────────┼───────────────────┐
       ▼               ▼                   ▼
┌─────────────┐ ┌─────────────┐  ┌────────────────┐
│ lab_server   │ │network_info │  │  utils          │
│ HTTP + TCP   │ │ IP/hostname │  │ config/logging  │
│ (127.0.0.1)  │ │ interface   │  │ dep checks      │
└──────┬───────┘ └─────────────┘  └────────────────┘
       │
       ▼
┌─────────────┐     ┌──────────────────┐
│port_scanner  │────▶│ process_mapper   │
│ Nmap XML     │     │ psutil PID lookup│
└──────┬───────┘     └──────────────────┘
       │
       ▼
┌──────────────┐    ┌────────────────────┐
│packet_capture│───▶│ traffic_generator  │
│ tshark       │    │ HTTP + TCP traffic │
└──────┬───────┘    └────────────────────┘
       │
       ▼
┌──────────────┐    ┌──────────────────┐
│packet_analyzer│──▶│suspicious_ports  │
│ stats/convos │    │ rule-based detect│
└──────┬───────┘    └──────────────────┘
       │
       ▼
┌──────────────────┐
│ report_generator │
│ JSON + terminal  │
└──────────────────┘
```

### Data Flow

```
Local Lab Services → Nmap Port Discovery → psutil Process Mapping
         ↓
   Tshark Capture ← Traffic Generator
         ↓
   Packet Analysis → Detection Engine → JSON Report
```

---

## Requirements

### System Requirements

| Software | Version | Purpose |
|----------|---------|---------|
| Linux    | Any modern distro | Primary OS |
| Python   | 3.11+   | Core runtime |
| Nmap     | 7.0+    | Port scanning |
| Tshark   | 3.0+    | Packet capture |

### Python Libraries

| Library | Purpose |
|---------|---------|
| psutil  | Process-to-port mapping |
| pytest  | Unit testing |

---

## Installation

### Step 1: Install System Dependencies

```bash
# Debian/Ubuntu
sudo apt update
sudo apt install python3 python3-venv python3-pip nmap tshark

# Allow tshark to capture without root (optional but recommended)
sudo usermod -aG wireshark $USER
# Log out and back in for group change to take effect
```

### Step 2: Clone and Setup

```bash
# Navigate to the project
cd cli-network-scanner

# Make scripts executable
chmod +x install.sh run.sh

# Run the installer
./install.sh
```

### Step 3: Activate the Virtual Environment

```bash
source .venv/bin/activate
```

---

## Usage

### Full Autopilot Lab (Recommended)

```bash
python3 src/main.py full
```

This executes the complete workflow: start lab → scan → map → capture → analyze → report.

### Individual Commands

```bash
# Show help
python3 src/main.py --help

# Start lab servers only (Ctrl+C to stop)
python3 src/main.py lab

# Port scan only
python3 src/main.py scan

# Packet capture only
python3 src/main.py capture

# Analyze an existing capture file
python3 src/main.py analyze captures/lab_capture.pcapng
```

### Using the Run Script

```bash
./run.sh full
./run.sh scan
./run.sh --help
```

### Scanning a Private Lab Machine (Authorized Only)

```bash
python3 src/main.py --authorized-target 192.168.1.50 full
```

---

## Example Output

```
====================================================
 CLI NETWORK SCANNER + PACKET ANALYZER
              AUTOPILOT LAB
====================================================

[1/9] Checking dependencies...
----------------------------------------------------
  [+] Python          : 3.11 (OK)
  [+] Nmap            : OK
  [+] Tshark          : OK
  [+] psutil          : OK

[2/9] Starting local lab...
----------------------------------------------------
  [+] HTTP server     : 127.0.0.1:8080
  [+] TCP listener    : 127.0.0.1:9090

[3/9] Detecting network information...
----------------------------------------------------
  [+] Hostname        : my-laptop
  [+] Local IP        : 192.168.1.10
  [+] Loopback        : 127.0.0.1
  [+] Interface       : wlan0
  [+] Gateway         : 192.168.1.1

[4/9] Running Nmap port scan...
----------------------------------------------------
  [*] Target: 127.0.0.1
  [*] Arguments: -sT -sV
  [+] Scan complete — 2 open port(s) found

  PORT       STATE   SERVICE      VERSION
  --------   -----   ---------    ----------
  8080/tcp   open    http-proxy   Python 3.11
  9090/tcp   open    unknown

[5/9] Mapping ports to processes...
----------------------------------------------------
  PORT   PROCESS   PID
  ----   -------   ---
  8080   python3   4512
  9090   python3   4512

[6/9] Capturing packets...
----------------------------------------------------
  [+] Capture started : lo for 15s
  [+] Generating test traffic
  [+] Traffic sent    : 8 success, 0 errors
  [*] Waiting for capture to complete...
  [+] Capture complete: captures/lab_capture.pcapng

[7/9] Analyzing packets...
----------------------------------------------------
  [+] Packets analyzed: 87
  Total packets        : 87
  TCP packets          : 82
  UDP packets          : 5
  HTTP-related packets : 15
  Unique source IPs    : 1
  Unique dest IPs      : 1

  Top conversations:
    127.0.0.1:45678 -> 127.0.0.1:8080  (42 pkts)
    127.0.0.1:45690 -> 127.0.0.1:9090  (18 pkts)

  TCP behavior observed:
    - SYN (connection initiation)
    - SYN-ACK (connection accepted)
    - ACK (acknowledgment)
    - PSH-ACK (data transfer)
    - FIN (connection teardown)

[8/9] Checking suspicious ports...
----------------------------------------------------
  [+] No unexpected high-risk ports detected

  PORT   SERVICE   CLASS       SEVERITY  REASON
  ----   -------   --------    --------  ---------
  8080   http      EXPECTED    info      Lab service
  9090   unknown   EXPECTED    info      Lab service

  [*] IMPORTANT: An open port does NOT prove that a service
      is vulnerable or malicious. Open != Vulnerable != Malicious.

[9/9] Generating report...
----------------------------------------------------
  [+] Report saved    : reports/network_scan_report_20260915_100030.json
  [+] Latest report   : reports/network_scan_report.json

====================================================
                 LAB COMPLETE
====================================================
```

---

## Understanding Nmap Results

### Port States

| State    | Meaning |
|----------|---------|
| **open** | A service is actively listening and accepting connections |
| **closed** | The port is accessible but no service is listening |
| **filtered** | A firewall or filter is blocking access to the port |

### Service Detection

Nmap identifies services by:
1. **Port number** — matching against a database of well-known ports (e.g., 22 = SSH)
2. **Service probes** (`-sV` flag) — sending specific packets and analyzing responses to identify the exact software and version

### Scan Types

| Flag | Type | Description |
|------|------|-------------|
| `-sT` | TCP Connect | Full TCP handshake — reliable, non-stealthy |
| `-sV` | Version Detection | Probes services to determine software version |

This tool uses `-sT -sV` by default — a full, legitimate TCP connection scan.

---

## Understanding Packet Capture

### Protocol Layers

```
Application Layer:  HTTP, DNS, SSH
Transport Layer:    TCP, UDP
Network Layer:      IP (IPv4/IPv6)
Link Layer:         Ethernet, Loopback
```

### Key Fields

| Field | Description |
|-------|-------------|
| **Source IP** | The IP address sending the packet |
| **Destination IP** | The IP address receiving the packet |
| **Source Port** | The sender's port (usually ephemeral, e.g., 45678) |
| **Destination Port** | The receiver's port (usually a known service port, e.g., 8080) |
| **Protocol** | TCP, UDP, etc. |
| **Packet Length** | Size of the packet in bytes |

### TCP Flags (Handshake)

```
Client                          Server
  │                               │
  │─── SYN ──────────────────────▶│   1. Client initiates connection
  │                               │
  │◀── SYN-ACK ──────────────────│   2. Server accepts
  │                               │
  │─── ACK ──────────────────────▶│   3. Connection established
  │                               │
  │─── PSH-ACK (HTTP GET) ──────▶│   4. Client sends data
  │                               │
  │◀── PSH-ACK (HTTP 200) ──────│   5. Server responds
  │                               │
  │─── FIN-ACK ─────────────────▶│   6. Client closes connection
  │                               │
  │◀── FIN-ACK ─────────────────│   7. Server confirms close
  │                               │
```

| Flag | Meaning |
|------|---------|
| **SYN** | Synchronize — initiates a TCP connection |
| **SYN-ACK** | Server acknowledges and accepts the connection |
| **ACK** | Acknowledgment — confirms receipt of data |
| **PSH** | Push — deliver data immediately to the application |
| **FIN** | Finish — gracefully close the connection |
| **RST** | Reset — abruptly terminate the connection |

---

## Security Concepts

### Attack Surface

The **attack surface** is the total number of points where an unauthorized user could try to enter or extract data. Every open port is a potential entry point that increases the attack surface.

### Open Ports

An **open port** means a service is listening. This is normal and necessary — web servers need port 80/443, SSH needs port 22. The key question is: **should** this port be open?

### Services and Process Ownership

Knowing **which process** owns a port helps determine if the service is legitimate. For example:
- Port 8080 owned by `python3` → our lab server (expected)
- Port 4444 owned by `nc` → potentially suspicious (unknown listener)

### Network Traffic Analysis

Capturing and analyzing traffic reveals:
- **Who** is communicating (source/destination IPs)
- **What** protocols are in use (TCP, HTTP, etc.)
- **How** connections behave (handshake patterns)

### Suspicious Port Detection

This tool classifies ports into three categories:

| Category | Meaning |
|----------|---------|
| **EXPECTED** | Part of the authorized lab — no concern |
| **UNKNOWN** | Not in any list — may be a legitimate system service |
| **REVIEW** | On the review list — investigate to confirm authorization |

### False Positives

> **IMPORTANT:** An open port does NOT prove that a service is vulnerable or malicious.

Many ports are open for legitimate reasons:
- SSH (22) — remote administration
- DNS (53) — name resolution
- HTTP (80/443) — web services

The detection engine flags ports for **review**, not as confirmed threats.

---

## Suspicious Port Detection

### How It Works

The detection engine compares discovered open ports against two lists:

1. **Expected Ports** — lab services and known-good ports → `EXPECTED`
2. **Review Ports** — ports that warrant investigation → `REVIEW`
3. Everything else → `UNKNOWN`

### Default Review Ports

| Port | Service | Severity | Why |
|------|---------|----------|-----|
| 23   | Telnet  | High     | Unencrypted protocol — credentials sent in cleartext |
| 445  | SMB     | Medium   | File sharing — common lateral movement vector |
| 3389 | RDP     | Medium   | Remote desktop — verify authorization |
| 5900 | VNC     | Medium   | Remote desktop — verify encryption |
| 6667 | IRC     | High     | Sometimes used by botnets for command-and-control |

### Customization

Edit `config/config.json` to add your own rules:

```json
{
    "detection_rules": {
        "expected_ports": [8080, 9090, 22],
        "review_ports": [23, 445, 3389],
        "severity": {
            "23": "high",
            "445": "medium"
        }
    }
}
```

---

## Configuration

All settings are in `config/config.json`:

```json
{
    "target": "127.0.0.1",
    "lab_ports": {
        "http_port": 8080,
        "tcp_port": 9090
    },
    "scan_arguments": "-sT -sV",
    "capture_duration": 15,
    "capture_interface": "lo",
    "detection_rules": { ... }
}
```

| Setting | Default | Description |
|---------|---------|-------------|
| `target` | `127.0.0.1` | Scan target (localhost only by default) |
| `lab_ports.http_port` | `8080` | HTTP server port |
| `lab_ports.tcp_port` | `9090` | TCP listener port |
| `scan_arguments` | `-sT -sV` | Nmap command-line flags |
| `capture_duration` | `15` | Packet capture duration (seconds) |
| `capture_interface` | `lo` | Network interface for capture |

---

## Testing

### Run All Tests

```bash
# Activate venv first
source .venv/bin/activate

# Run tests
python3 -m pytest tests/ -v
```

### Test Coverage

| Module | Tests |
|--------|-------|
| `network_info` | Hostname detection, IP validation, loopback |
| `port_scanner` | Nmap XML parsing, target validation, formatting |
| `process_mapper` | Connection listing, PID lookup, unknown ports |
| `suspicious_ports` | Classification logic, severity, summary |
| `report_generator` | Schema validation, JSON serialization, file saving |

### End-to-End Test

```bash
# Full workflow test
python3 src/main.py full

# Verify outputs
cat reports/network_scan_report.json | python3 -m json.tool
ls -la captures/lab_capture.pcapng
cat logs/scanner.log
```

---

## Module Documentation

### How Each Module Works

| Module | What It Does | Key Technology |
|--------|-------------|----------------|
| `lab_server.py` | Starts HTTP server and TCP listener as daemon threads bound to 127.0.0.1 | `http.server`, `socket`, `threading` |
| `network_info.py` | Detects hostname, local IP (UDP connect trick), active interface, default gateway | `socket`, `psutil`, `/proc/net/route` |
| `port_scanner.py` | Runs `nmap` via subprocess, parses XML output with ElementTree | `subprocess`, `xml.etree.ElementTree` |
| `process_mapper.py` | Uses `psutil.net_connections()` to map listening ports to PIDs and process names | `psutil` |
| `packet_capture.py` | Manages `tshark` subprocess with configurable duration and BPF filters | `subprocess`, `signal` |
| `traffic_generator.py` | Sends HTTP GET requests and TCP connections to lab services | `urllib.request`, `socket` |
| `packet_analyzer.py` | Reads pcapng via `tshark -T fields`, computes stats, conversations, TCP behavior | `subprocess`, `collections.Counter` |
| `suspicious_ports.py` | Rule-based classification: EXPECTED / UNKNOWN / REVIEW with severity | Config-driven rules |
| `report_generator.py` | Builds JSON report with all data, saves timestamped + latest copies | `json`, `datetime` |
| `main.py` | CLI with argparse subcommands, orchestrates the 9-step workflow | `argparse` |
| `utils.py` | Config loading, dependency checks, logging, terminal output, target validation | Standard library |

### How Nmap Discovers Open Ports

1. Nmap sends a **TCP SYN** packet to each target port
2. If the port is **open**, the service responds with **SYN-ACK**
3. Nmap completes the handshake (**ACK**) — this is a TCP Connect scan (`-sT`)
4. With `-sV`, Nmap sends additional probes to identify the service software
5. Results are output as XML, which we parse with Python's `ElementTree`

### How psutil Maps Ports to Processes

1. `psutil.net_connections(kind='inet')` lists all network sockets
2. We filter for `LISTEN` status (servers waiting for connections)
3. Each connection includes a `pid` — the process ID
4. We look up the process name and command line via `psutil.Process(pid)`
5. If access is denied (non-root), we report this clearly

### How Tshark Captures Packets

1. `tshark -i lo` captures on the loopback interface
2. `-f "port 8080 or port 9090"` filters to lab traffic only
3. `-a duration:15` stops after 15 seconds
4. `-w captures/lab_capture.pcapng` saves the raw capture
5. For analysis, `tshark -r` reads the file with `-T fields` for structured output

### How the Packet Analyzer Interprets Captures

1. Reads packets via `tshark -r -T fields` with specific field selectors
2. Counts protocols (TCP, UDP, HTTP) from `frame.protocols`
3. Tracks unique source/destination IPs
4. Groups packets into conversations by IP:port pairs
5. Analyzes TCP flags to identify handshake and teardown patterns

### How Suspicious Port Detection Works

1. Loads expected and review port lists from `config.json`
2. For each open port, checks: is it expected? Is it on the review list?
3. Assigns classification (EXPECTED / UNKNOWN / REVIEW) and severity
4. Generates a summary with risk assessment
5. **Always** includes the disclaimer: Open ≠ Vulnerable ≠ Malicious

---

## How to Demonstrate (Viva Guide)

### Before the Viva

1. Install the project on your laptop
2. Run `python3 src/main.py full` at least once to verify everything works
3. Have a pre-generated `reports/network_scan_report.json` ready
4. Understand what each step does (see Module Documentation above)

### During the Viva

**Step 1:** Show the project structure
```bash
tree cli-network-scanner/
```

**Step 2:** Explain the architecture (use the diagram in this README)

**Step 3:** Run the tool live
```bash
python3 src/main.py full
```

**Step 4:** Walk through each step of the output:
- "Here we see the lab starting two services on localhost"
- "Nmap found 2 open ports — our lab services"
- "psutil confirmed both ports belong to our Python process"
- "tshark captured N packets of our test traffic"
- "The analyzer shows TCP handshakes — SYN, SYN-ACK, ACK"
- "Both ports classified as EXPECTED — no suspicious findings"

**Step 5:** Show the JSON report
```bash
cat reports/network_scan_report.json | python3 -m json.tool | head -50
```

**Step 6:** Explain key concepts:
- Attack surface and why open ports matter
- TCP three-way handshake
- Why "open port ≠ vulnerability"
- Process ownership for accountability

**Step 7:** Run the unit tests
```bash
python3 -m pytest tests/ -v
```

### Common Viva Questions

| Question | Answer |
|----------|--------|
| "What is a port scan?" | A method to discover which network ports are open and which services are listening |
| "Is port scanning legal?" | Scanning your own systems is legal. Scanning others without permission may violate laws |
| "What does SYN-ACK mean?" | The server acknowledges a connection request and agrees to establish the connection |
| "How does Nmap work?" | It sends crafted packets to target ports and analyzes the responses to determine port states |
| "What is psutil?" | A Python library for system and process monitoring — we use it to map ports to processes |

---

## Screenshots for Project Report

Capture these screenshots for your written report:

1. **Project structure** — `tree cli-network-scanner/`
2. **Installation** — running `./install.sh`
3. **Dependency check** — Step 1/9 output
4. **Lab startup** — Step 2/9 showing HTTP and TCP servers
5. **Network info** — Step 3/9 with hostname and IP
6. **Nmap results** — Step 4/9 port scan table
7. **Process mapping** — Step 5/9 port→process table
8. **Packet capture stats** — Step 7/9 analysis
9. **TCP behavior** — handshake phases from analysis
10. **Suspicious ports** — Step 8/9 classification table
11. **JSON report** — formatted output of the report file
12. **Unit tests** — pytest output showing all tests passing

---

## Limitations

> **An open port alone does not prove that a service is vulnerable or malicious.**

### What This Tool Does NOT Do

- ❌ Does not exploit vulnerabilities
- ❌ Does not steal credentials
- ❌ Does not perform stealth scanning
- ❌ Does not inject packets
- ❌ Does not persist on the system
- ❌ Does not scan public Internet targets
- ❌ Does not capture traffic outside the lab

### Technical Limitations

- Requires root/sudo for some Nmap features (service version detection)
- Tshark may require wireshark group membership for non-root capture
- Only scans localhost by default (security safeguard)
- Rule-based detection is simple — not a replacement for a SIEM or IDS
- Packet analysis is basic — does not perform deep packet inspection

### Accuracy Considerations

- The suspicious port engine uses static rules, not behavioral analysis
- Network information detection may vary across Linux distributions
- Process mapping may show "(access denied)" without root privileges

---

## Future Improvements

1. **Interactive Web Dashboard** — Flask/Django UI for visual reports
2. **Historical Comparison** — diff reports over time to detect changes
3. **Advanced Detection Rules** — YAML-based rules with regex matching
4. **Vulnerability Correlation** — cross-reference ports with CVE databases
5. **Multi-host Support** — scan multiple authorized lab machines
6. **Real-time Monitoring** — continuous capture with live alerting
7. **Export Formats** — PDF, HTML, and CSV report generation
8. **Docker Lab** — containerized lab environment for isolation
9. **Integration Tests** — automated end-to-end testing with CI/CD
10. **Notification System** — email/Slack alerts for review-level findings

---

## Security Notice

This tool is designed for **educational purposes** and **authorized local lab use only**.

- Default target: `127.0.0.1` (localhost)
- Public IPs are rejected by default
- Private IPs require explicit `--authorized-target` flag
- No offensive capabilities are included

**Do not use this tool to scan systems you do not own or have explicit written permission to test.**

---

## License

Educational project — use responsibly.
