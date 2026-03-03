# Corvus - Windows Endpoint Security Scanner

**Portable, offline Windows endpoint threat detection tool. Single EXE, no agent required.**

Drop `corvus.exe` on any Windows 10/11 machine, run as Administrator, get a full HTML report with risk scoring and MITRE ATT&CK mapping. No installation, no internet, no dependencies on target.

Built for **incident responders**, **sysadmins**, and **security auditors** who need fast endpoint visibility.

---

## Features

- **24 Scanner Modules** -- file system, memory, network, registry, event logs, forensic artifacts, certificates, USB history
- **YARA Integration** -- 5 custom rule sets + Neo23x0 community rules (auto-downloadable)
- **Online Enrichment** -- optional VirusTotal + AbuseIPDB lookups (`--online` flag)
- **IOC Auto-Update** -- abuse.ch feeds + CISA KEV with `--update-iocs`
- **MITRE ATT&CK Mapping** -- every finding linked to a technique ID
- **Risk Scoring** -- 0-100 security score with executive summary
- **HTML + JSON Reports** -- dark-theme HTML dashboard + machine-readable JSON
- **Scan Diff** -- compare against previous scan baseline (`--diff previous.json`)
- **LOLBin Detection** -- command-line analysis for 8 living-off-the-land binaries
- **Single EXE** -- Nuitka-compiled native binary (~80 MB), zero target dependencies
- **Offline-First** -- all IOCs bundled, internet only needed for `--update-iocs` and `--online`
- **False-Positive Tuned** -- WinVerifyTrust signature verification, trusted vendor lists, context-aware detection

---

## Scanner Modules

| # | Module | Description | MITRE ATT&CK |
|---|--------|-------------|---------------|
| 1 | **File Scanner** | YARA rules, hash IOCs, PE entropy analysis, string signatures | T1027, T1204 |
| 2 | **Network Scanner** | Active connections, malicious IP matching | T1071 |
| 3 | **Persistence Scanner** | Registry Run keys, Scheduled Tasks, WMI subscriptions | T1547, T1053 |
| 4 | **Process Scanner** | Typosquatting, parent-child anomalies, LOLBin abuse, unsigned binaries | T1055, T1218 |
| 5 | **Memory Scanner** | RWX memory regions, process injection detection | T1055.012 |
| 6 | **Vulnerability Scanner** | CVE database + CISA KEV matching | T1203 |
| 7 | **Service Scanner** | Suspicious Windows services, unsigned service binaries | T1543.003 |
| 8 | **Event Log Scanner** | Failed logins, privilege escalation, account lockouts | T1078 |
| 9 | **Security Config Scanner** | Firewall, UAC, BitLocker, Secure Boot, LSASS protection | T1562 |
| 10 | **DNS Cache Scanner** | Malicious domains, DGA detection | T1071.004 |
| 11 | **Port Scanner** | Open port enumeration, known-bad ports | T1046 |
| 12 | **Hosts File Scanner** | Hosts file manipulation detection | T1565.001 |
| 13 | **ADS Scanner** | NTFS Alternate Data Streams | T1564.004 |
| 14 | **Named Pipe Scanner** | Cobalt Strike, Metasploit, C2 pipe patterns | T1570 |
| 15 | **DLL Hijack Scanner** | DLL search order hijacking | T1574.001 |
| 16 | **Amcache Scanner** | Execution artifacts (UserAssist, BAM/DAM, MUICache) | T1059 |
| 17 | **Prefetch Scanner** | Prefetch execution history | T1059 |
| 18 | **PowerShell History** | PSReadLine history analysis | T1059.001 |
| 19 | **Credential Scanner** | Exposed keys, tokens, registry passwords | T1552 |
| 20 | **Browser Scanner** | Malicious browser extensions | T1176 |
| 21 | **Attack Vector Scanner** | Suspicious .lnk, .iso, .vhd, .chm, .xll files | T1204.002 |
| 22 | **Certificate Store Scanner** | Rogue root CAs, expired/weak certs | T1553.004 |
| 23 | **Scheduled Task Scanner** | XML-parsed task analysis, suspicious commands | T1053.005 |
| 24 | **USB Scanner** | USB device history, unauthorized device detection | T1091 |

---

## Quick Start

### Run Pre-built EXE

```
corvus.exe                          # Full scan (default)
corvus.exe --quick                  # Quick triage (~30s)
corvus.exe --profile forensic       # Deep forensic scan
corvus.exe --online                 # With VirusTotal + AbuseIPDB enrichment
corvus.exe --update-iocs            # Update IOC databases + YARA community rules
corvus.exe --diff previous.json     # Compare with previous scan
corvus.exe --ioc-info               # Show IOC database status
```

**Important:** Run as Administrator for full visibility (process memory, registry, event logs).

### Build from Source

```bash
git clone https://github.com/rayk0l/Corvus.git
cd Corvus

pip install -r requirements.txt

# Build single-file EXE with Nuitka
build.bat
```

Nuitka compiles Python to C, then to a native binary. First build takes 5-10 minutes, subsequent builds use cache.

---

## Usage

```
corvus.exe [OPTIONS]

Options:
  -o, --output DIR              Output directory (default: Desktop\SecurityScanReports)
  -p, --profile PROFILE         quick | standard | full | forensic
  --modules MOD1,MOD2,...       Run specific modules only
  --quick                       Shortcut for --profile quick
  --online                      Enable VirusTotal + AbuseIPDB enrichment
  --vt-key KEY                  VirusTotal API key (or set in config.json)
  --abuseipdb-key KEY           AbuseIPDB API key (or set in config.json)
  --update-iocs                 Fetch latest IOC feeds + YARA community rules
  --ioc-info                    Show IOC database status
  --diff FILE                   Compare with previous JSON report
  --list-profiles               Show available scan profiles
  --list-modules                Show available modules
  --no-report                   Skip HTML report generation
  --no-open                     Don't auto-open report in browser
```

### Scan Profiles

| Profile | Time | Description |
|---------|------|-------------|
| `quick` | ~30s | Triage -- skips file, memory, ADS scanners |
| `standard` | ~3min | Balanced -- all modules except full disk scan |
| `full` | ~10min | Complete scan -- all 24 modules (default) |
| `forensic` | ~15min | Deep forensic -- maximum depth and coverage |

---

## Report Output

- **HTML Report** -- dark-theme dashboard with executive summary, risk score, per-module findings
- **JSON Report** -- machine-readable, supports scan diff comparison
- **Log File** -- detailed scan log

### Risk Score

| Score | Rating |
|-------|--------|
| 90-100 | Excellent |
| 70-89 | Good |
| 50-69 | Fair |
| 0-49 | Critical |

---

## Configuration

Edit `config.json`:

```json
{
    "scan": {
        "max_file_size_mb": 50,
        "file_scan_threads": 4,
        "event_log_days": 7,
        "memory_scan_max_per_process_mb": 50
    },
    "modules": {
        "file_scanner": true,
        "network_scanner": true,
        "..."
    },
    "exclusions": {
        "paths": [],
        "processes": [],
        "hashes": []
    },
    "online": {
        "enabled": false,
        "vt_api_key": "",
        "abuseipdb_api_key": ""
    }
}
```

---

## Project Structure

```
corvus/
├── corvus.exe                         # Nuitka-compiled binary
├── src/
│   ├── main.py                        # Entry point, CLI, orchestrator
│   ├── ioc_updater.py                 # IOC + YARA auto-update system
│   ├── scanner_core/
│   │   ├── models.py                  # Finding dataclass, risk scoring
│   │   ├── utils.py                   # Hashing, signature verification, IOC loading
│   │   ├── config.py                  # Configuration loader with validation
│   │   ├── logger.py                  # Dual logging (console + file)
│   │   └── online_enrichment.py       # VirusTotal + AbuseIPDB integration
│   ├── scanners/
│   │   ├── __init__.py                # SCANNER_REGISTRY (24 modules)
│   │   ├── file_scanner.py            # YARA + hash + PE entropy + signatures
│   │   ├── process_scanner.py         # LOLBin detection, cmdline analysis
│   │   ├── memory_scanner.py          # RWX regions, injection detection
│   │   ├── ...                        # 21 more scanner modules
│   │   └── usb_scanner.py             # USB device history
│   └── report/
│       ├── html_report.py             # Dark-theme HTML report
│       └── json_report.py             # JSON report with diff support
├── tests/                             # 372 tests
├── iocs/                              # IOC databases (auto-updatable)
├── yara_rules/                        # YARA detection rules
│   ├── *.yar                          # 5 custom rule sets
│   ├── disabled_rules.txt             # FP rule disable list
│   └── community/                     # Neo23x0 rules (via --update-iocs)
├── config.json                        # Runtime configuration
├── build.bat                          # Nuitka build script
└── requirements.txt
```

---

## Building

### Prerequisites
- Python 3.10+ (Windows)
- Nuitka + Zig compiler (auto-downloaded)

### Build

```batch
pip install -r requirements.txt
build.bat
```

### AV False Positives

Nuitka produces native binaries (not packed Python), which significantly reduces AV false positives compared to PyInstaller. For best results:

1. Add Windows Defender exclusions for the build directory
2. Sign the executable with a code signing certificate
3. Submit false positive reports to AV vendors

---

## Disclaimer

This tool is for **authorized security assessments only**. Use only on systems you own or have explicit permission to scan.

---

<p align="center">
  <b>Corvus Endpoint Scanner</b><br>
  Python | 24 Modules | Nuitka | Offline | Portable
</p>
