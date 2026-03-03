# Corvus Endpoint Scanner

Portable, offline Windows endpoint threat detection tool. Single-EXE (Nuitka),
22 scanner modules, YARA integration, HTML/JSON reporting.
Runs on target endpoints without installation.

**Design philosophy:** Agentless, offline, single-exe, zero dependency on target.
NOT an EDR, NOT a continuous monitor. Drop → scan → report → leave.

## Stack
- Python 3.10+ (Windows-only, uses ctypes.windll extensively)
- Nuitka 2.x+ for single-EXE packaging (compiles Python → C → native binary)
- Zig compiler (auto-downloaded by Nuitka for Python 3.13+)
- psutil for process/network enumeration
- yara-python for malware signature matching
- tqdm for progress bars (optional, graceful fallback)

## Project Structure

```
corvus/
├── corvus.exe                     → Built binary (Nuitka compiled, tracked in repo)
├── corvus.ico                     → Application icon
├── src/
│   ├── main.py                    → Entry point, CLI, orchestrator
│   ├── ioc_updater.py             → IOC auto-update from abuse.ch feeds
│   ├── scanner_core/
│   │   ├── models.py              → Finding, RiskLevel, calculate_risk_score()
│   │   ├── utils.py               → Hashing, signature check, IOC loading, trusted vendors,
│   │   │                            IOThrottle, re-exports models for convenience
│   │   ├── config.py              → ScanConfig, loads config.json with safe defaults
│   │   └── logger.py              → Dual logging: console + file
│   ├── scanners/
│   │   ├── __init__.py            → SCANNER_REGISTRY, HEAVY_MODULES
│   │   ├── file_scanner.py        → YARA + hash IOC + string signatures
│   │   ├── network_scanner.py     → Active TCP connections, malicious IP matching
│   │   ├── persistence_scanner.py → Registry Run keys, Scheduled Tasks, WMI
│   │   ├── process_scanner.py     → Typosquatting, parent-child, unsigned bins
│   │   ├── memory_scanner.py      → RWX regions, process injection via ctypes
│   │   ├── vulnerability_scanner.py → Offline CVE matching
│   │   ├── service_scanner.py     → Suspicious Windows services
│   │   ├── eventlog_scanner.py    → Failed logins, privilege escalation
│   │   ├── security_config_scanner.py → Firewall, UAC, BitLocker, LSASS
│   │   ├── dns_scanner.py         → DNS cache, DGA detection
│   │   ├── port_scanner.py        → Open port enumeration
│   │   ├── hosts_scanner.py       → Hosts file manipulation
│   │   ├── ads_scanner.py         → NTFS Alternate Data Streams
│   │   ├── pipe_scanner.py        → Named pipe C2 patterns
│   │   ├── dll_hijack_scanner.py  → DLL search order hijacking
│   │   ├── amcache_scanner.py     → Amcache, UserAssist, BAM/DAM
│   │   ├── prefetch_scanner.py    → Prefetch execution history
│   │   ├── powershell_history_scanner.py → PSReadLine history
│   │   ├── credential_scanner.py  → Exposed keys, tokens, cloud creds, registry passwords
│   │   ├── browser_scanner.py     → Malicious browser extensions
│   │   ├── attack_vector_scanner.py → .lnk/.iso/.vhd/.chm/.xll detection
│   │   └── certificate_store_scanner.py → Rogue root CA, expired cert, weak algo detection
│   └── report/
│       ├── html_report.py         → Standalone dark-theme HTML report
│       └── json_report.py         → Machine-readable JSON report
├── tests/
│   ├── conftest.py
│   ├── test_scoring.py
│   ├── test_config.py
│   ├── test_signature.py
│   ├── test_process_cmdline.py
│   ├── test_attack_vector.py
│   ├── test_pe_entropy.py
│   ├── test_credential_registry.py
│   ├── test_certificate_store.py
│   ├── test_scan_diff.py
│   └── test_smoke_scanners.py
├── iocs/                          → IOC databases
├── yara_rules/                    → YARA detection rules
├── config.json                    → Runtime configuration
├── corvus.spec                    → LEGACY PyInstaller spec (reference only)
├── build.bat                      → Build script (Nuitka + Zig)
├── requirements.txt
├── requirements-dev.txt
├── pyproject.toml
└── .gitignore
```

## Module Contract
Every scanner module MUST export:
```python
from scanner_core.utils import Finding, RiskLevel, print_section, print_finding

def scan() -> List[Finding]:
    findings = []
    # detection logic
    return findings
```
- Return: always `List[Finding]`
- Finding requires: module, risk (RiskLevel), title, description
- Optional: details (dict), mitre_id (str), remediation (str)
- Import shared logic from `scanner_core.utils` — never duplicate

## Adding a New Module
1. Create `src/scanners/new_scanner.py` with `scan() -> List[Finding]`
2. Import + register in `src/scanners/__init__.py` → SCANNER_REGISTRY
3. Add default to DEFAULTS["modules"] in `src/scanner_core/config.py`
4. If heavy I/O, add to HEAVY_MODULES set in `src/scanners/__init__.py`

## Key Design Decisions
- Risk score: ONE source of truth → `src/scanner_core/models.py` → `calculate_risk_score()`
- utils.py re-exports Finding, RiskLevel, calculate_risk_score for convenience
- `get_resource_path()`: Nuitka → `__nuitka_binary_dir`, PyInstaller → `_MEIPASS`, dev → project root
- config.json, iocs/, yara_rules/ live at project root (bundled into exe via build.bat)
- corvus.exe lives in project root, tracked in git (`!corvus.exe` in .gitignore)
- Nuitka + Zig compiler reduces AV false positives vs PyInstaller bootloader
- Modules run sequentially — NOT parallel. Shared system resources make parallelism unsafe on prod endpoints. IOThrottle handles I/O pressure.

## Code Standards
- Type hints on all function signatures
- Docstrings: Google style, module-level required
- Specific exceptions only (PermissionError, OSError, psutil.NoSuchProcess)
- Never bare `except:` — minimum `except Exception`
- `IOThrottle` for disk/registry I/O loops
- Graceful degradation: log and continue on non-fatal errors
- Console: `[+]` success, `[!]` warning, `[i]` info, `[*]` action

## Security — NON-NEGOTIABLE
- READ-ONLY: never modify system state (registry, services, files)
- OFFLINE: scanner works fully offline. Optional network: `--update-iocs` for IOC feeds, future `--online` for real-time enrichment
- subprocess: always timeout, always shell=False, never shell=True
- File reads: always try/except PermissionError
- ctypes: validate handles, check return values

## False Positive Management
- Context-aware detection: check signature, trusted vendor, dev tool BEFORE flagging
- `check_file_signature()` → `is_trusted_signer()` → `is_known_dev_tool()` → `is_os_native_path()`
- When in doubt, downgrade risk level rather than false-flag

## Risk Scoring (models.py — single source of truth)
```
CRITICAL: -15 | HIGH: -8 | MEDIUM: -3 | INFO: -1
Score = max(0, min(100, 100 - sum(deductions)))
```

## MITRE ATT&CK
Every Finding needs `mitre_id`. Use specific sub-techniques:
T1059.001 not T1059 | T1547.001 not T1547 | T1574.001 not T1574

## Build & Test
```batch
pip install -r requirements.txt
build.bat                              → corvus.exe (~5-10 min, cached)

pip install -r requirements-dev.txt
pytest -v
```

## DANGEROUS — ASK BEFORE
- Changing Finding dataclass fields
- Modifying SCANNER_REGISTRY
- Editing trusted vendor lists
- Changing calculate_risk_score()
- Any new subprocess call
- Switching build system or Nuitka flags

---

## DEVELOPMENT ROADMAP

Status: [ ] todo  [~] in progress  [x] done

### Sprint 1 — Performance & Detection Critical

#### 1.1 WinVerifyTrust ctypes replacement
- [x] Replace check_file_signature() PowerShell spawning with ctypes WinVerifyTrust
- [x] MUST support catalog-signed files too (CryptCATAdminCalcHashFromFileHandle + CryptCATAdminEnumCatalogFromHash) — most Windows built-ins are catalog-signed, not embedded Authenticode
- [x] Keep PowerShell as fallback if ctypes call fails
- [x] Replace unbounded _signature_cache with LRU cache (max 2000 entries)
- [x] Expected: 10-100x speedup on signature checks → measured ~30x
- Files: `src/scanner_core/utils.py`, `tests/test_signature.py`
- Test: svchost.exe → signed+trusted, notepad.exe → signed+trusted, random unsigned → unsigned
- Result: 20/20 tests pass, ~11ms/call vs ~320ms PowerShell

#### 1.2 Process scanner command-line analysis
- [x] Capture cmdline via psutil.Process.cmdline() — lazy per-PID fetch
- [x] Detect LOLBin abuse patterns (8 binaries, 24 compiled regex patterns):
  - certutil -urlcache / -encode / -decode
  - mshta javascript: / vbscript: / http:
  - rundll32 suspicious DLL paths or javascript:
  - regsvr32 /s /n /u /i:URL scrobj.dll
  - bitsadmin /transfer
  - wmic process call create
  - powershell -enc / IEX / downloadstring / -w hidden / -nop / frombase64string
  - cmd.exe /c with nested interpreters / pipe chains
- [x] General suspicious cmdline patterns for non-trusted processes (5 patterns)
- [x] Skip cmdline analysis for trusted-signed processes (performance)
- [x] LOLBins always checked regardless of trust (they ARE Microsoft-signed)
- [x] Two-phase scan: Phase A name-deduped (existing), Phase B per-PID cmdline
- [x] MITRE: T1218.005/.010/.011, T1059.001/.003, T1197, T1105, T1047, T1220, T1140, T1027, T1564.003, T1204.002
- Files: `src/scanners/process_scanner.py`, `tests/test_process_cmdline.py`
- Note: cmdline requires admin for some processes — handled via AccessDenied graceful fallback
- Result: 97/97 tests pass (61 new cmdline tests), 8 LOLBins × 2-8 patterns each + 5 general patterns

#### 1.3 Trusted signer exact+prefix match
- [x] Replace substring matching with exact + prefix: `signer_lower == trusted OR signer_lower.startswith(trusted + " ")`
- [x] Remove all `if trusted in signer_lower` patterns
- [x] Verify: "notmicrosoft corp" must NOT match. "Microsoft Corporation" must match.
- Files: `src/scanner_core/utils.py`, `tests/test_signature.py`
- Result: 36/36 tests pass, 16 new trusted signer tests (exact, prefix, spoof prevention, edge cases)

#### 1.4 Modern attack vector file extensions
- [x] New lightweight module: `attack_vector_scanner.py` (NOT in HEAVY_MODULES — runs in all modes including --quick)
- [x] Detect 7 dangerous extensions in user-writable dirs (Downloads, Desktop, Temp, AppData, Public):
  - .lnk → custom MS-SHLLINK binary parser, 10 suspicious target patterns (LOLBins: powershell, cmd, mshta, certutil, regsvr32, bitsadmin, rundll32, wscript, cscript)
  - .iso / .img → mounted disk images (MOTW bypass), context-aware risk (Temp=HIGH, Downloads=MEDIUM)
  - .chm → compiled HTML help (script execution), always HIGH
  - .xll → Excel add-in (code execution), always HIGH
  - .vhd / .vhdx → virtual hard disk (MOTW bypass), always HIGH
- [x] MITRE: T1204.002, T1553.005, T1218.001, T1137.006
- [x] Context-aware risk: staging locations (Temp/AppData) = HIGH, user dirs (Downloads/Desktop) = MEDIUM for ISO/IMG
- Files: `src/scanners/attack_vector_scanner.py`, `tests/test_attack_vector.py`, `src/scanners/__init__.py`, `src/scanner_core/config.py`
- Note: Windows Defender blocks `open()` on .lnk files with known-malicious content — scanner handles gracefully via OSError catch, tests use in-memory parsing
- Result: 84/84 tests pass, 21 scanner modules total

### Sprint 2 — Code Quality & Stability

#### 2.1 Deduplicate SYSTEM_PROCESSES
- [x] Unified SYSTEM_PROCESSES set (35 entries) in `src/scanner_core/utils.py`
- [x] Merged entries from both process_scanner (31) and memory_scanner (27) — union of both
- [x] Both modules now import from utils — single source of truth
- Files: `src/scanner_core/utils.py`, `src/scanners/process_scanner.py`, `src/scanners/memory_scanner.py`

#### 2.2 HTML report — dynamic module list
- [x] Module list derived from SCANNER_REGISTRY at report generation time
- [x] Icon + description metadata in `_MODULE_META` dict with safe fallback for unknown modules
- [x] Fixed: attack_vector_scanner was missing from HTML report (active bug)
- [x] Fixed: config.json was missing attack_vector_scanner entry
- Files: `src/report/html_report.py`, `config.json`

#### 2.3 Config validation
- [x] Validation in `ScanConfig._validate()` called after every `load()`
- [x] Range checks: max_file_size_mb 1-500, threads 1-16, days 1-365, events 100-50000, log_level valid
- [x] Invalid values: warn + fallback to DEFAULTS — never crash
- Files: `src/scanner_core/config.py`

#### 2.4 Module smoke tests
- [x] Every module: import OK, scan() returns List[Finding], no crash
- [x] Mark Windows-only with @pytest.mark.skipif, heavy modules with @pytest.mark.slow
- [x] 22 modules × 1 smoke test + 1 registry completeness test = 23 tests
- Files: `tests/test_smoke_scanners.py`
- Result: 23/23 tests pass (19 non-slow + 3 slow + 1 meta)

#### 2.5 ~~VERSION centralization~~ — REMOVED
- [x] VERSION removed entirely (no versioning needed at this stage)
- Files: `src/scanner_core/utils.py`, `src/main.py`, `src/report/*.py`

### Sprint 3 — Detection Depth

#### 3.1 PE header + entropy analysis
- [x] Pure Python PE parser (no pefile dependency): DOS header → PE signature → COFF header → Section table
- [x] 3 detection types: packer section names (20+ entries, HIGH), high entropy >7.0 (MEDIUM), RWX sections (MEDIUM)
- [x] Shannon entropy calculation per section (max 256KB read)
- [x] Integrated as CHECK 4 in file_scanner._scan_single_file() for .exe/.dll/.scr/.cpl
- [x] MITRE: T1027.002
- Files: `src/scanners/file_scanner.py`, `tests/test_pe_entropy.py`
- Result: 32/32 tests pass

#### 3.2 Credential scanner expansion (registry only)
- [x] Registry credentials: PuTTY sessions, WinSCP sessions, RealVNC, TightVNC (winreg stdlib)
- [x] FileZilla: sitemanager.xml existence check (%APPDATA%)
- [x] Report EXISTENCE only — `details["note"] = "Credential values NOT read"` enforced
- [x] MITRE: T1552.002 (registry), T1552.001 (FileZilla file-based)
- [x] Scope narrowed: Discord/Slack tokens and cmdkey removed (unnecessary risk)
- Files: `src/scanners/credential_scanner.py`, `tests/test_credential_registry.py`
- Result: 19/19 tests pass

#### 3.3 Scan diff / baseline comparison
- [x] `corvus.exe --diff previous_report.json` CLI argument
- [x] `_compute_diff()` compares using (module, title) identity key
- [x] Console output: NEW/RESOLVED/UNCHANGED counts + first 10 of each
- [x] JSON report: `diff` section with new_findings, resolved_findings, summary
- [x] HTML report: Baseline Comparison card with new/resolved finding lists
- [x] Graceful error handling: missing file → None, bad JSON → None, scan continues
- Files: `src/main.py`, `src/report/json_report.py`, `src/report/html_report.py`, `tests/test_scan_diff.py`
- Result: 24/24 tests pass

### Sprint 4 — Reporting & Integration

#### ~~4.1 SIEM export (CSV, Splunk HEC JSON)~~ — REMOVED (unnecessary complexity)
#### ~~4.2 HTML report pagination/search for 500+ findings~~ — REMOVED (premature optimization)
#### ~~4.3 Sysmon log parser (new module)~~ — REMOVED (breaks scan-and-leave philosophy)
#### 4.4 Certificate store scanner
- [x] New module: `certificate_store_scanner.py` — rogue root CA detection via ctypes + crypt32.dll
- [x] 4 checks: untrusted root CA (HIGH/MEDIUM), expired cert (INFO), weak algorithm MD5/SHA1 (HIGH/MEDIUM), self-signed unknown (HIGH)
- [x] TRUSTED_ROOT_ISSUERS: ~100+ entries covering all major CAs
- [x] ctypes setup with proper argtypes/restype (64-bit safe)
- [x] MITRE: T1553.004
- [x] Registered in: `__init__.py`, `config.py`, `html_report.py`, `config.json`
- [x] Module count: 21 → 22
- Files: `src/scanners/certificate_store_scanner.py`, `tests/test_certificate_store.py`
- Result: 36/36 tests pass

### Sprint 5 — Security Hardening & IOC Management

#### 5.1 shell=True → shell=False refactor
- [x] `_run_cmd(cmd: str)` → `_run_cmd(cmd: List[str])` with `shell=False`
- [x] All 20+ command strings converted to list format in `security_config_scanner.py`
- [x] 3 WMI commands converted in `persistence_scanner.py`
- Files: `src/scanners/security_config_scanner.py`, `src/scanners/persistence_scanner.py`

#### 5.2 IOC auto-update system
- [x] New module: `src/ioc_updater.py` — fetches from abuse.ch feeds (urllib, zero dependencies)
- [x] Sources: Feodo Tracker (IPs), URLhaus (domains), MalwareBazaar (hashes)
- [x] Merge strategy: existing + new = union (manual entries preserved)
- [x] Metadata headers auto-written (timestamp, source, count)
- [x] `--update-iocs` CLI flag: fetch and merge IOC feeds
- [x] `--ioc-info` CLI flag: show IOC database status
- Files: `src/ioc_updater.py`, `src/main.py`

#### 5.3 YARA Mimikatz rule tightening
- [x] Old condition: `any of ($s*) or ($author and $name)` — single generic string could trigger
- [x] New condition: `2 of ($s1-$s5)` OR `($author and $name and any of ($s*))` OR `3 of ($s*)`
- [x] `$s6` ("privilege::debug") and `$s7` ("token::elevate") no longer trigger alone
- Files: `yara_rules/malware_rules.yar`

### Sprint 6 (planned) — Online Enrichment

#### 6.1 Real-time threat intel (`--online` flag)
- [ ] `--online` flag: query external APIs during scan for real-time enrichment
- [ ] VirusTotal API: hash reputation lookup (API key in config.json)
- [ ] AbuseIPDB: IP reputation score
- [ ] Rate limiting, session-level LRU cache, graceful fallback
- Files: TBD

### Backlog — Future Consideration
- Sigma rule engine (high effort, pySigma dependency)
- ETW traces (needs continuous monitoring — doesn't fit scan-and-leave)
- ~~STIX/TAXII IOC updates~~ → Sprint 5.2 (abuse.ch feeds) ✓
- Shellcode patterns in memory (high FP, modern encoders bypass)
- UDP scanning (unreliable via psutil on Windows)
- Beaconing detection (needs time-series, not snapshot)
- Geo-IP (needs external DB, breaks offline)
- Parallel modules (unsafe — shared resources, race conditions)
- WMI event subscription deep inspection (Registry/COM, MOF parsing)
- Scheduled Task XML parsing (`C:\Windows\System32\tasks\`)
- DLL sideloading YARA rule MZ check (`uint16(0) == 0x5A4D`)
- Risk scoring nonlinear model

### Out of Scope — Do NOT Implement
- Agent-based monitoring (Corvus = scan and leave)
- Packet capture (pcap/npcap dependency)
- Active exploitation (Corvus = passive only)
- Kernel hooking detection (needs driver)

---

## Technical Debt
- ~~check_file_signature() PowerShell spawning~~ → Sprint 1.1 ✓
- ~~Trusted signer substring match~~ → Sprint 1.3 ✓
- ~~_signature_cache unbounded~~ → Sprint 1.1 (LRU) ✓
- ~~SYSTEM_PROCESSES duplicated~~ → Sprint 2.1 ✓
- ~~HTML report hardcoded module list~~ → Sprint 2.2 ✓
- ~~Config accepts invalid values~~ → Sprint 2.3 ✓
- ~~VERSION in 2 places~~ → Removed entirely ✓
- ~~No smoke tests~~ → Sprint 2.4 ✓ (22 modules, 312 total tests)
- ~~shell=True in subprocess calls~~ → Sprint 5.1 ✓
- ~~IOC files no versioning/metadata~~ → Sprint 5.2 ✓
- ~~YARA Mimikatz rule too broad~~ → Sprint 5.3 ✓
- No CI/CD pipeline (after Sprint 2 stabilizes tests)
