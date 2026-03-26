"""
main.py - Main entry point for Corvus Endpoint Scanner.
Orchestrates all scanner modules and generates the HTML report.

USAGE:
  Double-click corvus.exe   →  Full scan, saves report to Desktop
  corvus.exe                →  Same as above
  corvus.exe -o C:/Reports  ->  Custom output directory
  corvus.exe --modules file,network,port  ->  Run specific modules only
  corvus.exe --quick        ->  Quick scan (skip heavy modules)
  corvus.exe --profile forensic  ->  Forensic deep scan

SCAN PROFILES:
  quick     →  ~30s   Triage scan, skip heavy modules (file/memory/ads)
  standard  →  ~3min  Balanced scan, all modules except full disk file scan
  full      →  ~12min Complete scan, all 21 modules (default)
  forensic  →  ~15min Deep forensic scan, all modules + enhanced depth
"""

import os
import sys
import io
import json
import time
import socket
import shutil
import ctypes
import argparse
import platform
import traceback
import webbrowser
from datetime import datetime
from collections import Counter
from typing import List, Optional

from scanner_core.config import config
from scanner_core.logger import setup_logger, get_log_file_path
from scanner_core.utils import BANNER, is_admin, print_section, print_startup_banner
from scanner_core.models import Finding, RiskLevel, calculate_risk_score
from scanners import SCANNER_REGISTRY, HEAVY_MODULES
from report.html_report import generate as generate_html_report
from report.json_report import export as export_json_report

# tqdm progress bar (optional, graceful fallback)
try:
    from tqdm import tqdm
    HAS_TQDM = True
except ImportError:
    HAS_TQDM = False


# ---- Scan Profiles ----
SCAN_PROFILES = {
    "quick": {
        "description": "Triage scan (~30s) — skip heavy I/O modules",
        "skip_modules": {"file_scanner", "memory_scanner", "ads_scanner"},
        "estimated_time": "30 seconds",
    },
    "standard": {
        "description": "Balanced scan (~3min) — all except full disk file scan",
        "skip_modules": {"file_scanner"},
        "estimated_time": "3 minutes",
    },
    "full": {
        "description": f"Complete scan (~12min) — all {len(SCANNER_REGISTRY)} modules",
        "skip_modules": set(),
        "estimated_time": "12 minutes",
    },
    "forensic": {
        "description": f"Deep forensic scan (~15min) — all {len(SCANNER_REGISTRY)} modules, maximum depth",
        "skip_modules": set(),
        "estimated_time": "15 minutes",
    },
}


# ---------------------------------------------------------------------------
# CLI Argument Parser
# ---------------------------------------------------------------------------

def _build_parser() -> argparse.ArgumentParser:
    """Build the argument parser with rich help text and examples."""
    # Build module list for help text
    module_lines = []
    for _, display_name, config_key in SCANNER_REGISTRY:
        short_key = config_key.replace("_scanner", "")
        heavy = " (heavy)" if config_key in HEAVY_MODULES else ""
        module_lines.append(f"    {short_key:<22} {display_name}{heavy}")
    module_list = "\n".join(module_lines)

    # Build profile list for help text
    profile_lines = []
    for pname, pdata in SCAN_PROFILES.items():
        default = " (default)" if pname == "full" else ""
        profile_lines.append(f"    {pname:<12} {pdata['description']}{default}")
    profile_list = "\n".join(profile_lines)

    epilog = f"""
examples:
  corvus.exe                              Full scan, report saved to Desktop
  corvus.exe --quick                      Triage scan (~30s, skip heavy modules)
  corvus.exe --profile forensic           Deep forensic scan (~15min)
  corvus.exe -m file,network,process      Run only specific modules
  corvus.exe -o C:\\Reports                Save reports to custom directory
  corvus.exe --no-open                    Don't auto-open HTML report in browser
  corvus.exe --list-modules               Show all available scanner modules
  corvus.exe --list-profiles              Show scan profile details
  corvus.exe --update-iocs               Fetch latest IOC feeds from abuse.ch
  corvus.exe --ioc-info                  Show IOC database status

scan profiles:
{profile_list}

scanner modules ({len(SCANNER_REGISTRY)} available):
{module_list}
    (heavy) = skipped in --quick mode

notes:
  - Run as Administrator for full visibility (prefetch, BAM/DAM, event logs)
  - Reports are saved as both HTML and JSON by default
  - Config overrides can be set in config.json (use --config for custom path)
  - Corvus is READ-ONLY — it never modifies system state
  - Scanner works fully offline; use --update-iocs to optionally fetch latest threat intel
"""

    parser = argparse.ArgumentParser(
        prog="corvus.exe",
        description="Corvus — Portable Endpoint Threat Detection Scanner",
        epilog=epilog,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--output-dir", "-o",
        default=".",
        metavar="DIR",
        help="Directory to save reports (default: Desktop/SecurityScanReports)",
    )
    parser.add_argument(
        "--no-open",
        action="store_true",
        help="Don't auto-open the HTML report in the browser after scan",
    )
    parser.add_argument(
        "--modules", "-m",
        default=None,
        metavar="LIST",
        help="Comma-separated modules to run, e.g. file,network,port (overrides profile)",
    )
    parser.add_argument(
        "--quick", "-q",
        action="store_true",
        help="Quick triage scan — skip heavy I/O modules (file, memory, ADS)",
    )
    parser.add_argument(
        "--profile", "-p",
        default=None,
        choices=["quick", "standard", "full", "forensic"],
        metavar="NAME",
        help="Scan profile: quick, standard, full (default), forensic",
    )
    parser.add_argument(
        "--config", "-c",
        default=None,
        metavar="FILE",
        help="Path to custom config.json file",
    )
    parser.add_argument(
        "--list-profiles",
        action="store_true",
        help="Show available scan profiles and exit",
    )
    parser.add_argument(
        "--list-modules",
        action="store_true",
        help="Show all available scanner modules and exit",
    )
    parser.add_argument(
        "--diff", "-d",
        default=None,
        metavar="FILE",
        help="Compare current scan with a previous JSON report (show NEW/RESOLVED/UNCHANGED)",
    )
    parser.add_argument(
        "--update-iocs",
        action="store_true",
        help="Fetch latest IOC feeds from threat intel sources (abuse.ch) and update local IOC files",
    )
    parser.add_argument(
        "--ioc-info",
        action="store_true",
        help="Show IOC database status (last update, entry counts, sources) and exit",
    )
    parser.add_argument(
        "--online",
        action="store_true",
        help="Enable online enrichment (VirusTotal, AbuseIPDB). Requires API keys in config.json.",
    )
    parser.add_argument(
        "--vt-key",
        default=None,
        metavar="KEY",
        help="VirusTotal API key (overrides config.json)",
    )
    parser.add_argument(
        "--abuseipdb-key",
        default=None,
        metavar="KEY",
        help="AbuseIPDB API key (overrides config.json)",
    )
    parser.add_argument(
        "--threatfox-key",
        default=None,
        metavar="KEY",
        help="ThreatFox auth key (overrides config.json). Get free at auth.abuse.ch",
    )
    parser.add_argument(
        "--pulsedive-key",
        default=None,
        metavar="KEY",
        help="Pulsedive API key (overrides config.json). Get free at pulsedive.com",
    )
    parser.add_argument(
        "--urlscan-key",
        default=None,
        metavar="KEY",
        help="URLScan.io API key (overrides config.json). Get free at urlscan.io",
    )
    return parser


def _show_profiles() -> None:
    """Display available scan profiles with details."""
    print(f"\n  Corvus — Scan Profiles")
    print(f"  {'='*55}")
    for pname, pdata in SCAN_PROFILES.items():
        marker = " (default)" if pname == "full" else ""
        print(f"\n  {pname.upper()}{marker}")
        print(f"    {pdata['description']}")
        print(f"    Estimated time: ~{pdata['estimated_time']}")
        if pdata["skip_modules"]:
            skipped = ", ".join(sorted(k.replace("_scanner", "") for k in pdata["skip_modules"]))
            print(f"    Skips: {skipped}")
        else:
            print(f"    Runs all {len(SCANNER_REGISTRY)} modules")
    print(f"\n  Usage: corvus.exe --profile <name>")
    print()


def _show_modules() -> None:
    """Display all available scanner modules with details."""
    print(f"\n  Corvus — Scanner Modules ({len(SCANNER_REGISTRY)} total)")
    print(f"  {'='*60}")
    print(f"  {'SHORT NAME':<22} {'DISPLAY NAME':<26} {'FLAGS'}")
    print(f"  {'-'*22} {'-'*26} {'-'*10}")
    for _, display_name, config_key in SCANNER_REGISTRY:
        short_key = config_key.replace("_scanner", "")
        flags = []
        if config_key in HEAVY_MODULES:
            flags.append("heavy")
        if not config.is_module_enabled(config_key):
            flags.append("disabled")
        flag_str = ", ".join(flags) if flags else ""
        print(f"  {short_key:<22} {display_name:<26} {flag_str}")
    print(f"\n  Heavy modules are skipped in --quick mode.")
    print(f"  Run specific modules: corvus.exe -m file,network,process")
    print()


# ---- Pre-flight Health Check ----
def _preflight_check(logger) -> dict:
    """
    Run pre-flight system checks before scanning.
    Returns a dict with check results for display and logging.
    """
    checks = {}

    # 1. Administrator privileges
    admin = is_admin()
    checks["admin"] = admin
    if admin:
        print("  [+] Administrator    : Yes — full scan coverage")
    else:
        print("  [!] Administrator    : No — limited visibility")
        print("      ╰─ Missing: Prefetch, BAM/DAM, full Event Logs, ADS deep scan")
    logger.info(f"Admin privileges: {admin}")

    # 2. OS version info
    try:
        ver = platform.version()
        build = int(ver.split(".")[-1]) if ver.count(".") >= 2 else 0
        os_name = "Windows 11" if build >= 22000 else "Windows 10"
        checks["os"] = f"{os_name} (Build {build})"
        print(f"  [i] Operating System : {os_name} Build {build}")
    except Exception:
        checks["os"] = platform.platform()
        print(f"  [i] Operating System : {platform.platform()}")
    logger.info(f"OS: {checks['os']}")

    # 3. Disk space check
    try:
        total, used, free = shutil.disk_usage("C:\\")
        free_gb = free / (1024 ** 3)
        checks["disk_free_gb"] = round(free_gb, 1)
        if free_gb < 1.0:
            print(f"  [!] Disk Space       : {free_gb:.1f} GB free — LOW! Reports may fail")
            logger.warning(f"Low disk space: {free_gb:.1f} GB")
        else:
            print(f"  [i] Disk Space       : {free_gb:.1f} GB free")
    except Exception:
        checks["disk_free_gb"] = -1

    # 4. Set process priority to Below Normal (avoid overloading system)
    try:
        handle = ctypes.windll.kernel32.GetCurrentProcess()
        BELOW_NORMAL_PRIORITY_CLASS = 0x00004000
        ctypes.windll.kernel32.SetPriorityClass(handle, BELOW_NORMAL_PRIORITY_CLASS)
        checks["priority"] = "below_normal"
        print("  [i] Process Priority : Below Normal (system-friendly)")
        logger.info("Process priority set to Below Normal")
    except Exception:
        checks["priority"] = "normal"

    # 5. Check if running from safe location
    exe_path = sys.executable if getattr(sys, "frozen", False) else os.path.abspath(__file__)
    checks["exe_path"] = exe_path
    suspicious_run_locations = ["\\temp\\", "\\tmp\\", "\\downloads\\"]
    if any(loc in exe_path.lower() for loc in suspicious_run_locations):
        print(f"  [!] Run Location     : Temporary path — consider running from a stable location")
    else:
        print(f"  [i] Run Location     : {os.path.dirname(exe_path)}")

    print()  # Blank line after pre-flight
    return checks


def _get_output_dir(cli_dir: str) -> str:
    """
    Smart output directory selection for drop-and-run portability.
    Priority:
      1. CLI --output-dir if explicitly provided
      2. Desktop of the current user
      3. Directory where the exe is located
      4. Current working directory
    """
    if cli_dir != ".":
        path = os.path.abspath(cli_dir)
        os.makedirs(path, exist_ok=True)
        return path

    desktop = os.path.join(os.environ.get("USERPROFILE", ""), "Desktop")
    if os.path.isdir(desktop):
        report_dir = os.path.join(desktop, "SecurityScanReports")
        try:
            os.makedirs(report_dir, exist_ok=True)
            return report_dir
        except OSError:
            pass

    if getattr(sys, "frozen", False):
        exe_dir = os.path.dirname(sys.executable)
    else:
        exe_dir = os.path.dirname(os.path.abspath(__file__))

    try:
        os.makedirs(exe_dir, exist_ok=True)
        test_file = os.path.join(exe_dir, ".write_test")
        with open(test_file, "w") as f:
            f.write("test")
        os.remove(test_file)
        return exe_dir
    except OSError:
        pass

    return os.path.abspath(".")


def _resolve_modules(args) -> tuple:
    """
    Resolve which modules to run based on CLI args, profile, and config.
    Returns (module_list, profile_name).
    """
    # If --modules is specified, only run those (overrides everything)
    if args.modules:
        requested = {m.strip().lower() for m in args.modules.split(",")}
        modules = [
            (mod, name, key) for mod, name, key in SCANNER_REGISTRY
            if key in requested or key.replace("_scanner", "") in requested
        ]
        return modules, "custom"

    # Determine profile
    profile_name = "full"  # default
    if args.quick:
        profile_name = "quick"
    elif args.profile:
        profile_name = args.profile.lower()
        if profile_name not in SCAN_PROFILES:
            print(f"  [!] Unknown profile '{args.profile}'. Available: {', '.join(SCAN_PROFILES.keys())}")
            print(f"  [i] Falling back to 'full' profile.")
            profile_name = "full"

    profile = SCAN_PROFILES[profile_name]
    skip = profile["skip_modules"]

    modules = [
        (mod, name, key) for mod, name, key in SCANNER_REGISTRY
        if key not in skip and config.is_module_enabled(key)
    ]
    return modules, profile_name


def _compute_diff(
    current_findings: List[Finding],
    previous_json_path: str,
) -> Optional[dict]:
    """Compare current scan findings with a previous JSON report.

    Comparison key: (module, title) tuple — description may change between
    runs so only module+title are used for identity matching.

    Args:
        current_findings: Findings from the current scan.
        previous_json_path: Path to a previous Corvus JSON report.

    Returns:
        Dict with new/resolved/unchanged findings and summary counts.
        Returns None if the previous report cannot be loaded.
    """
    try:
        with open(previous_json_path, "r", encoding="utf-8") as f:
            prev_data = json.load(f)
    except FileNotFoundError:
        print(f"  [!] Previous report not found: {previous_json_path}")
        return None
    except (json.JSONDecodeError, ValueError) as e:
        print(f"  [!] Cannot parse previous report: {e}")
        return None

    prev_findings = prev_data.get("findings", [])
    if not isinstance(prev_findings, list):
        print("  [!] Previous report has invalid findings format.")
        return None

    # Build key sets: (module, title)
    prev_keys = {(f.get("module", ""), f.get("title", "")) for f in prev_findings}
    curr_keys = {(f.module, f.title) for f in current_findings}

    new_findings = [f for f in current_findings if (f.module, f.title) not in prev_keys]
    resolved_findings = [f for f in prev_findings if (f.get("module", ""), f.get("title", "")) not in curr_keys]
    unchanged_findings = [f for f in current_findings if (f.module, f.title) in prev_keys]

    return {
        "previous_report": previous_json_path,
        "previous_scan_time": prev_data.get("scan_time", "Unknown"),
        "previous_risk_score": prev_data.get("risk_score", -1),
        "new": new_findings,
        "resolved": resolved_findings,
        "unchanged": unchanged_findings,
        "summary": {
            "new_count": len(new_findings),
            "resolved_count": len(resolved_findings),
            "unchanged_count": len(unchanged_findings),
        },
    }


def main():
    # Fix Windows console encoding for Unicode output
    try:
        if sys.stdout.encoding != "utf-8":
            sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
            sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8", errors="replace")
    except Exception:
        pass

    # Enable ANSI escape codes on Windows 10+
    try:
        kernel32 = ctypes.windll.kernel32
        kernel32.SetConsoleMode(kernel32.GetStdHandle(-11), 7)
    except Exception:
        pass

    # Parse arguments FIRST — --help, --version, --list-* exit before banner
    parser = _build_parser()
    args, _ = parser.parse_known_args()

    # Handle info-only flags (no banner, no scan)
    if args.list_profiles:
        _show_profiles()
        return
    if args.list_modules:
        _show_modules()
        return
    if args.ioc_info:
        from ioc_updater import show_ioc_info
        show_ioc_info()
        return
    if args.update_iocs:
        from ioc_updater import update_all_iocs
        print(f"\n  [*] Corvus IOC + YARA Rule Update")
        print(f"  {'='*55}")
        results = update_all_iocs(
            threatfox_key=args.threatfox_key,
            pulsedive_key=args.pulsedive_key,
        )
        print(f"\n  {'─'*55}")
        if results["updated"]:
            print(f"  [+] Successfully updated {len(results['updated'])} IOC file(s)")
        if results["failed"]:
            print(f"  [!] Failed to update {len(results['failed'])} source(s)")
            for fail in results["failed"]:
                print(f"      • {fail['file']}: {fail['error']}")
        yara_res = results.get("yara", {})
        if yara_res.get("feeds_processed", 0) > 0:
            print(f"  [+] YARA community: {yara_res['rules_valid']} rules ready"
                  f" ({yara_res['rules_broken']} broken)")
        print(f"  [i] Timestamp: {results['timestamp']}")
        print()
        return

    # ---- Actual scan starts here — show animated banner ----
    print_startup_banner(animate=True)
    print(f"  Hostname: {socket.gethostname()}")
    print(f"  Time   : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

    # Load configuration
    config.load(args.config)

    # Configure online enrichment if --online flag is set
    if args.online:
        from scanner_core.online_enrichment import configure as _configure_online
        online_cfg = config._data.get("online", {}).copy()
        online_cfg["enabled"] = True
        if args.vt_key:
            online_cfg["vt_api_key"] = args.vt_key
        if args.abuseipdb_key:
            online_cfg["abuseipdb_api_key"] = args.abuseipdb_key
        if args.urlscan_key:
            online_cfg["urlscan_api_key"] = args.urlscan_key
        _configure_online(online_cfg)
        print("  [i] Online enrichment: ENABLED")

    # Determine output directory
    output_dir = _get_output_dir(args.output_dir)

    # Initialize logger
    log_level = config.output.get("log_level", "INFO")
    logger = setup_logger(output_dir, log_level)
    logger.info("Corvus starting")
    logger.info(f"Output directory: {output_dir}")

    print(f"  [i] Report will be saved to: {output_dir}\n")

    # ---- Pre-flight Health Check ----
    print(f"  {'─'*55}")
    print(f"  PRE-FLIGHT CHECK")
    print(f"  {'─'*55}")
    preflight = _preflight_check(logger)

    # Resolve which modules to run
    active_modules, profile_name = _resolve_modules(args)
    module_names = [name for _, name, _ in active_modules]

    if profile_name != "custom":
        profile_info = SCAN_PROFILES[profile_name]
        print(f"  [i] Scan Profile: {profile_name.upper()} — {profile_info['description']}")
        print(f"  [i] Estimated time: ~{profile_info['estimated_time']}")

    print(f"  [i] Active modules ({len(active_modules)}): {', '.join(module_names)}\n")
    logger.info(f"Profile: {profile_name} | Active modules: {', '.join(module_names)}")

    start_time = time.time()
    all_findings: list[Finding] = []
    module_timings = {}

    # ---- Run scanner modules ----
    success_count = 0
    fail_count = 0
    total_modules = len(active_modules)

    # Use tqdm progress bar if available
    if HAS_TQDM and total_modules > 1:
        progress = tqdm(
            active_modules,
            desc="  Scanning",
            unit="module",
            bar_format="  {l_bar}{bar:30}{r_bar}",
            ncols=80,
            leave=True,
        )
    else:
        progress = active_modules

    for mod, display_name, config_key in progress:
        if HAS_TQDM and total_modules > 1:
            progress.set_postfix_str(display_name, refresh=True)

        mod_start = time.time()
        try:
            print_section(display_name.upper())
            findings = mod.scan()
            all_findings.extend(findings)
            mod_elapsed = time.time() - mod_start
            module_timings[display_name] = mod_elapsed
            print(f"  [+] {display_name}: {len(findings)} finding(s) ({mod_elapsed:.1f}s)")
            logger.info(f"{display_name}: {len(findings)} findings in {mod_elapsed:.1f}s")
            success_count += 1
        except Exception as e:
            mod_elapsed = time.time() - mod_start
            module_timings[display_name] = mod_elapsed
            print(f"  [!] {display_name} FAILED: {e}")
            traceback.print_exc()
            logger.error(f"{display_name} FAILED: {e}")
            fail_count += 1

    print(f"\n  [i] Modules: {success_count} OK, {fail_count} failed")

    # ---- Online Enrichment (post-scan, pre-report) ----
    enrichment_summary = None
    if args.online:
        from scanner_core.online_enrichment import enrich_findings
        print_section("ONLINE ENRICHMENT")
        enrichment_summary = enrich_findings(all_findings)
        if enrichment_summary:
            print(f"  [i] Hashes queried : {enrichment_summary['hashes_queried']}")
            print(f"  [i] IPs queried    : {enrichment_summary['ips_queried']}")
            print(f"  [i] VT hits        : {enrichment_summary['vt_hits']}")
            print(f"  [i] AbuseIPDB hits : {enrichment_summary['abuseipdb_hits']}")
            if enrichment_summary["risk_upgrades"] > 0:
                print(f"  [!] Risk upgrades  : {enrichment_summary['risk_upgrades']} finding(s)")

    # ---- Cross-Module Correlation ----
    from scanner_core.correlator import correlate
    correlation_findings = correlate(all_findings)
    if correlation_findings:
        print_section("CORRELATION ENGINE")
        print(f"  [!] {len(correlation_findings)} attack chain(s) detected:")
        for cf in correlation_findings:
            print(f"      [{cf.risk.value}] {cf.title}")
            print_finding(cf)
        all_findings.extend(correlation_findings)
    else:
        print_section("CORRELATION ENGINE")
        print("  [+] No attack chains detected — no cross-module correlations found.")

    # ---- Generate Reports ----
    elapsed = time.time() - start_time
    report_path = None
    json_path = None

    # Compute diff against previous report if --diff was provided
    diff_data = None
    if args.diff:
        diff_data = _compute_diff(all_findings, args.diff)

    print_section("REPORT GENERATION")

    # HTML Report
    if config.output.get("html_report", True):
        try:
            report_path = generate_html_report(
                all_findings, output_dir,
                elapsed=elapsed,
                module_timings=module_timings,
                diff_data=diff_data,
            )
            print(f"  [+] HTML report: {report_path}")
            logger.info(f"HTML report saved: {report_path}")
        except Exception as e:
            print(f"  [!] HTML report generation error: {e}")
            logger.error(f"HTML report error: {e}")

    # JSON Report
    if config.output.get("json_report", True):
        try:
            json_path = export_json_report(all_findings, output_dir, elapsed, module_timings, diff_data, enrichment_summary)
            print(f"  [+] JSON report: {json_path}")
            logger.info(f"JSON report saved: {json_path}")
        except Exception as e:
            print(f"  [!] JSON report generation error: {e}")
            logger.error(f"JSON report error: {e}")

    # Log file info
    log_path = get_log_file_path()
    if log_path:
        print(f"  [+] Scan log  : {log_path}")

    # ---- Summary ----
    risk_score = calculate_risk_score(all_findings)

    print(f"\n{'='*60}")
    print(f"  SCAN COMPLETE")
    print(f"{'='*60}")
    print(f"  Security Score: {risk_score}/100")
    print(f"  Duration      : {elapsed:.1f} seconds")
    print(f"  Total Findings: {len(all_findings)}")

    risk_counts = Counter(f.risk for f in all_findings)
    critical = risk_counts.get(RiskLevel.CRITICAL, 0)
    high = risk_counts.get(RiskLevel.HIGH, 0)
    medium = risk_counts.get(RiskLevel.MEDIUM, 0)
    info = risk_counts.get(RiskLevel.INFO, 0)

    if critical:
        print(f"  CRITICAL      : {critical}")
    if high:
        print(f"  HIGH          : {high}")
    if medium:
        print(f"  MEDIUM        : {medium}")
    if info:
        print(f"  INFO          : {info}")
    if not all_findings:
        print(f"  Status        : No suspicious findings detected. System appears clean.")

    if report_path:
        print(f"\n  HTML Report  : {report_path}")
    if json_path:
        print(f"  JSON Report  : {json_path}")

    print(f"{'='*60}")

    # ---- Diff Summary (if --diff was used) ----
    if diff_data:
        print(f"\n  {'─'*55}")
        print(f"  BASELINE COMPARISON")
        print(f"  {'─'*55}")
        print(f"  Previous report : {diff_data['previous_report']}")
        print(f"  Previous scan   : {diff_data['previous_scan_time']}")
        prev_score = diff_data["previous_risk_score"]
        if prev_score >= 0:
            delta = risk_score - prev_score
            arrow = "↑" if delta > 0 else ("↓" if delta < 0 else "=")
            print(f"  Score change    : {prev_score} → {risk_score} ({arrow}{abs(delta)})")

        diff_summary = diff_data["summary"]
        print(f"\n  [+] NEW       : {diff_summary['new_count']} finding(s)")
        print(f"  [+] RESOLVED  : {diff_summary['resolved_count']} finding(s)")
        print(f"  [i] UNCHANGED : {diff_summary['unchanged_count']} finding(s)")

        # List first N new findings
        new_list = diff_data.get("new", [])
        if new_list:
            print(f"\n  New findings:")
            for nf in new_list[:10]:
                print(f"    • [{nf.risk.value}] {nf.title}")
            if len(new_list) > 10:
                print(f"    ... and {len(new_list) - 10} more")

        # List first N resolved findings (dicts from previous JSON)
        resolved_list = diff_data.get("resolved", [])
        if resolved_list:
            print(f"\n  Resolved findings:")
            for rf in resolved_list[:10]:
                print(f"    • [{rf.get('risk', 'UNKNOWN')}] {rf.get('title', 'Unknown')}")
            if len(resolved_list) > 10:
                print(f"    ... and {len(resolved_list) - 10} more")
        print()

    logger.info(f"Scan complete: {len(all_findings)} findings, {elapsed:.1f}s, "
                f"C:{critical} H:{high} M:{medium} I:{info}")

    # Auto-open report
    auto_open = config.output.get("auto_open_report", True)
    if report_path and not args.no_open and auto_open:
        try:
            print("\n  [*] Opening report in browser...")
            webbrowser.open(f"file:///{report_path.replace(os.sep, '/')}")
        except Exception:
            pass

    # Keep console open when double-clicked
    print("\n  Press Enter to exit...")
    try:
        input()
    except (EOFError, KeyboardInterrupt):
        pass


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n  [!] Scan cancelled by user.")
    except Exception as e:
        print(f"\n  [!] Unexpected error: {e}")
        traceback.print_exc()
        print("  Press Enter to exit...")
        try:
            input()
        except (EOFError, KeyboardInterrupt):
            pass
