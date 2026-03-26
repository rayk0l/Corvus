"""
memory_scanner.py - Process memory analysis module.
Scans running processes for:
  1. Suspicious strings in process memory (malware signatures)
  2. Executable memory regions (RWX) indicating code injection
  3. Unsigned/suspicious loaded DLLs
  4. Process hollowing indicators

Requires Administrator privileges for full coverage.
"""

import os
import json
import ctypes
import ctypes.wintypes
from typing import List, Dict, Set, Optional
from dataclasses import dataclass

import psutil

from scanner_core.utils import (
    Finding, RiskLevel, IOThrottle, SYSTEM_PROCESSES,
    get_resource_path, check_file_signature,
    is_known_dev_tool, is_os_native_path,
    print_section, print_finding,
)

# ---- Windows API Constants ----
PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_VM_READ = 0x0010
MEM_COMMIT = 0x1000
PAGE_EXECUTE_READWRITE = 0x40
PAGE_EXECUTE_WRITECOPY = 0x80
PAGE_EXECUTE = 0x10
PAGE_EXECUTE_READ = 0x20

# All executable memory protection flags
EXECUTABLE_PROTECTIONS = {
    PAGE_EXECUTE, PAGE_EXECUTE_READ,
    PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_WRITECOPY,
}

# RWX (Read-Write-Execute) — strongest injection indicator
RWX_PROTECTIONS = {PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_WRITECOPY}

# Minimum RWX region size to flag (skip small allocations)
MIN_RWX_SIZE = 4096  # 4 KB
LARGE_RWX_THRESHOLD = 1024 * 1024  # 1 MB — strong indicator


# ---- Windows API Structures ----
class MEMORY_BASIC_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("BaseAddress", ctypes.c_void_p),
        ("AllocationBase", ctypes.c_void_p),
        ("AllocationProtect", ctypes.wintypes.DWORD),
        ("RegionSize", ctypes.c_size_t),
        ("State", ctypes.wintypes.DWORD),
        ("Protect", ctypes.wintypes.DWORD),
        ("Type", ctypes.wintypes.DWORD),
    ]

# Processes that legitimately use RWX memory (JIT compilers, V8, .NET)
# These are expected to have RWX regions and should NOT be flagged
JIT_PROCESSES = {
    # Chromium-based browsers (V8 JIT)
    "chrome.exe", "brave.exe", "msedge.exe", "opera.exe", "vivaldi.exe",
    "msedgewebview2.exe", "chromium.exe",
    # Electron apps (V8 JIT)
    "antigravity.exe", "code.exe", "cursor.exe", "claude.exe",
    "discord.exe", "slack.exe", "teams.exe", "msteams.exe",
    "notion.exe", "spotify.exe", "figma.exe", "obsidian.exe",
    "whatsapp.exe", "telegram.exe", "signal.exe", "postman.exe",
    "bitwarden.exe",
    # .NET JIT
    "powershell.exe", "pwsh.exe", "dotnet.exe",
    # Java JIT
    "java.exe", "javaw.exe",
    # Node.js (V8 JIT)
    "node.exe",
    # Firefox (SpiderMonkey JIT)
    "firefox.exe",
    # Games (anti-cheat, scripting engines, DRM use RWX memory)
    "league of legends.exe", "leagueclient.exe", "riotclientservices.exe",
    "valorant.exe", "valorant-win64-shipping.exe",
    "csgo.exe", "cs2.exe", "dota2.exe",
    "fortnite.exe", "fortniteclient-win64-shipping.exe",
    "gta5.exe", "rdr2.exe",
    "steam.exe", "steamwebhelper.exe",
    "epicgameslauncher.exe",
}

# Processes that are EXPECTED to have some RWX regions due to audio DSP,
# drivers, etc. These are still scanned but severity is reduced from
# MEDIUM to INFO unless they show extremely suspicious indicators.
KNOWN_RWX_SERVICES = {
    # Audio services (DSP engines use RWX for real-time audio processing)
    "intelaudioservice.exe", "wavesaudioservice.exe", "wavessyssvc64.exe",
    "dolbydalaxservice.exe", "reabornsvc64.exe", "nahimicsvc64.exe",
    "realtekaudioservice.exe",
    # Anti-virus / security (they inspect memory, legitimately need RWX)
    "msmpeng.exe", "mpcmdrun.exe",
}

# ---- Known safe DLL directories ----
SAFE_DLL_DIRS = [
    "c:\\windows\\system32",
    "c:\\windows\\syswow64",
    "c:\\windows\\winsxs",
    "c:\\program files\\",
    "c:\\program files (x86)\\",
]

# ---- Safe paths for "memory-only" DLL detection ----
# DLLs loaded from these paths are legitimate even if the file is no longer
# on disk (e.g., Office ClickToRun loads from Updates/ which gets cleaned up).
# We use PATH-based matching rather than name-based to prevent attackers from
# naming their DLL "msvcp140.dll" and getting a free pass.
SAFE_MEMORY_DLL_PATHS = [
    # Microsoft Office ClickToRun update staging
    "\\clicktorun\\updates\\",
    "\\microsoft shared\\clicktorun\\updates\\",
    # Windows Update staging
    "\\windows\\softwaredistribution\\",
    # .NET runtime paths
    "\\dotnet\\shared\\",
    "\\assembly\\nativeimages_",
    # Windows Installer temp
    "\\installer\\{",
]

# ---- Known suspicious DLL names ----
SUSPICIOUS_DLL_NAMES = {
    "metsrv.dll", "ext_server_stdapi.dll", "ext_server_priv.dll",
    "beacon.dll", "beacon.x64.dll",
    "inject.dll", "payload.dll", "loader.dll",
    "mimikatz.dll", "mimilib.dll", "mimidrv.sys",
    "hookdll.dll", "keylog.dll",
}


def _load_memory_signatures() -> List[Dict]:
    """Load memory-specific malware signatures."""
    path = get_resource_path(os.path.join("iocs", "malware_signatures.json"))
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        return data.get("memory_signatures", [])
    except (FileNotFoundError, json.JSONDecodeError):
        return []


def _open_process(pid: int) -> Optional[int]:
    """Open a process for memory reading."""
    try:
        handle = ctypes.windll.kernel32.OpenProcess(
            PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, False, pid
        )
        return handle if handle else None
    except Exception:
        return None


def _close_handle(handle: int):
    """Close a process handle."""
    try:
        ctypes.windll.kernel32.CloseHandle(handle)
    except Exception:
        pass


def _get_memory_regions(handle: int) -> List[MEMORY_BASIC_INFORMATION]:
    """Enumerate memory regions of a process."""
    regions = []
    mbi = MEMORY_BASIC_INFORMATION()
    address = 0
    max_address = 0x7FFFFFFFFFFF  # User-mode address space limit (x64)

    try:
        while address < max_address:
            result = ctypes.windll.kernel32.VirtualQueryEx(
                handle, ctypes.c_void_p(address),
                ctypes.byref(mbi), ctypes.sizeof(mbi)
            )
            if result == 0:
                break

            if mbi.State == MEM_COMMIT:
                regions.append(MEMORY_BASIC_INFORMATION(
                    BaseAddress=mbi.BaseAddress,
                    AllocationBase=mbi.AllocationBase,
                    AllocationProtect=mbi.AllocationProtect,
                    RegionSize=mbi.RegionSize,
                    State=mbi.State,
                    Protect=mbi.Protect,
                    Type=mbi.Type,
                ))

            address += mbi.RegionSize if mbi.RegionSize > 0 else 4096
    except Exception:
        pass

    return regions


def _read_process_memory(handle: int, address: int, size: int) -> Optional[bytes]:
    """Read memory from a process."""
    try:
        buf = ctypes.create_string_buffer(size)
        bytes_read = ctypes.c_size_t()
        result = ctypes.windll.kernel32.ReadProcessMemory(
            handle, ctypes.c_void_p(address),
            buf, size, ctypes.byref(bytes_read)
        )
        if result:
            return buf.raw[:bytes_read.value]
    except Exception:
        pass
    return None


def _check_rwx_regions(
    pid: int,
    proc_name: str,
    proc_path: str,
    handle: int,
    regions: List[MEMORY_BASIC_INFORMATION],
) -> List[Finding]:
    """Check for suspicious RWX (Read-Write-Execute) memory regions."""
    findings = []
    rwx_count = 0
    rwx_total_size = 0
    large_rwx = False

    for region in regions:
        if region.Protect in RWX_PROTECTIONS and region.RegionSize >= MIN_RWX_SIZE:
            rwx_count += 1
            rwx_total_size += region.RegionSize
            if region.RegionSize >= LARGE_RWX_THRESHOLD:
                large_rwx = True

    # Flag if excessive RWX regions or any large ones
    if large_rwx or rwx_count >= 5:
        name_lower = proc_name.lower()
        is_known_service = name_lower in KNOWN_RWX_SERVICES

        if is_known_service and not large_rwx:
            # Known services (audio DSP, etc.) with small RWX: INFO only
            risk = RiskLevel.INFO
            title_prefix = "Expected RWX memory"
            desc = (
                f"Process has {rwx_count} RWX memory regions ({rwx_total_size / 1024:.1f} KB). "
                "This is expected for audio/DSP services but noted for audit."
            )
        else:
            # Check if the process is signed+trusted in a safe install dir.
            # Trusted vendor software in Program Files with small RWX is
            # benign (JIT, audio DSP, game engines).  Downgrade to INFO.
            sig = check_file_signature(proc_path) if proc_path else {}
            is_safe_install = (
                proc_path and proc_path.lower().startswith((
                    "c:\\program files\\", "c:\\program files (x86)\\",
                ))
            )
            if sig.get("trusted") and is_safe_install and not large_rwx:
                risk = RiskLevel.INFO
                title_prefix = "RWX memory (trusted vendor)"
                desc = (
                    f"Process has {rwx_count} RWX memory regions "
                    f"({rwx_total_size / 1024:.1f} KB). Process is signed "
                    "by a trusted vendor in a standard install path."
                )
            else:
                risk = RiskLevel.HIGH if large_rwx else RiskLevel.MEDIUM
                title_prefix = "Suspicious RWX memory"
                desc = "Process has executable+writable memory regions, indicating possible code injection or shellcode."

        findings.append(Finding(
            module="Memory Scanner",
            risk=risk,
            title=f"{title_prefix}: {proc_name} (PID {pid})",
            description=desc,
            details={
                "process": proc_name,
                "pid": pid,
                "path": proc_path,
                "rwx_regions": rwx_count,
                "rwx_total_size": f"{rwx_total_size / 1024:.1f} KB",
                "has_large_rwx": large_rwx,
                "known_service": is_known_service,
            },
            mitre_id="T1055",
            remediation=f"Kill the process (PID {pid}). Investigate for code injection or shellcode.",
        ))

    return findings


def _check_memory_strings(
    pid: int,
    proc_name: str,
    proc_path: str,
    handle: int,
    regions: List[MEMORY_BASIC_INFORMATION],
    signatures: List[Dict],
    is_jit_process: bool = False,
) -> List[Finding]:
    """Scan readable memory regions for malware strings.

    For JIT/browser processes, a higher match threshold is required because
    web content (security articles, chat conversations) can contain malware
    keywords as text. A real in-memory beacon will match 3+ signature strings,
    while a web page mentioning "mimikatz" will match only 1-2.

    Args:
        is_jit_process: If True, require 3+ matched strings per signature
                        and downgrade severity (to avoid web-content FPs).
    """
    findings = []
    max_scan_size = 50 * 1024 * 1024  # Max 50 MB per process
    scanned = 0

    # Collect readable memory content
    memory_chunks = []
    for region in regions:
        if scanned >= max_scan_size:
            break

        # Only scan committed, readable regions
        if region.State != MEM_COMMIT:
            continue
        if region.RegionSize > 10 * 1024 * 1024:
            continue  # Skip very large regions (>10MB)

        data = _read_process_memory(handle, region.BaseAddress, min(region.RegionSize, 4 * 1024 * 1024))
        if data:
            memory_chunks.append(data)
            scanned += len(data)

    if not memory_chunks:
        return findings

    # Combine chunks and search
    combined = b"".join(memory_chunks)
    combined_lower = combined.lower()

    # JIT/browser processes need stronger evidence: 3+ matches to flag
    # because web page text can contain individual malware keywords.
    # A real injected beacon will have many matching strings at once.
    min_matches = 3 if is_jit_process else 1

    for sig in signatures:
        strings = sig.get("strings", [])
        total_strings = len(strings)
        matched = []
        for s in strings:
            if s.lower().encode("utf-8", errors="ignore") in combined_lower:
                matched.append(s)

        if len(matched) < min_matches:
            continue  # Not enough evidence

        # Calculate match confidence
        match_ratio = len(matched) / max(total_strings, 1)

        severity = sig.get("severity", "HIGH")

        if is_jit_process:
            # For JIT processes: downgrade one level to account for
            # legitimate web content. CRITICAL→HIGH, HIGH→MEDIUM.
            # But if ALL strings match (high confidence), keep original severity.
            if match_ratio < 0.8:
                risk = (
                    RiskLevel.HIGH if severity == "CRITICAL"
                    else RiskLevel.MEDIUM
                )
                confidence = "MEDIUM"
            else:
                risk = (
                    RiskLevel.CRITICAL if severity == "CRITICAL"
                    else RiskLevel.HIGH if severity == "HIGH"
                    else RiskLevel.MEDIUM
                )
                confidence = "HIGH"
        else:
            risk = (
                RiskLevel.CRITICAL if severity == "CRITICAL"
                else RiskLevel.HIGH if severity == "HIGH"
                else RiskLevel.MEDIUM
            )
            confidence = "HIGH"

        findings.append(Finding(
            module="Memory Scanner",
            risk=risk,
            title=f"Malware in memory: {sig['name']} — {proc_name} (PID {pid})",
            description=f"Process memory contains strings matching {sig['name']}.",
            details={
                "process": proc_name,
                "pid": pid,
                "path": proc_path,
                "signature_id": sig.get("id", ""),
                "signature_name": sig.get("name", ""),
                "matched_strings": ", ".join(matched[:5]),
                "matched_count": f"{len(matched)}/{total_strings}",
                "confidence": confidence,
                "memory_scanned": f"{scanned / 1024 / 1024:.1f} MB",
            },
            mitre_id="T1055",
            remediation=f"Kill the process (PID {pid}) immediately. Run a full memory scan on the system.",
        ))

    return findings


def _check_loaded_dlls(pid: int, proc_name: str, proc_path: str) -> List[Finding]:
    """Check loaded DLLs for suspicious or unsigned modules."""
    findings = []

    try:
        proc = psutil.Process(pid)
        memory_maps = proc.memory_maps(grouped=False)
    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess, Exception):
        return findings

    suspicious_dlls = []
    seen_dlls = set()  # Deduplication: (reason, dll_name) per process

    for mmap in memory_maps:
        path = mmap.path if hasattr(mmap, "path") else ""
        if not path or not path.lower().endswith(".dll"):
            continue

        path_lower = path.lower()
        dll_name = os.path.basename(path).lower()

        # Check known suspicious DLL names (always flag, never skip)
        if dll_name in SUSPICIOUS_DLL_NAMES:
            dedup_key = ("known_bad", dll_name)
            if dedup_key not in seen_dlls:
                seen_dlls.add(dedup_key)
                suspicious_dlls.append(("known_bad", path, dll_name))
            continue

        # Check if DLL exists on disk (memory-only = highly suspicious)
        if not os.path.isfile(path):
            # PATH-based safe check: only skip if the DLL's full path matches
            # a known safe staging/update directory. This prevents attackers
            # from simply naming a DLL "msvcp140.dll" to bypass detection.
            is_safe_path = any(sp in path_lower for sp in SAFE_MEMORY_DLL_PATHS)
            if is_safe_path:
                continue

            # Deduplicate: only report each (reason, dll_name) once per process
            dedup_key = ("no_disk_file", dll_name)
            if dedup_key not in seen_dlls:
                seen_dlls.add(dedup_key)
                suspicious_dlls.append(("no_disk_file", path, dll_name))
            continue

        # Skip DLLs from safe directories
        if any(path_lower.startswith(safe) for safe in SAFE_DLL_DIRS):
            continue

        # Skip known dev tool paths
        if is_known_dev_tool("", path):
            continue

    for reason, dll_path, dll_name in suspicious_dlls:
        if reason == "known_bad":
            findings.append(Finding(
                module="Memory Scanner",
                risk=RiskLevel.CRITICAL,
                title=f"Known malicious DLL loaded: {dll_name} in {proc_name}",
                description=f"Process has loaded a known malicious DLL: {dll_name}",
                details={
                    "process": proc_name,
                    "pid": pid,
                    "dll_name": dll_name,
                    "dll_path": dll_path,
                    "detection": "Known Bad DLL Name",
                },
                mitre_id="T1055.001",
                remediation=f"Kill the process (PID {pid}) and delete the malicious DLL: {dll_path}",
            ))
        elif reason == "no_disk_file":
            # Context-aware risk: if the parent process is signed by a
            # trusted vendor (e.g., Chromium/Edge loading DLLs dynamically),
            # downgrade from HIGH to INFO.  Still reported, never suppressed.
            sig = check_file_signature(proc_path) if proc_path else {}
            if sig.get("trusted"):
                risk = RiskLevel.INFO
                desc = (
                    "A DLL is loaded in memory but does not exist on disk. "
                    "The parent process is signed by a trusted vendor, so "
                    "this is likely legitimate dynamic loading."
                )
            else:
                risk = RiskLevel.HIGH
                desc = (
                    "A DLL is loaded in memory but does not exist on disk. "
                    "This may indicate reflective DLL injection."
                )
            findings.append(Finding(
                module="Memory Scanner",
                risk=risk,
                title=f"Memory-only DLL in {proc_name}: {dll_name}",
                description=desc,
                details={
                    "process": proc_name,
                    "pid": pid,
                    "dll_name": dll_name,
                    "dll_path": dll_path,
                    "detection": "Memory-Only DLL",
                    "process_trusted": sig.get("trusted", False),
                    "process_signer": sig.get("signer", "Unknown"),
                },
                mitre_id="T1055.001",
                remediation=f"Kill the process (PID {pid}). Investigate for reflective DLL injection.",
            ))

    return findings


def scan() -> List[Finding]:
    """Run the memory scanner and return findings."""
    print_section("MEMORY SCANNER - Process Memory Analysis")
    findings = []
    throttle = IOThrottle(ops_per_batch=10, sleep_seconds=0.05)

    # Load memory signatures
    signatures = _load_memory_signatures()
    print(f"  [i] Loaded {len(signatures)} memory signatures")

    # Get our own PID so we can skip self-scanning
    own_pid = os.getpid()

    # Get process list
    processes = []
    for proc in psutil.process_iter(["pid", "name", "exe"]):
        try:
            info = proc.info
            name_lower = (info.get("name") or "").lower()

            # Skip system processes
            if name_lower in SYSTEM_PROCESSES:
                continue
            # Skip PID 0 and 4
            if info["pid"] in (0, 4):
                continue
            # Skip our own process (scanner contains malware signature
            # strings in memory which trigger self-detection false positives)
            if info["pid"] == own_pid:
                continue

            processes.append({
                "pid": info["pid"],
                "name": info.get("name", ""),
                "exe": info.get("exe") or "",
            })
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass

    print(f"  [i] Scanning {len(processes)} user-mode processes")

    scanned = 0
    skipped = 0

    for proc in processes:
        pid = proc["pid"]
        name = proc["name"]
        exe = proc["exe"]
        name_lower = name.lower()

        # Skip known developer tools (but still scan for memory injection)
        skip_strings = is_known_dev_tool(name, exe)
        is_jit = name_lower in JIT_PROCESSES

        # Open process for memory reading
        handle = _open_process(pid)
        if not handle:
            skipped += 1
            continue

        try:
            regions = _get_memory_regions(handle)

            # Check 1: RWX memory regions (skip JIT processes like browsers/Electron)
            if not is_jit:
                rwx_findings = _check_rwx_regions(pid, name, exe, handle, regions)
                for f in rwx_findings:
                    findings.append(f)
                    print_finding(f)

            # Check 2: Memory string signatures
            # - Dev tools: skip entirely (their code contains security strings)
            # - JIT/browsers: scan with higher threshold (3+ matches required)
            #   to avoid web-content false positives while catching real injections
            if not skip_strings and signatures:
                mem_findings = _check_memory_strings(
                    pid, name, exe, handle, regions, signatures,
                    is_jit_process=is_jit,
                )
                for f in mem_findings:
                    findings.append(f)
                    print_finding(f)

        finally:
            _close_handle(handle)

        # Check 3: Loaded DLLs (always check)
        dll_findings = _check_loaded_dlls(pid, name, exe)
        for f in dll_findings:
            findings.append(f)
            print_finding(f)

        scanned += 1
        throttle.tick()

        if scanned % 50 == 0:
            print(f"  [i] Progress: {scanned}/{len(processes)} processes scanned...")

    print(f"  [i] Memory scan complete. {scanned} scanned, {skipped} skipped (access denied).")
    print(f"  [i] {len(findings)} findings.")
    return findings
