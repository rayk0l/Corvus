"""
browser_scanner.py - Browser extension and security scanner module.
Analyzes installed browser extensions for malicious or suspicious behavior.

Checks:
  1. Chrome/Edge/Brave extensions — manifest analysis
  2. Known malicious extension IDs
  3. Suspicious permissions (access all sites, read cookies, keylogging)
  4. Sideloaded extensions (not from official store)

MITRE ATT&CK: T1176 (Browser Extensions)
"""

import os
import json
import glob
from typing import List, Dict, Optional

from scanner_core.utils import (
    Finding, RiskLevel, IOThrottle,
    print_section, print_finding,
)


# ---- Known malicious extension IDs (partial list) ----
# These are extensions that have been flagged by security researchers
KNOWN_MALICIOUS_IDS = {
    # Known cryptominers and stealers
    "ejdhbfahajfpejmgbmeakchbkghlekhcf",  # Example malicious
    "lgjogljbnbfjcaigalbhiagkfigcckpg",  # Known stealer
}

# ---- Suspicious permission keywords ----
# High-risk permissions that warrant investigation
HIGH_RISK_PERMISSIONS = {
    "<all_urls>": ("Access ALL websites", RiskLevel.MEDIUM),
    "http://*/*": ("Access all HTTP sites", RiskLevel.INFO),
    "https://*/*": ("Access all HTTPS sites", RiskLevel.INFO),
    "webRequest": ("Intercept web requests", RiskLevel.MEDIUM),
    "webRequestBlocking": ("Block/modify web requests", RiskLevel.MEDIUM),
    "cookies": ("Read/write cookies", RiskLevel.MEDIUM),
    "clipboardRead": ("Read clipboard", RiskLevel.MEDIUM),
    "clipboardWrite": ("Write clipboard", RiskLevel.INFO),
    "nativeMessaging": ("Communicate with native apps", RiskLevel.MEDIUM),
    "debugger": ("Chrome debugger API access", RiskLevel.HIGH),
    "desktopCapture": ("Capture screen content", RiskLevel.MEDIUM),
    "input": ("Monitor keyboard input", RiskLevel.HIGH),
    "proxy": ("Control proxy settings", RiskLevel.MEDIUM),
    "privacy": ("Modify privacy settings", RiskLevel.MEDIUM),
    "management": ("Manage other extensions", RiskLevel.MEDIUM),
}

# Known safe/popular extensions by ID
KNOWN_SAFE_EXTENSIONS = {
    # Password managers
    "nngceckbapebfimnlniiiahkandclblb",  # Bitwarden
    "aeblfdkhhhdcdjpifhhbdiojplfjncoa",  # 1Password
    "hdokiejnpimakedhajhdlcegeplioahd",  # LastPass
    # Ad blockers
    "cjpalhdlnbpafiamejdnhcphjbkeiagm",  # uBlock Origin
    "gighmmpiobklfepjocnamgkkbiglidom",  # AdBlock
    "cfhdojbkjhnklbpkdaibdccddilifddb",  # Adblock Plus
    # Development
    "fmkadmapgofadopljbjfkapdkoienihi",  # React DevTools
    "nhdogjmejiglipccpnnnanhbledajbpd",  # Vue DevTools
    "lmhkpmbekcpmknklioeibfkpmmfibljd",  # Redux DevTools
    "bhlhnicpbhignbdhedgjhgdocnmhomnp",  # ColorZilla
    # Productivity
    "aapbdbdomjkkjkaonfhkkikfgjllcleb",  # Google Translate
    "ghbmnnjooekpmoecnnnilnnbfdlolhkhi", # Google Docs Offline
    "efaidnbmnnnibpcajpcglclefindmkaj",  # Adobe Acrobat
    # Privacy
    "gcbommkclmhbdajafcjcbiipbpfbmpcd",  # HTTPS Everywhere (archive)
    "pkehgijcmpdhfbdbbnkijodmdjhbjlgp",  # Privacy Badger
    "ogfcmafjalglgifnmanfmniipnlkdmnk",  # uMatrix
    # AI Assistants
    "fcoeoabgfenejglbffodgkkbkcdhcgfn",  # Claude (Anthropic)
    # Enterprise security / corporate tools
    "pbbjjnjikpfdhmafpjooclchedndmkdl",  # Fortinet Privileged Access Agent
    "eloipddcgcnhmfcckfbhjeikfjidpml",   # Fortinet FortiClient
    "jknemblkbdhdcpllfgbfekkdciegfboi",  # Cisco Umbrella
    "noondiphcddnnabmjcihcjfbhfklnnep",  # Microsoft Defender Browser Protection
    "ghbmnnjooekpmoecnnnilnnbfdlolhkhi", # Google Docs Offline (also here)
    "aapocclcgogkmnckokdopfmhonfmgoek",  # Google Slides
}

# Browser extension directories
BROWSER_PATHS = [
    {
        "name": "Google Chrome",
        "path": os.path.join(os.environ.get("LOCALAPPDATA", ""), "Google", "Chrome", "User Data"),
        "browser": "chrome",
    },
    {
        "name": "Microsoft Edge",
        "path": os.path.join(os.environ.get("LOCALAPPDATA", ""), "Microsoft", "Edge", "User Data"),
        "browser": "edge",
    },
    {
        "name": "Brave Browser",
        "path": os.path.join(os.environ.get("LOCALAPPDATA", ""), "BraveSoftware", "Brave-Browser", "User Data"),
        "browser": "brave",
    },
    {
        "name": "Opera",
        "path": os.path.join(os.environ.get("APPDATA", ""), "Opera Software", "Opera Stable"),
        "browser": "opera",
    },
]


def _get_extension_dirs(browser_data_path: str) -> List[str]:
    """Find all extension directories across all profiles."""
    ext_dirs = []

    # Default profile
    default_ext = os.path.join(browser_data_path, "Default", "Extensions")
    if os.path.isdir(default_ext):
        ext_dirs.append(default_ext)

    # Numbered profiles (Profile 1, Profile 2, etc.)
    for item in glob.glob(os.path.join(browser_data_path, "Profile *", "Extensions")):
        if os.path.isdir(item):
            ext_dirs.append(item)

    return ext_dirs


def _parse_manifest(manifest_path: str) -> Optional[Dict]:
    """Parse a Chrome extension manifest.json."""
    try:
        with open(manifest_path, "r", encoding="utf-8", errors="ignore") as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError):
        return None


def _analyze_extension(ext_id: str, ext_path: str, browser_name: str) -> List[Finding]:
    """Analyze a single browser extension for suspicious indicators."""
    findings = []

    # Find the latest version directory
    versions = []
    try:
        for item in os.listdir(ext_path):
            ver_path = os.path.join(ext_path, item)
            if os.path.isdir(ver_path):
                manifest_path = os.path.join(ver_path, "manifest.json")
                if os.path.isfile(manifest_path):
                    versions.append((item, ver_path, manifest_path))
    except OSError:
        return findings

    if not versions:
        return findings

    # Use latest version
    versions.sort(reverse=True)
    ver_str, ver_path, manifest_path = versions[0]

    manifest = _parse_manifest(manifest_path)
    if not manifest:
        return findings

    ext_name = manifest.get("name", "Unknown Extension")
    ext_version = manifest.get("version", "?")
    ext_desc = manifest.get("description", "")[:100]

    # Skip system/component extensions
    if ext_name.startswith("__MSG_") or ext_name in ("Chrome PDF Viewer", "Chrome Web Store"):
        return findings

    # Skip known safe extensions
    if ext_id in KNOWN_SAFE_EXTENSIONS:
        return findings

    # Check 1: Known malicious extension ID
    if ext_id in KNOWN_MALICIOUS_IDS:
        finding = Finding(
            module="Browser Scanner",
            risk=RiskLevel.CRITICAL,
            title=f"Known malicious extension: {ext_name}",
            description=f"Extension '{ext_name}' (ID: {ext_id}) is flagged as malicious.",
            details={
                "extension_id": ext_id,
                "name": ext_name,
                "version": ext_version,
                "browser": browser_name,
                "path": ext_path,
            },
            mitre_id="T1176",
            remediation=f"Remove the extension immediately from {browser_name}. "
                        "Check for data exfiltration.",
        )
        findings.append(finding)
        print_finding(finding)
        return findings

    # Check 2: Analyze permissions
    permissions = set()
    for key in ("permissions", "optional_permissions"):
        perms = manifest.get(key, [])
        if isinstance(perms, list):
            permissions.update(perms)

    # Also check host_permissions (Manifest V3)
    host_perms = manifest.get("host_permissions", [])
    if isinstance(host_perms, list):
        permissions.update(host_perms)

    # Count high-risk permissions
    risky_perms = []
    max_risk = RiskLevel.INFO
    for perm in permissions:
        if perm in HIGH_RISK_PERMISSIONS:
            desc, risk = HIGH_RISK_PERMISSIONS[perm]
            risky_perms.append(f"{perm} ({desc})")
            if risk.order < max_risk.order:
                max_risk = risk

    # Check 3: Sideloaded extension (not from web store)
    is_sideloaded = False
    update_url = manifest.get("update_url", "")
    if not update_url:
        is_sideloaded = True
    elif "clients2.google.com" not in update_url and "edge.microsoft.com" not in update_url:
        is_sideloaded = True

    # Check 4: Suspicious content scripts matching all URLs
    content_scripts = manifest.get("content_scripts", [])
    matches_all = False
    for cs in content_scripts:
        match_patterns = cs.get("matches", [])
        if any(p in ("<all_urls>", "http://*/*", "https://*/*", "*://*/*") for p in match_patterns):
            matches_all = True

    # Decision: flag extensions with many risky permissions OR sideloaded
    # Only flag if it has notable risk indicators
    risk_indicators = 0
    if len(risky_perms) >= 3:
        risk_indicators += 1
    if is_sideloaded:
        risk_indicators += 1
    if matches_all and len(risky_perms) >= 2:
        risk_indicators += 1
    if "debugger" in permissions or "input" in permissions:
        risk_indicators += 2  # Very suspicious

    if risk_indicators >= 2:
        risk = max_risk if max_risk.order <= RiskLevel.MEDIUM.order else RiskLevel.MEDIUM
        if is_sideloaded:
            title = f"Sideloaded extension with risky permissions: {ext_name}"
            desc_text = (f"Extension '{ext_name}' is sideloaded (not from official store) "
                        f"and requests {len(risky_perms)} high-risk permission(s).")
        else:
            title = f"Extension with high-risk permissions: {ext_name}"
            desc_text = (f"Extension '{ext_name}' requests {len(risky_perms)} "
                        f"high-risk permission(s) that could be used for data theft.")

        finding = Finding(
            module="Browser Scanner",
            risk=risk,
            title=title,
            description=desc_text,
            details={
                "extension_id": ext_id,
                "name": ext_name,
                "version": ext_version,
                "browser": browser_name,
                "sideloaded": is_sideloaded,
                "risky_permissions": risky_perms[:10],
                "total_permissions": len(permissions),
                "matches_all_urls": matches_all,
            },
            mitre_id="T1176",
            remediation=f"Review the extension '{ext_name}' in {browser_name}. "
                        "Remove if not recognized or no longer needed.",
        )
        findings.append(finding)
        print_finding(finding)

    return findings


def scan() -> List[Finding]:
    """Run the browser extension scanner and return findings."""
    print_section("BROWSER SCANNER - Extension Security Analysis")
    findings = []
    total_extensions = 0

    for browser_info in BROWSER_PATHS:
        browser_name = browser_info["name"]
        browser_data = browser_info["path"]

        if not os.path.isdir(browser_data):
            continue

        print(f"  [i] Scanning {browser_name} extensions...")
        ext_dirs = _get_extension_dirs(browser_data)

        browser_ext_count = 0
        for ext_dir in ext_dirs:
            try:
                for ext_id in os.listdir(ext_dir):
                    ext_path = os.path.join(ext_dir, ext_id)
                    if not os.path.isdir(ext_path):
                        continue

                    # Skip Chrome's internal extension storage structure
                    if ext_id.startswith("Temp") or len(ext_id) != 32:
                        continue

                    ext_findings = _analyze_extension(ext_id, ext_path, browser_name)
                    findings.extend(ext_findings)
                    browser_ext_count += 1
            except (PermissionError, OSError):
                continue

        total_extensions += browser_ext_count
        print(f"  [i] {browser_name}: {browser_ext_count} extensions analyzed")

    if total_extensions == 0:
        print("  [i] No supported browsers found or no extensions installed.")

    print(f"  [i] Browser scan complete. {total_extensions} extensions, {len(findings)} findings.")
    return findings
