"""
credential_scanner.py - Credential exposure detection module.
Scans the filesystem for exposed credentials, API keys, tokens,
and sensitive configuration files left in plaintext.

Checks:
  1. Sensitive files in user directories (.env, credentials.json, id_rsa, etc.)
  2. AWS/Azure/GCP cloud credential files
  3. SSH private keys
  4. Browser saved password databases (existence check only)
  5. Wi-Fi passwords stored in plaintext profiles
  6. Registry-stored application credentials (PuTTY, WinSCP, VNC, FileZilla)

MITRE ATT&CK: T1552 (Unsecured Credentials)
"""

import os
import re
import glob
import subprocess
from typing import List

from scanner_core.utils import (
    Finding, RiskLevel, IOThrottle,
    print_section, print_finding,
)


# ---- Sensitive file patterns to search for ----
# (glob_pattern, description, risk_level, mitre_id)
SENSITIVE_FILE_PATTERNS = [
    # SSH Keys
    ("id_rsa", "SSH private key (RSA)", RiskLevel.HIGH, "T1552.004"),
    ("id_ecdsa", "SSH private key (ECDSA)", RiskLevel.HIGH, "T1552.004"),
    ("id_ed25519", "SSH private key (Ed25519)", RiskLevel.HIGH, "T1552.004"),
    ("id_dsa", "SSH private key (DSA)", RiskLevel.HIGH, "T1552.004"),

    # Environment files with secrets
    (".env", "Environment file (may contain secrets)", RiskLevel.MEDIUM, "T1552.001"),
    (".env.local", "Local environment file", RiskLevel.MEDIUM, "T1552.001"),
    (".env.production", "Production environment file", RiskLevel.HIGH, "T1552.001"),
    (".env.staging", "Staging environment file", RiskLevel.MEDIUM, "T1552.001"),

    # Cloud credentials
    ("credentials", "AWS credentials file", RiskLevel.CRITICAL, "T1552.001"),
    # NOTE: "config" removed from here — too generic, matches .ssh/config etc.
    # AWS config is handled separately in CLOUD_CREDENTIAL_PATHS

    # Application credentials
    ("credentials.json", "Google Cloud credentials", RiskLevel.CRITICAL, "T1552.001"),
    ("service-account.json", "GCP service account key", RiskLevel.CRITICAL, "T1552.001"),
    ("keyfile.json", "Service account key file", RiskLevel.HIGH, "T1552.001"),

    # Database connection files
    ("wp-config.php", "WordPress config (DB credentials)", RiskLevel.HIGH, "T1552.001"),
    ("database.yml", "Rails database config", RiskLevel.MEDIUM, "T1552.001"),
    (".pgpass", "PostgreSQL password file", RiskLevel.HIGH, "T1552.001"),
    (".my.cnf", "MySQL client config", RiskLevel.MEDIUM, "T1552.001"),

    # Other sensitive files
    (".netrc", "FTP/HTTP credentials file", RiskLevel.HIGH, "T1552.001"),
    (".npmrc", "NPM registry token", RiskLevel.MEDIUM, "T1552.001"),
    (".pypirc", "PyPI upload credentials", RiskLevel.MEDIUM, "T1552.001"),
    (".docker/config.json", "Docker registry credentials", RiskLevel.HIGH, "T1552.001"),
    (".kube/config", "Kubernetes config (cluster access)", RiskLevel.CRITICAL, "T1552.001"),

    # VPN/Remote access
    ("*.ovpn", "OpenVPN config (may contain keys)", RiskLevel.MEDIUM, "T1552.004"),
    ("*.rdp", "RDP connection file", RiskLevel.MEDIUM, "T1552.001"),

    # Certificate private keys
    ("*.pem", "PEM certificate/key file", RiskLevel.MEDIUM, "T1552.004"),
    ("*.pfx", "PKCS#12 certificate bundle", RiskLevel.MEDIUM, "T1552.004"),
    ("*.p12", "PKCS#12 certificate bundle", RiskLevel.MEDIUM, "T1552.004"),
    ("*.key", "Private key file", RiskLevel.HIGH, "T1552.004"),
]

# Directories to search (user home covers Desktop/Downloads/Documents)
SEARCH_DIRS = [
    os.path.expanduser("~"),
]

# Files to skip (Windows default files that are normal)
SAFE_SKIP_FILES = {
    "default.rdp",      # Windows default RDP connection file
    "known_hosts",       # SSH known hosts (not a secret)
    "authorized_keys",   # SSH public keys (not a secret)
    "config",            # Too generic — SSH config, app config, etc.
}

# Application-specific key files that are NOT real credentials
SAFE_KEY_FILE_PATTERNS = {
    "relate.secret.key",      # Neo4j Desktop internal key
    "storage.secret.key",     # Application storage key
    "secret.key",             # Django auto-generated key (not user secret)
    "cookie.key",             # Browser cookie encryption key
    "session.key",            # App session key
}

# Specific cloud credential paths to check
CLOUD_CREDENTIAL_PATHS = [
    # AWS
    (os.path.expanduser("~\\.aws\\credentials"), "AWS CLI credentials", RiskLevel.CRITICAL, "T1552.001"),
    (os.path.expanduser("~\\.aws\\config"), "AWS CLI config", RiskLevel.INFO, "T1552.001"),
    # Azure
    (os.path.expanduser("~\\.azure\\accessTokens.json"), "Azure access tokens", RiskLevel.CRITICAL, "T1552.001"),
    (os.path.expanduser("~\\.azure\\azureProfile.json"), "Azure profile", RiskLevel.INFO, "T1552.001"),
    # GCP
    (os.path.expanduser("~\\AppData\\Roaming\\gcloud\\credentials.db"), "GCloud credentials DB", RiskLevel.HIGH, "T1552.001"),
    (os.path.expanduser("~\\AppData\\Roaming\\gcloud\\application_default_credentials.json"), "GCloud default credentials", RiskLevel.CRITICAL, "T1552.001"),
    # Kubernetes
    (os.path.expanduser("~\\.kube\\config"), "Kubernetes cluster config", RiskLevel.HIGH, "T1552.001"),
    # Docker
    (os.path.expanduser("~\\.docker\\config.json"), "Docker registry auth", RiskLevel.HIGH, "T1552.001"),
    # Git
    (os.path.expanduser("~\\.git-credentials"), "Git plaintext credentials", RiskLevel.HIGH, "T1552.001"),
    (os.path.expanduser("~\\.gitconfig"), "Git global config", RiskLevel.INFO, "T1552.001"),
]

# Safe directories to skip (avoid scanning deep into node_modules, .git, etc.)
SKIP_DIRS = {
    "node_modules", ".git", ".svn", ".hg", "__pycache__",
    ".tox", ".venv", "venv", "env", "site-packages",
    ".cache", ".npm", ".yarn", "dist", "build",
    "appdata", ".vscode", ".cursor",
}

MAX_DEPTH = 4  # User home → Desktop/Documents/Downloads → project dirs


def _is_private_key_content(filepath: str) -> bool:
    """Check if a file actually contains a private key header."""
    try:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            header = f.read(256)
        return any(marker in header for marker in [
            "-----BEGIN RSA PRIVATE KEY-----",
            "-----BEGIN EC PRIVATE KEY-----",
            "-----BEGIN PRIVATE KEY-----",
            "-----BEGIN OPENSSH PRIVATE KEY-----",
            "-----BEGIN DSA PRIVATE KEY-----",
            "-----BEGIN ENCRYPTED PRIVATE KEY-----",
        ])
    except (PermissionError, OSError):
        return False


def _check_env_file_has_secrets(filepath: str) -> List[str]:
    """Check if a .env file contains actual secret values."""
    secret_patterns = [
        r"(?i)(api[_-]?key|api[_-]?secret)\s*=\s*\S+",
        r"(?i)(password|passwd|pwd)\s*=\s*\S+",
        r"(?i)(secret[_-]?key|private[_-]?key)\s*=\s*\S+",
        r"(?i)(access[_-]?token|auth[_-]?token)\s*=\s*\S+",
        r"(?i)(database[_-]?url|db[_-]?password)\s*=\s*\S+",
        r"(?i)(aws[_-]?secret|aws[_-]?access)\s*=\s*\S+",
        r"(?i)(stripe|twilio|sendgrid|mailgun)[_-]?\w*\s*=\s*\S+",
    ]
    found_keys = []
    try:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read(8192)  # Read first 8KB
        for pattern in secret_patterns:
            matches = re.findall(pattern, content)
            found_keys.extend(matches)
    except (PermissionError, OSError):
        pass
    return found_keys[:5]  # Return max 5 matches


def _check_aws_credentials(filepath: str) -> bool:
    """Check if AWS credentials file has actual keys (not just config)."""
    try:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read(4096)
        return "aws_secret_access_key" in content.lower() or "aws_access_key_id" in content.lower()
    except (PermissionError, OSError):
        return False


def _scan_wifi_passwords() -> List[Finding]:
    """Check for Wi-Fi passwords stored in plaintext profiles."""
    findings = []
    try:
        result = subprocess.run(
            ["netsh", "wlan", "show", "profiles"],
            capture_output=True, text=True, timeout=10,
            encoding="utf-8", errors="replace"
        )
        profiles = re.findall(r"All User Profile\s*:\s*(.+)", result.stdout)
        if not profiles:
            profiles = re.findall(r"Kullanıcı Profili\s*:\s*(.+)", result.stdout)  # Turkish

        wifi_count = len(profiles)
        if wifi_count > 0:
            # INFO-level finding: Wi-Fi passwords are stored (Windows default behavior)
            findings.append(Finding(
                module="Credential Scanner",
                risk=RiskLevel.INFO,
                title=f"Wi-Fi profiles stored: {wifi_count} networks",
                description=f"Windows stores {wifi_count} Wi-Fi password(s) locally. "
                            "These can be extracted with 'netsh wlan show profile name=X key=clear'.",
                details={
                    "profile_count": wifi_count,
                    "profiles": [p.strip() for p in profiles[:10]],
                    "note": "This is normal Windows behavior but should be noted for security audit",
                },
                mitre_id="T1552.004",
                remediation="Review stored Wi-Fi profiles. Remove profiles no longer needed: "
                            "netsh wlan delete profile name=\"NetworkName\"",
            ))
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        pass
    return findings


def _scan_sensitive_files() -> List[Finding]:
    """Scan user directories for sensitive credential files."""
    findings = []
    throttle = IOThrottle(ops_per_batch=100, sleep_seconds=0.01)
    reported_paths = set()

    for search_dir in SEARCH_DIRS:
        if not os.path.isdir(search_dir):
            continue

        try:
            for root, dirs, files in os.walk(search_dir):
                # Depth check
                depth = root.replace(search_dir, "").count(os.sep)
                if depth > MAX_DEPTH:
                    dirs.clear()
                    continue

                # Skip safe directories
                dirs[:] = [d for d in dirs if d.lower() not in SKIP_DIRS]

                for fname in files:
                    fname_lower = fname.lower()
                    full_path = os.path.join(root, fname)

                    # Skip Windows default files
                    if fname_lower in SAFE_SKIP_FILES:
                        continue

                    # Dedup by real path — symlinks/junctions resolve
                    # to same file. Different dirs = different findings.
                    try:
                        _real = os.path.realpath(full_path).lower()
                    except (OSError, ValueError):
                        _real = full_path.lower()
                    if _real in reported_paths:
                        continue

                    for pattern, desc, risk, mitre in SENSITIVE_FILE_PATTERNS:
                        matched = False
                        if pattern.startswith("*."):
                            # Extension match
                            if fname_lower.endswith(pattern[1:]):
                                matched = True
                        elif "/" in pattern:
                            # Path pattern
                            if full_path.lower().endswith(pattern.lower().replace("/", os.sep)):
                                matched = True
                        else:
                            # Exact filename match
                            if fname_lower == pattern.lower():
                                matched = True

                        if not matched:
                            continue

                        # Validate: don't flag empty files
                        try:
                            fsize = os.path.getsize(full_path)
                            if fsize == 0:
                                continue
                        except OSError:
                            continue

                        # Extra validation for specific file types
                        actual_risk = risk
                        extra_info = {}

                        if fname_lower in ("id_rsa", "id_ecdsa", "id_ed25519", "id_dsa"):
                            if not _is_private_key_content(full_path):
                                continue  # Not actually a private key
                            extra_info["has_private_key_header"] = True

                        elif fname_lower.startswith(".env"):
                            secrets = _check_env_file_has_secrets(full_path)
                            if not secrets:
                                continue  # .env without secrets
                            extra_info["secret_keys_found"] = len(secrets)

                        elif fname_lower == "credentials" and ".aws" in root.lower():
                            if not _check_aws_credentials(full_path):
                                continue

                        elif fname_lower.endswith((".pem", ".key")):
                            # Skip known application key files that aren't real credentials
                            if fname_lower in SAFE_KEY_FILE_PATTERNS:
                                continue
                            if not _is_private_key_content(full_path):
                                continue  # Not a real private key, skip entirely

                        reported_paths.add(_real)
                        finding = Finding(
                            module="Credential Scanner",
                            risk=actual_risk,
                            title=f"Exposed credential: {fname}",
                            description=f"{desc}. Found in user-accessible location.",
                            details={
                                "path": full_path,
                                "file_size": f"{fsize:,} bytes",
                                "type": desc,
                                **extra_info,
                            },
                            mitre_id=mitre,
                            remediation=f"Move '{fname}' to a secure location or encrypt it. "
                                        "Rotate any exposed credentials immediately.",
                        )
                        findings.append(finding)
                        print_finding(finding)
                        break  # One finding per file

                    throttle.tick()
        except (PermissionError, OSError):
            continue

    return findings


def _scan_cloud_credentials() -> List[Finding]:
    """Check specific cloud credential file paths."""
    findings = []

    for cred_path, desc, risk, mitre in CLOUD_CREDENTIAL_PATHS:
        if not os.path.isfile(cred_path):
            continue

        try:
            fsize = os.path.getsize(cred_path)
            if fsize == 0:
                continue
        except OSError:
            continue

        # Extra validation for AWS credentials
        if "aws" in cred_path.lower() and cred_path.endswith("credentials"):
            if not _check_aws_credentials(cred_path):
                continue

        # Skip INFO-level cloud configs (they're normal)
        if risk == RiskLevel.INFO:
            continue

        finding = Finding(
            module="Credential Scanner",
            risk=risk,
            title=f"Cloud credential file: {os.path.basename(cred_path)}",
            description=f"{desc}. This file may contain sensitive cloud access keys.",
            details={
                "path": cred_path,
                "file_size": f"{fsize:,} bytes",
                "cloud_service": desc.split()[0],
            },
            mitre_id=mitre,
            remediation=f"Review '{os.path.basename(cred_path)}' for exposed keys. "
                        "Use environment variables or a secrets manager instead.",
        )
        findings.append(finding)
        print_finding(finding)

    return findings


# ---- Registry-Stored Application Credentials (Sprint 3.2) ----

# Registry paths to check for stored credentials.
# Format: (hive_name, key_path, app_name, description, check_type)
# check_type: "sessions" = count subkeys, "key_exists" = key presence = password stored
_REGISTRY_CREDENTIAL_PATHS = [
    # PuTTY saved sessions
    ("HKCU", r"Software\SimonTatham\PuTTY\Sessions",
     "PuTTY", "PuTTY saved sessions with possible stored credentials", "sessions"),
    # WinSCP saved sessions
    ("HKCU", r"Software\Martin Prikryl\WinSCP 2\Sessions",
     "WinSCP", "WinSCP saved sessions with stored credentials", "sessions"),
    # RealVNC
    ("HKLM", r"Software\RealVNC\WinVNC4",
     "RealVNC", "RealVNC stored connection password", "key_exists"),
    ("HKLM", r"Software\RealVNC\vncserver",
     "RealVNC", "RealVNC server stored password", "key_exists"),
    ("HKCU", r"Software\RealVNC\VNC4",
     "RealVNC", "RealVNC user stored password", "key_exists"),
    # TightVNC
    ("HKCU", r"Software\TightVNC\Server",
     "TightVNC", "TightVNC server stored password", "key_exists"),
    ("HKLM", r"Software\TightVNC\Server",
     "TightVNC", "TightVNC server stored password (system-wide)", "key_exists"),
]

# Hive name → winreg constant mapping
_HIVE_MAP = {}  # Populated at runtime to avoid import error on non-Windows


def _get_hive_map() -> dict:
    """Lazy-init hive mapping (winreg only on Windows)."""
    global _HIVE_MAP
    if not _HIVE_MAP:
        try:
            import winreg
            _HIVE_MAP = {
                "HKCU": winreg.HKEY_CURRENT_USER,
                "HKLM": winreg.HKEY_LOCAL_MACHINE,
            }
        except ImportError:
            pass
    return _HIVE_MAP


def _scan_registry_credentials() -> List[Finding]:
    """Check registry for applications storing credentials.

    Reports EXISTENCE only — never reads or logs actual credential values.
    Uses winreg (stdlib) for registry access.

    Detects: PuTTY, WinSCP, RealVNC, TightVNC saved passwords/sessions.
    Also checks FileZilla sitemanager.xml (file-based, same threat category).

    MITRE: T1552.002 (Credentials in Registry)
    """
    findings = []
    hive_map = _get_hive_map()
    if not hive_map:
        return findings  # Not on Windows

    import winreg

    for hive_name, key_path, app_name, description, check_type in _REGISTRY_CREDENTIAL_PATHS:
        hive = hive_map.get(hive_name)
        if hive is None:
            continue

        try:
            key = winreg.OpenKey(hive, key_path, access=winreg.KEY_READ)
        except FileNotFoundError:
            continue  # App not installed
        except PermissionError:
            continue  # No access
        except OSError:
            continue

        try:
            if check_type == "sessions":
                # Count subkeys (each subkey = a saved session)
                session_count = 0
                try:
                    i = 0
                    while True:
                        sub_name = winreg.EnumKey(key, i)
                        # Skip "Default Settings" in PuTTY — it's not a real session
                        if sub_name.lower() != "default%20settings":
                            session_count += 1
                        i += 1
                except OSError:
                    pass

                if session_count > 0:
                    finding = Finding(
                        module="Credential Scanner",
                        risk=RiskLevel.MEDIUM,
                        title=f"{app_name}: {session_count} saved session(s) found",
                        description=(
                            f"{description}. {session_count} session(s) stored in "
                            "registry. Saved sessions may contain plaintext or "
                            "reversibly encrypted passwords."
                        ),
                        details={
                            "application": app_name,
                            "registry_path": f"{hive_name}\\{key_path}",
                            "session_count": session_count,
                            "note": "Credential values NOT read — existence reported only",
                        },
                        mitre_id="T1552.002",
                        remediation=(
                            f"Review {app_name} saved sessions. Remove stored "
                            "credentials that are no longer needed. Use SSH "
                            "key-based authentication instead."
                        ),
                    )
                    findings.append(finding)
                    print_finding(finding)

            elif check_type == "key_exists":
                # VNC: registry key existing means password is stored
                finding = Finding(
                    module="Credential Scanner",
                    risk=RiskLevel.MEDIUM,
                    title=f"{app_name}: stored password detected",
                    description=(
                        f"{description}. VNC passwords are stored with weak "
                        "encryption (DES) and are easily recoverable by attackers."
                    ),
                    details={
                        "application": app_name,
                        "registry_path": f"{hive_name}\\{key_path}",
                        "note": "Credential values NOT read — existence reported only",
                    },
                    mitre_id="T1552.002",
                    remediation=(
                        f"Change the {app_name} password regularly. Consider "
                        "using VNC over SSH tunnel instead of standalone VNC "
                        "authentication."
                    ),
                )
                findings.append(finding)
                print_finding(finding)

        finally:
            winreg.CloseKey(key)

    # FileZilla (file-based, not registry — but same credential exposure risk)
    filezilla_path = os.path.join(
        os.environ.get("APPDATA", ""), "FileZilla", "sitemanager.xml"
    )
    if os.path.isfile(filezilla_path):
        try:
            fsize = os.path.getsize(filezilla_path)
            if fsize > 0:
                finding = Finding(
                    module="Credential Scanner",
                    risk=RiskLevel.MEDIUM,
                    title="FileZilla: saved site credentials found",
                    description=(
                        "FileZilla sitemanager.xml contains saved FTP/SFTP "
                        "credentials. Passwords are stored in plaintext or "
                        "base64-encoded (easily reversible)."
                    ),
                    details={
                        "application": "FileZilla",
                        "path": filezilla_path,
                        "file_size": f"{fsize:,} bytes",
                        "note": "Credential values NOT read — existence reported only",
                    },
                    mitre_id="T1552.001",
                    remediation=(
                        "Remove saved passwords from FileZilla. Use SSH "
                        "key-based authentication instead of password storage."
                    ),
                )
                findings.append(finding)
                print_finding(finding)
        except OSError:
            pass

    return findings


def scan() -> List[Finding]:
    """Run the credential exposure scanner and return findings."""
    print_section("CREDENTIAL SCANNER - Exposed Secrets Detection")
    findings = []

    # Check cloud credential paths
    print("  [i] Checking cloud credential paths...")
    cloud_findings = _scan_cloud_credentials()
    findings.extend(cloud_findings)
    print(f"  [i] Cloud credentials: {len(cloud_findings)} findings")

    # Scan user directories for sensitive files
    print("  [i] Scanning user directories for exposed credentials...")
    file_findings = _scan_sensitive_files()
    findings.extend(file_findings)
    print(f"  [i] Sensitive files: {len(file_findings)} findings")

    # Check registry for stored application credentials (Sprint 3.2)
    print("  [i] Checking registry for stored application credentials...")
    registry_findings = _scan_registry_credentials()
    findings.extend(registry_findings)
    print(f"  [i] Registry credentials: {len(registry_findings)} findings")

    # Check Wi-Fi passwords
    print("  [i] Checking stored Wi-Fi profiles...")
    wifi_findings = _scan_wifi_passwords()
    findings.extend(wifi_findings)

    print(f"  [i] Credential scan complete. {len(findings)} findings.")
    return findings
