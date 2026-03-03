"""
certificate_store_scanner.py - Windows certificate store scanner.

Detects rogue root CAs, expired certificates, weak signature algorithms,
and self-signed certificates from unusual issuers in the Windows trust store.

Checks:
  1. Untrusted root CA issuers not in known-good list
  2. Expired certificates in root store
  3. Weak signature algorithms (MD5, SHA1)
  4. Self-signed certs from unknown issuers

Uses ctypes + crypt32.dll for certificate store access (no subprocess).
READ-ONLY: never modifies the certificate store.

MITRE ATT&CK: T1553.004 (Subvert Trust Controls: Install Root Certificate)
"""

import ctypes
import ctypes.wintypes
from datetime import datetime, timezone
from typing import List, Optional, Tuple

from scanner_core.utils import (
    Finding, RiskLevel,
    print_section, print_finding,
)


# ---------------------------------------------------------------------------
# Known trusted root CA issuers (lowercase for matching)
# These are well-known Certificate Authorities whose root certificates
# are expected in the Windows trust store.
# ---------------------------------------------------------------------------
TRUSTED_ROOT_ISSUERS = {
    # Microsoft
    "microsoft", "microsoft corporation",
    "microsoft root certificate authority",
    "microsoft root certificate authority 2010",
    "microsoft root certificate authority 2011",
    "microsoft root authority",
    "microsoft code signing pca",
    "microsoft code signing pca 2011",
    "microsoft time-stamp pca",
    "microsoft authenticode(tm) root authority",
    "microsoft ecc root certificate authority 2017",
    "microsoft rsa root certificate authority 2017",
    "microsoft identity verification root certificate authority 2020",
    "microsoft ecc product root certificate authority 2018",
    # DigiCert
    "digicert", "digicert global root ca",
    "digicert global root g2", "digicert global root g3",
    "digicert trusted root g4",
    "digicert high assurance ev root ca",
    "digicert assured id root ca",
    "digicert assured id root g2", "digicert assured id root g3",
    # GlobalSign
    "globalsign", "globalsign root ca",
    "globalsign root ca - r2", "globalsign root ca - r3",
    "globalsign root ca - r6",
    "globalsign root e46", "globalsign root r46",
    # Comodo / Sectigo
    "comodo", "comodo rsa certification authority",
    "comodo ecc certification authority",
    "sectigo", "usertrust",
    "usertrust rsa certification authority",
    "usertrust ecc certification authority",
    "aaa certificate services",
    # Let's Encrypt / ISRG
    "isrg root x1", "isrg root x2",
    # GoDaddy / Starfield
    "go daddy root certificate authority - g2",
    "go daddy class 2 certification authority",
    "starfield root certificate authority - g2",
    "starfield class 2 certification authority",
    "starfield services root certificate authority - g2",
    # Entrust
    "entrust", "entrust root certification authority",
    "entrust root certification authority - g2",
    "entrust root certification authority - g4",
    "entrust.net certification authority (2048)",
    # VeriSign (legacy, now Symantec/DigiCert)
    "verisign", "verisign class 3 public primary certification authority - g5",
    "verisign class 3 public primary certification authority - g4",
    "verisign class 3 public primary certification authority - g3",
    "verisign universal root certification authority",
    "class 3 public primary certification authority",
    "class 2 public primary certification authority",
    "class 1 public primary certification authority",
    # Thawte (legacy, now DigiCert)
    "thawte", "thawte primary root ca",
    "thawte primary root ca - g2", "thawte primary root ca - g3",
    "thawte premium server ca", "thawte server ca",
    "thawte timestamping ca",
    # GeoTrust
    "geotrust", "geotrust global ca",
    "geotrust primary certification authority",
    "geotrust primary certification authority - g2",
    "geotrust primary certification authority - g3",
    # Amazon
    "amazon", "amazon root ca 1", "amazon root ca 2",
    "amazon root ca 3", "amazon root ca 4",
    "starfield services root certificate authority",
    # Google Trust Services
    "google trust services llc",
    "gts root r1", "gts root r2", "gts root r3", "gts root r4",
    # Apple
    "apple", "apple root ca", "apple root ca - g2", "apple root ca - g3",
    # Baltimore / CyberTrust
    "baltimore cybertrust root",
    "gte cybertrust global root", "cybertrust global root",
    # DST / IdenTrust
    "dst root ca x3", "identrust",
    "identrust commercial root ca 1",
    # Comodo / AddTrust legacy
    "addtrust external ca root", "addtrust class 1 ca root",
    "addtrust qualified ca root",
    # Starfield legacy
    "starfield technologies", "starfield technologies, inc.",
    # Other well-known CAs
    "certum", "certum ca", "certum trusted network ca",
    "certum trusted network ca 2",
    "actalis authentication root ca",
    "buypass class 2 root ca", "buypass class 3 root ca",
    "quovadis root ca 2", "quovadis root ca 3 g3",
    "t-telesec globalroot class 2", "t-telesec globalroot class 3",
    "swisscom root ca 2", "swisscom root ev ca 2",
    "ssl.com root certification authority rsa",
    "ssl.com root certification authority ecc",
    "ssl.com ev root certification authority rsa r2",
    "atos trustedroot 2011",
    "e-tugra certification authority",
    "e-tugra global root ca rsa v3",
    "e-tugra global root ca ecc v3",
    "certigna", "certigna root ca",
    "hongkong post root ca 3",
    "izenpe.com",
    "oiste wisekey global root gb ca",
    "oiste wisekey global root gc ca",
    "d-trust root class 3 ca 2 2009",
    "d-trust root class 3 ca 2 ev 2009",
    "naver global root certification authority",
    "xramp global certification authority",
    "telia root ca v2",
    "teliasonera root ca v1",
    "emsign root ca - g1", "emsign root ca - c1",
    "emsign ecc root ca - g3", "emsign ecc root ca - c3",
    "harica tls rsa root ca 2021",
    "harica tls ecc root ca 2021",
    "ac raiz fnmt-rcm", "ac raiz fnmt-rcm servidores seguros",
    "autoridad de certificacion firmaprofesional cif a62634068",
    "tubitak kamu sm ssl kok sertifikasi - surum 1",
    "state of the netherlands",
    "governo italiano", "i.ca",
    "netlock", "microsec", "certia",
    "ca disig root r2",
    "trustcor rootcert ca-1", "trustcor rootcert ca-2",
    "trustcor eca-1",
    "security communication rootca2",
    "security communication rootca3",
    "security communication ecc rootca1",
    "secom trust systems co",
}

# Weak signature algorithm OIDs
WEAK_ALGORITHMS = {
    # OID → (friendly_name, risk_level)
    "1.2.840.113549.1.1.2": ("MD2-RSA", RiskLevel.HIGH),
    "1.2.840.113549.1.1.4": ("MD5-RSA", RiskLevel.HIGH),
    "1.2.840.113549.1.1.5": ("SHA1-RSA", RiskLevel.MEDIUM),
    "1.3.14.3.2.29":        ("SHA1-RSA (legacy OID)", RiskLevel.MEDIUM),
}


# ---------------------------------------------------------------------------
# ctypes structures and constants for crypt32.dll
# ---------------------------------------------------------------------------

# Certificate name types for CertGetNameStringW
CERT_NAME_SIMPLE_DISPLAY_TYPE = 4

# Certificate encoding
X509_ASN_ENCODING = 0x00000001
PKCS_7_ASN_ENCODING = 0x00010000
CERT_ENCODING = X509_ASN_ENCODING | PKCS_7_ASN_ENCODING

# Certificate name flags
CERT_NAME_ISSUER_FLAG = 0x1

# FILETIME structure
class FILETIME(ctypes.Structure):
    _fields_ = [
        ("dwLowDateTime", ctypes.wintypes.DWORD),
        ("dwHighDateTime", ctypes.wintypes.DWORD),
    ]


class CRYPT_ALGORITHM_IDENTIFIER(ctypes.Structure):
    _fields_ = [
        ("pszObjId", ctypes.c_char_p),
        ("Parameters_cbData", ctypes.wintypes.DWORD),
        ("Parameters_pbData", ctypes.c_void_p),
    ]


class CRYPT_BIT_BLOB(ctypes.Structure):
    _fields_ = [
        ("cbData", ctypes.wintypes.DWORD),
        ("pbData", ctypes.c_void_p),
        ("cUnusedBits", ctypes.wintypes.DWORD),
    ]


class CRYPT_INTEGER_BLOB(ctypes.Structure):
    _fields_ = [
        ("cbData", ctypes.wintypes.DWORD),
        ("pbData", ctypes.c_void_p),
    ]


class CERT_PUBLIC_KEY_INFO(ctypes.Structure):
    _fields_ = [
        ("Algorithm", CRYPT_ALGORITHM_IDENTIFIER),
        ("PublicKey", CRYPT_BIT_BLOB),
    ]


class CERT_INFO(ctypes.Structure):
    _fields_ = [
        ("dwVersion", ctypes.wintypes.DWORD),
        ("SerialNumber", CRYPT_INTEGER_BLOB),
        ("SignatureAlgorithm", CRYPT_ALGORITHM_IDENTIFIER),
        ("Issuer", CRYPT_INTEGER_BLOB),
        ("NotBefore", FILETIME),
        ("NotAfter", FILETIME),
        ("Subject", CRYPT_INTEGER_BLOB),
        ("SubjectPublicKeyInfo", CERT_PUBLIC_KEY_INFO),
    ]


class CERT_CONTEXT(ctypes.Structure):
    _fields_ = [
        ("dwCertEncodingType", ctypes.wintypes.DWORD),
        ("pbCertEncoded", ctypes.c_void_p),
        ("cbCertEncoded", ctypes.wintypes.DWORD),
        ("pCertInfo", ctypes.POINTER(CERT_INFO)),
        ("hCertStore", ctypes.c_void_p),
    ]


# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------

def _filetime_to_datetime(ft: FILETIME) -> Optional[datetime]:
    """Convert Windows FILETIME to Python datetime (UTC)."""
    try:
        timestamp = (ft.dwHighDateTime << 32) | ft.dwLowDateTime
        if timestamp == 0:
            return None
        # FILETIME epoch: January 1, 1601 (100-nanosecond intervals)
        # Python epoch: January 1, 1970
        # Difference: 11644473600 seconds
        epoch_diff = 11644473600
        seconds = (timestamp / 10_000_000) - epoch_diff
        return datetime.fromtimestamp(seconds, tz=timezone.utc)
    except (OSError, ValueError, OverflowError):
        return None


def _is_trusted_issuer(issuer: str) -> bool:
    """Check if a certificate issuer is in the trusted list.

    Uses exact match and prefix match (same pattern as is_trusted_signer
    in utils.py) to handle variations in CA naming.
    """
    if not issuer:
        return False
    issuer_lower = issuer.strip().lower()
    if not issuer_lower:
        return False

    for trusted in TRUSTED_ROOT_ISSUERS:
        if issuer_lower == trusted:
            return True
        if issuer_lower.startswith(trusted + " "):
            return True
        # Also check if trusted name is contained as a significant prefix
        # e.g., "Microsoft Corporation" matches "microsoft"
        if trusted in issuer_lower.split(",")[0].lower():
            return True

    return False


def _setup_crypt32():
    """Set up crypt32.dll function signatures for 64-bit safety.

    CRITICAL: Without explicit argtypes/restype, ctypes defaults to c_int
    return types which truncates 64-bit pointers, causing access violations.
    """
    try:
        crypt32 = ctypes.windll.crypt32
    except (AttributeError, OSError):
        return None

    # CertOpenSystemStoreW(HCRYPTPROV, LPCWSTR) -> HCERTSTORE
    crypt32.CertOpenSystemStoreW.argtypes = [ctypes.c_void_p, ctypes.c_wchar_p]
    crypt32.CertOpenSystemStoreW.restype = ctypes.c_void_p

    # CertEnumCertificatesInStore(HCERTSTORE, PCCERT_CONTEXT) -> PCCERT_CONTEXT
    crypt32.CertEnumCertificatesInStore.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
    crypt32.CertEnumCertificatesInStore.restype = ctypes.c_void_p

    # CertGetNameStringW(PCCERT_CONTEXT, DWORD, DWORD, void*, LPWSTR, DWORD) -> DWORD
    crypt32.CertGetNameStringW.argtypes = [
        ctypes.c_void_p, ctypes.wintypes.DWORD, ctypes.wintypes.DWORD,
        ctypes.c_void_p, ctypes.c_wchar_p, ctypes.wintypes.DWORD,
    ]
    crypt32.CertGetNameStringW.restype = ctypes.wintypes.DWORD

    # CertCloseStore(HCERTSTORE, DWORD) -> BOOL
    crypt32.CertCloseStore.argtypes = [ctypes.c_void_p, ctypes.wintypes.DWORD]
    crypt32.CertCloseStore.restype = ctypes.wintypes.BOOL

    return crypt32


# Module-level lazy init
_crypt32 = None


def _get_crypt32():
    """Get crypt32 handle with signatures configured (lazy singleton)."""
    global _crypt32
    if _crypt32 is None:
        _crypt32 = _setup_crypt32()
    return _crypt32


def _enumerate_store_certs(store_name: str) -> List[dict]:
    """Enumerate all certificates in a Windows system certificate store.

    Args:
        store_name: Store name ("Root", "AuthRoot", "CA", etc.)

    Returns:
        List of dicts with: subject, issuer, not_before, not_after,
        sig_algorithm_oid, is_self_signed.
    """
    certs = []
    crypt32 = _get_crypt32()
    if crypt32 is None:
        return certs

    # Open the system store
    h_store = crypt32.CertOpenSystemStoreW(None, store_name)
    if not h_store:
        return certs

    try:
        p_context = None  # Start from beginning
        name_buf = ctypes.create_unicode_buffer(256)

        while True:
            p_context = crypt32.CertEnumCertificatesInStore(h_store, p_context)
            if not p_context:
                break

            try:
                # Get subject name
                crypt32.CertGetNameStringW(
                    p_context, CERT_NAME_SIMPLE_DISPLAY_TYPE,
                    0, None, name_buf, 256
                )
                subject = name_buf.value or ""

                # Get issuer name
                crypt32.CertGetNameStringW(
                    p_context, CERT_NAME_SIMPLE_DISPLAY_TYPE,
                    CERT_NAME_ISSUER_FLAG, None, name_buf, 256
                )
                issuer = name_buf.value or ""

                # Access CERT_INFO for dates and algorithm OID
                # CERT_CONTEXT layout:
                #   DWORD dwCertEncodingType (4 bytes)
                #   [padding on 64-bit: 4 bytes]
                #   BYTE* pbCertEncoded (pointer-sized)
                #   DWORD cbCertEncoded (4 bytes)
                #   [padding on 64-bit: 4 bytes]
                #   CERT_INFO* pCertInfo (pointer-sized)
                ptr_size = ctypes.sizeof(ctypes.c_void_p)
                not_before = None
                not_after = None
                sig_oid = ""

                # Use the CERT_CONTEXT structure properly
                cert_ctx = ctypes.cast(
                    p_context, ctypes.POINTER(CERT_CONTEXT)
                ).contents

                if cert_ctx.pCertInfo:
                    cert_info = cert_ctx.pCertInfo.contents
                    not_before = _filetime_to_datetime(cert_info.NotBefore)
                    not_after = _filetime_to_datetime(cert_info.NotAfter)

                    try:
                        raw_oid = cert_info.SignatureAlgorithm.pszObjId
                        if raw_oid:
                            sig_oid = raw_oid.decode("ascii", errors="replace")
                    except (ValueError, AttributeError, OSError):
                        pass

                certs.append({
                    "subject": subject,
                    "issuer": issuer,
                    "not_before": not_before,
                    "not_after": not_after,
                    "sig_algorithm_oid": sig_oid,
                    "is_self_signed": (
                        subject.lower().strip() == issuer.lower().strip()
                        if subject and issuer else False
                    ),
                    "store": store_name,
                })

            except (ValueError, OSError, ctypes.ArgumentError):
                # Skip malformed cert context, continue enumeration
                continue

    except Exception:
        pass
    finally:
        crypt32.CertCloseStore(h_store, 0)

    return certs


# ---------------------------------------------------------------------------
# Main scan
# ---------------------------------------------------------------------------

def scan() -> List[Finding]:
    """Scan Windows certificate stores for rogue or suspicious certificates.

    Checks the Root and AuthRoot certificate stores for:
      1. Untrusted root CA issuers
      2. Expired certificates
      3. Weak signature algorithms (MD5, SHA1)
      4. Self-signed certs from unknown issuers
    """
    print_section("CERTIFICATE STORE SCANNER - Root CA Trust Analysis")
    findings = []

    stores_to_check = ["Root", "AuthRoot"]
    total_certs = 0
    # Dedup across stores: same cert in Root and AuthRoot → report once
    seen_cert_checks: set = set()

    for store_name in stores_to_check:
        print(f"  [i] Scanning '{store_name}' certificate store...")
        certs = _enumerate_store_certs(store_name)
        total_certs += len(certs)
        print(f"  [i] Found {len(certs)} certificates in {store_name}")

        now = datetime.now(tz=timezone.utc)

        for cert in certs:
            subject = cert["subject"]
            issuer = cert["issuer"]
            not_after = cert["not_after"]
            sig_oid = cert["sig_algorithm_oid"]
            is_self_signed = cert["is_self_signed"]

            # Dedup: skip if this exact cert was already checked in another store
            dedup_key = (subject.lower().strip(), issuer.lower().strip(), sig_oid)
            if dedup_key in seen_cert_checks:
                continue
            seen_cert_checks.add(dedup_key)

            # ---- Check 1: Untrusted root CA + self-signed from unknown issuer ----
            if not _is_trusted_issuer(issuer):
                if is_self_signed:
                    # Self-signed from unknown issuer → HIGH (potential rogue root CA)
                    finding = Finding(
                        module="Certificate Store Scanner",
                        risk=RiskLevel.HIGH,
                        title=f"Unknown self-signed root CA: {subject}",
                        description=(
                            f"Self-signed certificate from untrusted issuer "
                            f"'{issuer}' found in {store_name} store. This could "
                            "be a rogue root CA installed by malware or an "
                            "unauthorized proxy for TLS interception."
                        ),
                        details={
                            "subject": subject,
                            "issuer": issuer,
                            "store": store_name,
                            "self_signed": True,
                            "expires": str(not_after) if not_after else "Unknown",
                        },
                        mitre_id="T1553.004",
                        remediation=(
                            "Investigate this root certificate. If you did not "
                            "install it intentionally, remove it from the trusted "
                            "root store using certmgr.msc."
                        ),
                    )
                    findings.append(finding)
                    print_finding(finding)
                else:
                    # Cross-signed from unknown issuer → MEDIUM
                    finding = Finding(
                        module="Certificate Store Scanner",
                        risk=RiskLevel.MEDIUM,
                        title=f"Untrusted root CA issuer: {subject}",
                        description=(
                            f"Certificate issued by '{issuer}' found in "
                            f"{store_name} store. This issuer is not in the "
                            "known trusted CA list."
                        ),
                        details={
                            "subject": subject,
                            "issuer": issuer,
                            "store": store_name,
                            "self_signed": False,
                            "expires": str(not_after) if not_after else "Unknown",
                        },
                        mitre_id="T1553.004",
                        remediation=(
                            "Verify this certificate is legitimate. Check if it "
                            "was installed by your organization's IT department "
                            "or a required application."
                        ),
                    )
                    findings.append(finding)
                    print_finding(finding)

            # ---- Check 2: Expired certificate ----
            if not_after and not_after < now:
                finding = Finding(
                    module="Certificate Store Scanner",
                    risk=RiskLevel.INFO,
                    title=f"Expired root certificate: {subject}",
                    description=(
                        f"Certificate expired on {not_after.strftime('%Y-%m-%d')}. "
                        "Expired root certificates may cause validation errors "
                        "or security warnings."
                    ),
                    details={
                        "subject": subject,
                        "issuer": issuer,
                        "store": store_name,
                        "expired_on": str(not_after),
                    },
                    mitre_id="T1553.004",
                    remediation=(
                        "Expired root certificates are usually harmless but "
                        "should be reviewed. Windows Update typically manages "
                        "root certificate updates automatically."
                    ),
                )
                findings.append(finding)
                print_finding(finding)

            # ---- Check 3: Weak signature algorithm ----
            if sig_oid in WEAK_ALGORITHMS:
                algo_name, default_risk = WEAK_ALGORITHMS[sig_oid]
                # Context-aware: trusted legacy root CAs with SHA1 are
                # expected (Windows ships them).  Downgrade SHA1 to INFO.
                # MD2/MD5 stay HIGH even for trusted CAs (truly obsolete).
                risk = default_risk
                if algo_name.startswith("SHA1"):
                    if _is_trusted_issuer(issuer) or _is_trusted_issuer(subject):
                        risk = RiskLevel.INFO
                finding = Finding(
                    module="Certificate Store Scanner",
                    risk=risk,
                    title=f"Weak signature algorithm ({algo_name}): {subject}",
                    description=(
                        f"Root certificate uses {algo_name} signature algorithm "
                        f"(OID: {sig_oid}). This algorithm is considered "
                        "cryptographically weak and vulnerable to collision attacks."
                    ),
                    details={
                        "subject": subject,
                        "issuer": issuer,
                        "store": store_name,
                        "algorithm": algo_name,
                        "oid": sig_oid,
                    },
                    mitre_id="T1553.004",
                    remediation=(
                        f"Certificates signed with {algo_name} should be "
                        "replaced with SHA-256 or stronger alternatives. "
                        "Contact the certificate issuer for an updated certificate."
                    ),
                )
                findings.append(finding)
                print_finding(finding)

    print(f"  [i] Certificate scan complete. {total_certs} certs checked, "
          f"{len(findings)} findings.")
    return findings
