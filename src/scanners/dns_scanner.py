"""
dns_scanner.py - DNS cache scanner module.
Checks the local DNS cache for known malicious domains and
detects potential DGA (Domain Generation Algorithm) domains
and DNS tunneling indicators.
"""

import os
import re
import math
import subprocess
from typing import List, Set
from collections import Counter

from scanner_core.utils import (
    Finding, RiskLevel,
    get_resource_path, print_section, print_finding,
)


def _load_bad_domains() -> Set[str]:
    """Load known malicious domains from IOC file."""
    path = get_resource_path(os.path.join("iocs", "bad_domains.txt"))
    domains = set()
    try:
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip().lower()
                if line and not line.startswith("#"):
                    domains.add(line)
    except FileNotFoundError:
        print("  [!] bad_domains.txt not found")
    return domains


def _get_dns_cache() -> List[dict]:
    """Parse the DNS cache via ipconfig /displaydns."""
    entries = []
    try:
        result = subprocess.run(
            ["ipconfig", "/displaydns"],
            capture_output=True, text=True, timeout=15,
            encoding="utf-8", errors="replace"
        )
        output = result.stdout

        current = {}
        for line in output.split("\n"):
            line = line.strip()
            if "Record Name" in line or "Kayıt Adı" in line:
                if ":" in line:
                    name = line.split(":", 1)[1].strip().lower()
                    current = {"name": name}
            elif ("Record Type" in line or "Kayıt Türü" in line) and current:
                if ":" in line:
                    current["type"] = line.split(":", 1)[1].strip()
            elif ("(Host) Record" in line or "A (Ana" in line) and current:
                if ":" in line:
                    current["data"] = line.split(":", 1)[1].strip()
                    entries.append(current)
                    current = {}
            elif line == "" and current.get("name"):
                if "data" not in current:
                    current["data"] = ""
                entries.append(current)
                current = {}

    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        pass

    return entries


def _calculate_entropy(domain: str) -> float:
    """Calculate Shannon entropy of a domain name (excluding TLD)."""
    # Remove TLD
    parts = domain.split(".")
    if len(parts) > 1:
        name = ".".join(parts[:-1])
    else:
        name = domain

    if not name:
        return 0.0

    freq = Counter(name)
    length = len(name)
    entropy = -sum((count/length) * math.log2(count/length) for count in freq.values())
    return entropy


def _is_potential_dga(domain: str) -> bool:
    """Check if a domain looks like DGA-generated."""
    parts = domain.split(".")

    # Skip very short domains and known safe TLDs
    if len(parts) < 2:
        return False

    # Get the second-level domain
    sld = parts[-2] if len(parts) >= 2 else parts[0]

    # DGA indicators:
    # 1. High entropy (random-looking characters)
    entropy = _calculate_entropy(sld)
    if entropy < 3.5:
        return False

    # 2. Long second-level domain
    if len(sld) < 10:
        return False

    # 3. High ratio of consonants (random strings tend to have this)
    vowels = set("aeiou")
    consonant_ratio = sum(1 for c in sld if c.isalpha() and c not in vowels) / max(len(sld), 1)

    # 4. Contains mostly alphanumeric with numbers mixed in
    digit_ratio = sum(1 for c in sld if c.isdigit()) / max(len(sld), 1)

    # Combined heuristic
    if entropy > 4.0 and len(sld) > 12:
        return True
    if entropy > 3.5 and digit_ratio > 0.3:
        return True
    if entropy > 3.8 and consonant_ratio > 0.7:
        return True

    return False


def _is_dns_tunneling_indicator(domain: str) -> bool:
    """Check if a domain shows DNS tunneling characteristics."""
    # DNS tunneling uses very long subdomains to encode data
    parts = domain.split(".")

    if len(parts) < 3:
        return False

    # Check for very long subdomain labels
    for part in parts[:-2]:
        if len(part) > 50:
            return True

    # Check total length
    total_subdomain_len = sum(len(p) for p in parts[:-2])
    if total_subdomain_len > 100:
        return True

    # Check for base64-like patterns in subdomains
    subdomain = ".".join(parts[:-2])
    if re.match(r'^[A-Za-z0-9+/=]{30,}', subdomain):
        return True

    return False


# Safe domains to skip (includes CDN, cloud, analytics, telemetry)
SAFE_DOMAINS = {
    # Microsoft
    "microsoft.com", "windows.com", "windowsupdate.com", "msftncsi.com",
    "msedge.net", "msn.com", "live.com", "outlook.com", "office.com",
    "office.net", "office365.com", "microsoftonline.com",
    "azure.com", "azureedge.net", "azurefd.net", "cloudapp.net",
    "bing.com", "linkedin.com", "skype.com", "teams.microsoft.com",
    "windows.net", "msauth.net", "msftauth.net", "visualstudio.com",
    "vscode.dev", "trafficmanager.net", "vo.msecnd.net",
    # Google
    "google.com", "googleapis.com", "gstatic.com", "googlevideo.com",
    "youtube.com", "ytimg.com", "googleusercontent.com",
    "googlesyndication.com", "doubleclick.net", "gvt1.com", "gvt2.com",
    "google-analytics.com", "googletagmanager.com", "1e100.net",
    "crashlytics.com", "firebaseio.com", "firebase.google.com",
    # Apple
    "apple.com", "icloud.com", "apple-dns.net", "cdn-apple.com",
    # Amazon / AWS
    "amazon.com", "amazonaws.com", "cloudfront.net", "amazontrust.com",
    "a2z.com", "awsstatic.com", "elasticbeanstalk.com", "elb.amazonaws.com",
    # Meta
    "facebook.com", "fbcdn.net", "instagram.com", "whatsapp.net",
    # Twitter/X
    "twitter.com", "twimg.com", "x.com",
    # GitHub
    "github.com", "githubusercontent.com", "github.io", "githubassets.com",
    # CDNs & Infrastructure
    "cloudflare.com", "cloudflare-dns.com", "cdnjs.cloudflare.com", "pacloudflare.com",
    "cloudflareinsights.com", "cloudflareclient.com", "cloudflarestream.com",
    "cloudflareaccess.com", "cloudflaressl.com",
    "akamaiedge.net", "akamaitechnologies.com", "akamai.net",
    "fastly.net", "edgecastcdn.net", "stackpathdns.com",
    # Certificate Authorities
    "digicert.com", "verisign.com", "letsencrypt.org", "sectigo.com",
    "globalsign.com", "entrust.net", "usertrust.com",
    # Communication apps
    "zoom.us", "slack.com", "discord.com", "discord.gg",
    "notion.so", "figma.com",
    # Development
    "npmjs.org", "npmjs.com", "pypi.org", "docker.com", "docker.io",
    "jetbrains.com", "stackoverflow.com",
    # Telemetry & Analytics (legitimate)
    "sentry.io", "amplitude.com", "segment.io", "mixpanel.com",
    "datadoghq.com", "nr-data.net", "newrelic.com",
    # Other common
    "mozilla.org", "mozilla.net",
    "spotify.com", "steampowered.com",
    "localhost", "local",
}


def _is_safe_domain(domain: str) -> bool:
    """Check if a domain is in the safe list."""
    parts = domain.split(".")
    for i in range(len(parts)):
        parent = ".".join(parts[i:])
        if parent in SAFE_DOMAINS:
            return True
    return False


def scan() -> List[Finding]:
    """Run the DNS cache scanner and return findings."""
    print_section("DNS CACHE SCANNER - Malicious Domain & DGA Detection")
    findings = []

    bad_domains = _load_bad_domains()
    print(f"  [i] Loaded {len(bad_domains)} known malicious domains")

    print("  [i] Parsing DNS cache...")
    dns_entries = _get_dns_cache()
    print(f"  [i] Found {len(dns_entries)} DNS cache entries")

    reported_domains = set()

    for entry in dns_entries:
        domain = entry.get("name", "").lower()
        if not domain or domain in reported_domains:
            continue

        # Skip safe domains
        if _is_safe_domain(domain):
            continue

        # --- Check 1: Known malicious domain ---
        if domain in bad_domains or any(bd in domain for bd in bad_domains):
            reported_domains.add(domain)
            finding = Finding(
                module="DNS Scanner",
                risk=RiskLevel.CRITICAL,
                title=f"Known malicious domain in DNS cache: {domain}",
                description="This domain matches a known C2/malware/phishing domain.",
                details={
                    "domain": domain,
                    "resolved_ip": entry.get("data", ""),
                    "source": "DNS Cache",
                },
                mitre_id="T1071.001",
                remediation=f"Block the domain '{domain}' in the firewall/DNS. Investigate the system for compromise.",
            )
            findings.append(finding)
            print_finding(finding)
            continue

        # --- Check 2: DNS tunneling indicator ---
        if _is_dns_tunneling_indicator(domain):
            reported_domains.add(domain)
            finding = Finding(
                module="DNS Scanner",
                risk=RiskLevel.MEDIUM,
                title=f"Possible DNS tunneling: {domain[:80]}...",
                description="Domain has unusually long subdomains, which is a characteristic of DNS tunneling.",
                details={
                    "domain": domain[:200],
                    "total_length": len(domain),
                    "resolved_ip": entry.get("data", ""),
                },
                mitre_id="T1071.004",
                remediation="Block the domain. Monitor DNS traffic for data exfiltration.",
            )
            findings.append(finding)
            print_finding(finding)
            continue

        # --- Check 3: DGA domain detection ---
        if _is_potential_dga(domain):
            reported_domains.add(domain)
            sld = domain.split(".")[-2] if len(domain.split(".")) >= 2 else domain
            finding = Finding(
                module="DNS Scanner",
                risk=RiskLevel.MEDIUM,
                title=f"Potential DGA domain: {domain}",
                description="Domain has high entropy and appears algorithmically generated.",
                details={
                    "domain": domain,
                    "entropy": round(_calculate_entropy(sld), 2),
                    "resolved_ip": entry.get("data", ""),
                },
                mitre_id="T1568.002",
                remediation=f"Block the domain '{domain}'. Scan for malware using DGA-based C2 communication.",
            )
            findings.append(finding)
            print_finding(finding)

    print(f"  [i] DNS scan complete. {len(findings)} findings.")
    return findings
