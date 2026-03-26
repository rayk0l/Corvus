"""
correlator.py - Cross-module correlation engine.

Combines signals from multiple scanner modules to detect attack chains
that no single module can identify alone. Rule-based (not ML).

Each correlation rule requires findings from 2+ modules to fire.
Output: new Finding objects with module="Correlation Engine".
"""

from typing import List, Dict, Optional
from scanner_core.models import Finding, RiskLevel


# ---------------------------------------------------------------------------
# Correlation Rules
# ---------------------------------------------------------------------------
# Each rule has:
#   name: Human-readable attack chain name
#   description: What this chain means
#   conditions: List of module/title/risk matchers (ALL must match)
#   risk: Risk level for the correlation finding
#   mitre_id: Primary MITRE technique
#
# Condition types:
#   module: Module name to match
#   title_contains: Substring match in finding title (case-insensitive)
#   risk_min: Minimum risk level (CRITICAL < HIGH < MEDIUM < INFO)
#   any: True = any finding from this module matches

_RISK_ORDER = {
    RiskLevel.CRITICAL: 0,
    RiskLevel.HIGH: 1,
    RiskLevel.MEDIUM: 2,
    RiskLevel.INFO: 3,
}

CORRELATION_RULES: List[Dict] = [
    {
        "name": "Active C2 Implant",
        "description": (
            "A process is communicating with a known malicious C2 IP while "
            "persistence mechanisms are active. This strongly indicates an "
            "active compromise with established command-and-control."
        ),
        "conditions": [
            {"module": "Network Scanner", "title_contains": "malicious IP"},
            {"module": "Persistence Scanner", "any": True},
        ],
        "risk": RiskLevel.CRITICAL,
        "mitre_id": "T1071",
    },
    {
        "name": "Credential Theft + Suspicious Network",
        "description": (
            "Exposed credentials detected alongside suspicious outbound "
            "network activity. Stolen credentials may be exfiltrated."
        ),
        "conditions": [
            {"module": "Credential Scanner", "any": True, "risk_min": "MEDIUM"},
            {"module": "Network Scanner", "risk_min": "HIGH"},
        ],
        "risk": RiskLevel.CRITICAL,
        "mitre_id": "T1005",
    },
    {
        "name": "Defense Evasion Chain",
        "description": (
            "Security logging was cleared or disabled AND Windows Defender "
            "has been tampered with. Attackers commonly blind defenses "
            "before executing payloads."
        ),
        "conditions": [
            {"module": "Event Log Scanner", "title_contains": "log cleared"},
            {"module": "Security Config Scanner", "title_contains": "Defender"},
        ],
        "risk": RiskLevel.HIGH,
        "mitre_id": "T1562.001",
    },
    {
        "name": "Packed Binary + Network Activity",
        "description": (
            "A packed/encrypted executable is present alongside suspicious "
            "network connections. Packed binaries communicating externally "
            "are a strong malware indicator."
        ),
        "conditions": [
            {"module": "File Scanner", "title_contains": "Packed"},
            {"module": "Network Scanner", "risk_min": "MEDIUM"},
        ],
        "risk": RiskLevel.HIGH,
        "mitre_id": "T1027.002",
    },
    {
        "name": "LOLBin Abuse + Scheduled Task Persistence",
        "description": (
            "A LOLBin (Living Off the Land Binary) is being abused in "
            "combination with suspicious scheduled tasks. This pattern "
            "is commonly used for fileless persistence."
        ),
        "conditions": [
            {"module": "Process Scanner", "title_contains": "LOLBin"},
            {"module": "Scheduled Task Scanner", "any": True},
        ],
        "risk": RiskLevel.HIGH,
        "mitre_id": "T1218",
    },
    {
        "name": "Suspicious Service + Network Activity",
        "description": (
            "A suspicious service was installed alongside active network "
            "connections. Attackers install services for persistence and "
            "use network for C2/exfiltration."
        ),
        "conditions": [
            {"module": "Event Log Scanner", "title_contains": "service installed"},
            {"module": "Network Scanner", "any": True, "risk_min": "MEDIUM"},
        ],
        "risk": RiskLevel.HIGH,
        "mitre_id": "T1543.003",
    },
    {
        "name": "DLL Hijack + Persistence",
        "description": (
            "DLL hijack vulnerability detected alongside persistence "
            "mechanisms. Attackers exploit DLL search order to load "
            "malicious code via legitimate processes."
        ),
        "conditions": [
            {"module": "DLL Hijack Scanner", "any": True},
            {"module": "Persistence Scanner", "any": True},
        ],
        "risk": RiskLevel.HIGH,
        "mitre_id": "T1574.001",
    },
    {
        "name": "Log Tampering + Malicious Activity",
        "description": (
            "Security logs have been cleared or tampered with, and other "
            "scanners detected suspicious activity. Log tampering is a "
            "strong indicator of active compromise."
        ),
        "conditions": [
            {"module": "Event Log Scanner", "title_contains": "log"},
            {"module": "File Scanner", "risk_min": "HIGH"},
        ],
        "risk": RiskLevel.CRITICAL,
        "mitre_id": "T1070.001",
    },
]


# ---------------------------------------------------------------------------
# Matching Logic
# ---------------------------------------------------------------------------
def _condition_matches(
    condition: Dict,
    module_findings: Dict[str, List[Finding]],
) -> List[Finding]:
    """Check if a single condition matches any findings.

    Returns the list of matching findings (empty if no match).
    """
    module = condition.get("module", "")
    findings = module_findings.get(module, [])
    if not findings:
        return []

    matched = []
    for f in findings:
        # Title substring check
        title_check = condition.get("title_contains")
        if title_check and title_check.lower() not in f.title.lower():
            continue

        # Minimum risk check
        risk_min = condition.get("risk_min")
        if risk_min:
            min_level = RiskLevel(risk_min)
            if _RISK_ORDER[f.risk] > _RISK_ORDER[min_level]:
                continue  # Finding is lower severity than required

        matched.append(f)

    # "any" flag: any finding from the module matches (already filtered above)
    if condition.get("any") and not condition.get("title_contains") and not condition.get("risk_min"):
        return findings  # All findings from this module match

    return matched


def correlate(findings: List[Finding]) -> List[Finding]:
    """Run correlation rules against all findings.

    Args:
        findings: Complete list of findings from all scanner modules.

    Returns:
        List of new correlation Finding objects. These should be APPENDED
        to the main findings list, not replace them.
    """
    if not findings:
        return []

    # Index findings by module name for fast lookup
    module_findings: Dict[str, List[Finding]] = {}
    for f in findings:
        module_findings.setdefault(f.module, []).append(f)

    correlation_findings: List[Finding] = []

    for rule in CORRELATION_RULES:
        # ALL conditions must match for a rule to fire
        all_matched: List[Finding] = []
        rule_fires = True

        for condition in rule["conditions"]:
            matched = _condition_matches(condition, module_findings)
            if not matched:
                rule_fires = False
                break
            all_matched.extend(matched)

        if not rule_fires:
            continue

        # Build correlation finding
        correlated_titles = list(dict.fromkeys(
            f.title for f in all_matched
        ))[:10]  # Deduplicate, max 10

        correlated_modules = list(dict.fromkeys(
            f.module for f in all_matched
        ))

        finding = Finding(
            module="Correlation Engine",
            risk=rule["risk"],
            title=f"Attack Chain: {rule['name']}",
            description=rule["description"],
            details={
                "chain_name": rule["name"],
                "correlated_modules": correlated_modules,
                "correlated_findings": correlated_titles,
                "conditions_matched": len(rule["conditions"]),
            },
            mitre_id=rule["mitre_id"],
            remediation=(
                "This is a correlated alert combining signals from multiple "
                "scanner modules. Investigate each linked finding individually "
                "and assess the overall attack chain."
            ),
        )
        correlation_findings.append(finding)

    return correlation_findings
