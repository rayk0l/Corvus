"""
models.py - Core data structures for the security scanner.
Defines risk levels, finding dataclass, and risk score calculation.
"""

import enum
from dataclasses import dataclass, field


# ---------------------------------------------------------------------------
# Risk Levels
# ---------------------------------------------------------------------------
class RiskLevel(enum.Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    INFO = "INFO"

    @property
    def color(self):
        return {
            RiskLevel.CRITICAL: "#ff4757",
            RiskLevel.HIGH: "#ff6b35",
            RiskLevel.MEDIUM: "#ffa502",
            RiskLevel.INFO: "#3498db",
        }[self]

    @property
    def order(self):
        return {
            RiskLevel.CRITICAL: 0,
            RiskLevel.HIGH: 1,
            RiskLevel.MEDIUM: 2,
            RiskLevel.INFO: 3,
        }[self]


# ---------------------------------------------------------------------------
# Finding Data Structure
# ---------------------------------------------------------------------------
@dataclass
class Finding:
    module: str
    risk: RiskLevel
    title: str
    description: str
    details: dict = field(default_factory=dict)
    mitre_id: str = ""
    remediation: str = ""


# ---------------------------------------------------------------------------
# Risk Score Calculation (single source of truth)
# ---------------------------------------------------------------------------
def calculate_risk_score(findings: list) -> int:
    """
    Calculate a security risk score (0-100).
    100 = perfectly clean system, 0 = critically compromised.

    Deductions: CRITICAL=-15, HIGH=-8, MEDIUM=-3, INFO=-1
    """
    score = 100
    for f in findings:
        if f.risk == RiskLevel.CRITICAL:
            score -= 15
        elif f.risk == RiskLevel.HIGH:
            score -= 8
        elif f.risk == RiskLevel.MEDIUM:
            score -= 3
        elif f.risk == RiskLevel.INFO:
            score -= 1
    return max(0, min(100, score))
