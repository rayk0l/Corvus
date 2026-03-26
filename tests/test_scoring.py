from scanner_core.models import calculate_risk_score, RiskLevel, Finding


def test_clean_system_score_is_100(clean_findings):
    assert calculate_risk_score(clean_findings) == 100


def test_critical_deducts_15(sample_finding):
    sample_finding.risk = RiskLevel.CRITICAL
    assert calculate_risk_score([sample_finding]) == 85


def test_score_never_below_zero(critical_findings):
    # 5 critical × 15 = 75, capped to 30 per module → score = 70
    # But with many modules it can reach 0
    findings = []
    for i in range(10):
        findings.extend([
            Finding(module=f"Mod{i}", risk=RiskLevel.CRITICAL,
                    title=f"C{j}", description="t")
            for j in range(5)
        ])
    assert calculate_risk_score(findings) == 0


def test_score_never_above_100():
    assert calculate_risk_score([]) == 100


def test_info_zero_deduction():
    """INFO findings should NOT affect score at all."""
    findings = [Finding(module="T", risk=RiskLevel.INFO,
                title=f"I{i}", description="t") for i in range(100)]
    assert calculate_risk_score(findings) == 100


def test_module_cap_30():
    """Single module can't deduct more than 30 points."""
    findings = [Finding(module="File Scanner", risk=RiskLevel.CRITICAL,
                title=f"C{i}", description="t") for i in range(10)]
    # 10 × 15 = 150, capped to 30
    assert calculate_risk_score(findings) == 70


def test_multi_module():
    """Multiple modules each capped independently."""
    findings = []
    for mod in ["A", "B", "C"]:
        findings.extend([Finding(module=mod, risk=RiskLevel.HIGH,
                        title="H", description="t") for _ in range(10)])
    # Each module: 10 × 8 = 80, capped to 30 → total = 90
    assert calculate_risk_score(findings) == 10
