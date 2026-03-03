from scanner_core.models import calculate_risk_score, RiskLevel, Finding


def test_clean_system_score_is_100(clean_findings):
    assert calculate_risk_score(clean_findings) == 100


def test_critical_deducts_15(sample_finding):
    sample_finding.risk = RiskLevel.CRITICAL
    assert calculate_risk_score([sample_finding]) == 85


def test_score_never_below_zero(critical_findings):
    findings = critical_findings * 10  # 50 critical findings
    assert calculate_risk_score(findings) == 0


def test_score_never_above_100():
    assert calculate_risk_score([]) == 100
