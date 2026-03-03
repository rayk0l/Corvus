import pytest
from scanner_core.models import Finding, RiskLevel


@pytest.fixture
def sample_finding():
    return Finding(
        module="Test",
        risk=RiskLevel.HIGH,
        title="Test finding",
        description="Test description",
        mitre_id="T1059",
    )


@pytest.fixture
def clean_findings():
    """Temiz sistem — finding yok."""
    return []


@pytest.fixture
def critical_findings():
    """Kritik bulgular seti."""
    return [
        Finding(module="Test", risk=RiskLevel.CRITICAL, title=f"Critical {i}",
                description="test", mitre_id="T1059")
        for i in range(5)
    ]
