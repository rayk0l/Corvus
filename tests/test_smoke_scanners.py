"""
Module smoke tests — Sprint 2.4.

Every scanner module: import OK, scan() returns List[Finding], no crash.
Modules that require admin or specific system state gracefully return []
when those resources are unavailable (PermissionError, etc.).

Heavy I/O modules (file_scanner, memory_scanner, ads_scanner) are marked
with @pytest.mark.slow so they can be skipped via: pytest -m "not slow"
"""

import os
import sys
import pytest

# Ensure src/ is first on path so scanners resolves to src/scanners
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from scanner_core.models import Finding, RiskLevel

# All scanner smoke tests require Windows APIs
pytestmark = pytest.mark.skipif(
    sys.platform != "win32",
    reason="Scanner modules require Windows APIs",
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _assert_scan_contract(module) -> None:
    """Verify the scan() contract for a scanner module."""
    assert hasattr(module, "scan"), f"{module.__name__} missing scan() function"
    assert callable(module.scan), f"{module.__name__}.scan is not callable"

    findings = module.scan()

    assert isinstance(findings, list), (
        f"{module.__name__}.scan() returned {type(findings).__name__}, expected list"
    )
    for i, f in enumerate(findings):
        assert isinstance(f, Finding), (
            f"{module.__name__}.scan()[{i}] is {type(f).__name__}, expected Finding"
        )
        # Verify required fields are populated
        assert f.module, f"Finding[{i}].module is empty"
        assert isinstance(f.risk, RiskLevel), f"Finding[{i}].risk is not RiskLevel"
        assert f.title, f"Finding[{i}].title is empty"
        assert f.description, f"Finding[{i}].description is empty"


# ---------------------------------------------------------------------------
# Smoke tests — lightweight modules
# ---------------------------------------------------------------------------

def test_network_scanner_smoke():
    from scanners import network_scanner
    _assert_scan_contract(network_scanner)


def test_persistence_scanner_smoke():
    from scanners import persistence_scanner
    _assert_scan_contract(persistence_scanner)


def test_process_scanner_smoke():
    from scanners import process_scanner
    _assert_scan_contract(process_scanner)


def test_vulnerability_scanner_smoke():
    from scanners import vulnerability_scanner
    _assert_scan_contract(vulnerability_scanner)


def test_service_scanner_smoke():
    from scanners import service_scanner
    _assert_scan_contract(service_scanner)


def test_eventlog_scanner_smoke():
    from scanners import eventlog_scanner
    _assert_scan_contract(eventlog_scanner)


def test_security_config_scanner_smoke():
    from scanners import security_config_scanner
    _assert_scan_contract(security_config_scanner)


def test_dns_scanner_smoke():
    from scanners import dns_scanner
    _assert_scan_contract(dns_scanner)


def test_port_scanner_smoke():
    from scanners import port_scanner
    _assert_scan_contract(port_scanner)


def test_hosts_scanner_smoke():
    from scanners import hosts_scanner
    _assert_scan_contract(hosts_scanner)


def test_pipe_scanner_smoke():
    from scanners import pipe_scanner
    _assert_scan_contract(pipe_scanner)


def test_dll_hijack_scanner_smoke():
    from scanners import dll_hijack_scanner
    _assert_scan_contract(dll_hijack_scanner)


def test_amcache_scanner_smoke():
    from scanners import amcache_scanner
    _assert_scan_contract(amcache_scanner)


def test_prefetch_scanner_smoke():
    from scanners import prefetch_scanner
    _assert_scan_contract(prefetch_scanner)


def test_powershell_history_scanner_smoke():
    from scanners import powershell_history_scanner
    _assert_scan_contract(powershell_history_scanner)


def test_credential_scanner_smoke():
    from scanners import credential_scanner
    _assert_scan_contract(credential_scanner)


def test_browser_scanner_smoke():
    from scanners import browser_scanner
    _assert_scan_contract(browser_scanner)


def test_attack_vector_scanner_smoke():
    from scanners import attack_vector_scanner
    _assert_scan_contract(attack_vector_scanner)


def test_certificate_store_scanner_smoke():
    from scanners import certificate_store_scanner
    _assert_scan_contract(certificate_store_scanner)


def test_scheduled_task_scanner_smoke():
    from scanners import scheduled_task_scanner
    _assert_scan_contract(scheduled_task_scanner)


def test_usb_scanner_smoke():
    from scanners import usb_scanner
    _assert_scan_contract(usb_scanner)


# ---------------------------------------------------------------------------
# Smoke tests — HEAVY modules (slow I/O, mark for optional skip)
# ---------------------------------------------------------------------------

@pytest.mark.slow
def test_file_scanner_smoke():
    from scanners import file_scanner
    _assert_scan_contract(file_scanner)


@pytest.mark.slow
def test_memory_scanner_smoke():
    from scanners import memory_scanner
    _assert_scan_contract(memory_scanner)


@pytest.mark.slow
def test_ads_scanner_smoke():
    from scanners import ads_scanner
    _assert_scan_contract(ads_scanner)


# ---------------------------------------------------------------------------
# Meta test — verify SCANNER_REGISTRY completeness
# ---------------------------------------------------------------------------

def test_scanner_registry_matches_module_count():
    """Ensure SCANNER_REGISTRY has all expected modules."""
    from scanners import SCANNER_REGISTRY

    registry_keys = {config_key for _, _, config_key in SCANNER_REGISTRY}
    # All 24 modules should be in the registry
    assert len(registry_keys) == 24, (
        f"Expected 24 modules in SCANNER_REGISTRY, found {len(registry_keys)}"
    )

    # Verify each registered module has scan() callable
    for mod, display_name, config_key in SCANNER_REGISTRY:
        assert hasattr(mod, "scan"), (
            f"SCANNER_REGISTRY module '{display_name}' ({config_key}) missing scan()"
        )
        assert callable(mod.scan), (
            f"SCANNER_REGISTRY module '{display_name}' ({config_key}) scan is not callable"
        )
