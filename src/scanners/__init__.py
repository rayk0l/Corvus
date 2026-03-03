"""
scanners - All scanner modules for the Endpoint Security Scanner.
Each module exports a scan() -> List[Finding] function.
"""

from scanners import (
    file_scanner,
    network_scanner,
    persistence_scanner,
    process_scanner,
    memory_scanner,
    vulnerability_scanner,
    service_scanner,
    eventlog_scanner,
    security_config_scanner,
    dns_scanner,
    port_scanner,
    hosts_scanner,
    ads_scanner,
    pipe_scanner,
    dll_hijack_scanner,
    amcache_scanner,
    prefetch_scanner,
    powershell_history_scanner,
    credential_scanner,
    browser_scanner,
    attack_vector_scanner,
    certificate_store_scanner,
    scheduled_task_scanner,
    usb_scanner,
)

# ---------------------------------------------------------------------------
# Scanner Registry — ordered list of (module, display_name, config_key)
# ---------------------------------------------------------------------------
SCANNER_REGISTRY = [
    (file_scanner,              "File Scanner",            "file_scanner"),
    (network_scanner,           "Network Scanner",         "network_scanner"),
    (persistence_scanner,       "Persistence Scanner",     "persistence_scanner"),
    (process_scanner,           "Process Scanner",         "process_scanner"),
    (memory_scanner,            "Memory Scanner",          "memory_scanner"),
    (vulnerability_scanner,     "Vulnerability Scanner",   "vulnerability_scanner"),
    (service_scanner,           "Service Scanner",         "service_scanner"),
    (eventlog_scanner,          "Event Log Scanner",       "eventlog_scanner"),
    (security_config_scanner,   "Security Config Scanner", "security_config_scanner"),
    (dns_scanner,               "DNS Cache Scanner",       "dns_scanner"),
    (port_scanner,              "Open Port Scanner",       "port_scanner"),
    (hosts_scanner,             "Hosts File Scanner",      "hosts_scanner"),
    (ads_scanner,               "ADS Scanner",             "ads_scanner"),
    (pipe_scanner,              "Named Pipe Scanner",      "pipe_scanner"),
    (dll_hijack_scanner,        "DLL Hijack Scanner",      "dll_hijack_scanner"),
    (amcache_scanner,           "Amcache Scanner",         "amcache_scanner"),
    (prefetch_scanner,          "Prefetch Scanner",        "prefetch_scanner"),
    (powershell_history_scanner,"PS History Scanner",      "powershell_history_scanner"),
    (credential_scanner,        "Credential Scanner",      "credential_scanner"),
    (browser_scanner,           "Browser Scanner",         "browser_scanner"),
    (attack_vector_scanner,     "Attack Vector Scanner",   "attack_vector_scanner"),
    (certificate_store_scanner, "Certificate Store Scanner","certificate_store_scanner"),
    (scheduled_task_scanner,    "Scheduled Task Scanner",  "scheduled_task_scanner"),
    (usb_scanner,               "USB Scanner",             "usb_scanner"),
]

# Modules that are I/O-heavy and skipped in --quick mode
HEAVY_MODULES = {"file_scanner", "memory_scanner", "ads_scanner"}
