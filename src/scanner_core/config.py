"""
config.py - Configuration loader for the security scanner.
Loads settings from config.json with safe defaults for all values.
"""

import os
import json
from scanner_core.utils import get_resource_path


# ---------------------------------------------------------------------------
# Default Configuration (used when config.json is missing or incomplete)
# ---------------------------------------------------------------------------
DEFAULTS = {
    "scan": {
        "max_file_size_mb": 50,
        "max_signature_scan_size_mb": 10,
        "file_scan_threads": 4,
        "file_scan_max_depth": 10,
        "memory_scan_max_per_process_mb": 50,
        "event_log_days": 7,
        "event_log_max_events": 2000,
    },
    "modules": {
        "file_scanner": True,
        "network_scanner": True,
        "persistence_scanner": True,
        "process_scanner": True,
        "memory_scanner": True,
        "vulnerability_scanner": True,
        "service_scanner": True,
        "eventlog_scanner": True,
        "security_config_scanner": True,
        "dns_scanner": True,
        "port_scanner": True,
        "hosts_scanner": True,
        "ads_scanner": True,
        "pipe_scanner": True,
        "dll_hijack_scanner": True,
        "amcache_scanner": True,
        "prefetch_scanner": True,
        "powershell_history_scanner": True,
        "credential_scanner": True,
        "browser_scanner": True,
        "attack_vector_scanner": True,
        "certificate_store_scanner": True,
        "scheduled_task_scanner": True,
        "usb_scanner": True,
    },
    "exclusions": {
        "paths": [],
        "processes": [],
        "hashes": [],
    },
    "output": {
        "html_report": True,
        "json_report": True,
        "log_level": "INFO",
        "auto_open_report": True,
    },
    "online": {
        "enabled": False,
        "vt_api_key": "",
        "abuseipdb_api_key": "",
        "vt_rate_limit_per_min": 4,
        "abuseipdb_rate_limit_per_day": 1000,
    },
}


def _deep_merge(base: dict, override: dict) -> dict:
    """Recursively merge override into base, preserving base defaults."""
    result = base.copy()
    for key, value in override.items():
        if key.startswith("_"):
            continue  # Skip comment keys
        if key in result and isinstance(result[key], dict) and isinstance(value, dict):
            result[key] = _deep_merge(result[key], value)
        else:
            result[key] = value
    return result


class ScanConfig:
    """Scanner configuration with safe defaults."""

    def __init__(self):
        self._data = DEFAULTS.copy()
        self._loaded_from = None

    def load(self, config_path: str = None):
        """
        Load configuration from JSON file.
        Falls back to defaults if file is missing or invalid.
        After loading, validates all numeric/string values and clamps
        out-of-range entries back to their defaults with a warning.
        """
        if config_path is None:
            config_path = get_resource_path("config.json")

        try:
            with open(config_path, "r", encoding="utf-8") as f:
                user_config = json.load(f)
            self._data = _deep_merge(DEFAULTS, user_config)
            self._loaded_from = config_path
        except FileNotFoundError:
            # No config file — use defaults (this is normal)
            self._data = DEFAULTS.copy()
        except (json.JSONDecodeError, ValueError) as e:
            print(f"  [!] Config file error: {e}. Using defaults.")
            self._data = DEFAULTS.copy()

        self._validate()

    # ------------------------------------------------------------------
    # Validation — clamp bad values to defaults, never crash
    # ------------------------------------------------------------------
    _SCAN_RULES = {
        #  key                           min   max   default
        "max_file_size_mb":              (1,   500,  50),
        "max_signature_scan_size_mb":    (1,   100,  10),
        "file_scan_threads":             (1,   16,   4),
        "file_scan_max_depth":           (1,   50,   10),
        "memory_scan_max_per_process_mb":(1,   500,  50),
        "event_log_days":                (1,   365,  7),
        "event_log_max_events":          (100, 50000, 2000),
    }

    _VALID_LOG_LEVELS = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}

    def _validate(self):
        """Validate loaded config; clamp invalid values to defaults with a warning."""
        scan = self._data.get("scan", {})
        for key, (lo, hi, default) in self._SCAN_RULES.items():
            val = scan.get(key)
            if val is None:
                continue
            if not isinstance(val, (int, float)) or val < lo or val > hi:
                print(f"  [!] Config: scan.{key}={val!r} invalid "
                      f"(must be {lo}-{hi}). Using default {default}.")
                scan[key] = default

        # Validate log_level
        output = self._data.get("output", {})
        log_level = output.get("log_level")
        if log_level is not None and str(log_level).upper() not in self._VALID_LOG_LEVELS:
            print(f"  [!] Config: output.log_level={log_level!r} invalid. Using default INFO.")
            output["log_level"] = "INFO"

    @property
    def scan(self) -> dict:
        return self._data.get("scan", DEFAULTS["scan"])

    @property
    def modules(self) -> dict:
        return self._data.get("modules", DEFAULTS["modules"])

    @property
    def exclusions(self) -> dict:
        return self._data.get("exclusions", DEFAULTS["exclusions"])

    @property
    def output(self) -> dict:
        return self._data.get("output", DEFAULTS["output"])

    def is_module_enabled(self, module_name: str) -> bool:
        """Check if a specific scanner module is enabled."""
        return self.modules.get(module_name, True)

    def get_excluded_paths(self) -> set:
        """Get the set of excluded paths (normalized to lowercase)."""
        return {p.lower() for p in self.exclusions.get("paths", [])}

    def get_excluded_processes(self) -> set:
        """Get the set of excluded process names (normalized to lowercase)."""
        return {p.lower() for p in self.exclusions.get("processes", [])}

    def get_excluded_hashes(self) -> set:
        """Get the set of excluded hashes (normalized to lowercase)."""
        return {h.lower() for h in self.exclusions.get("hashes", [])}

    def __repr__(self):
        src = self._loaded_from or "defaults"
        return f"<ScanConfig from={src}>"


# Global config instance
config = ScanConfig()
