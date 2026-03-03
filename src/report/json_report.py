"""
json_report.py - JSON report exporter for the security scanner.
Produces a structured JSON report with findings, risk score, and metadata.
"""

import os
import json
import socket
import platform
from datetime import datetime
from collections import Counter

from scanner_core.utils import Finding, RiskLevel, calculate_risk_score, is_admin


def export(findings: list, output_dir: str, elapsed: float,
                module_timings: dict = None, diff_data: dict = None,
                enrichment_summary: dict = None) -> str:
    """Export findings as a structured JSON report."""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    hostname = socket.gethostname()
    filepath = os.path.join(output_dir, f"report_{hostname}_{timestamp}.json")

    risk_counts = Counter(f.risk for f in findings)

    # Calculate risk score
    risk_score = calculate_risk_score(findings)

    # Collect MITRE ATT&CK technique counts
    mitre_counts = Counter(f.mitre_id for f in findings if f.mitre_id)

    data = {
        "scanner": "Corvus",
        "scan_time": datetime.now().isoformat(),
        "hostname": hostname,
        "username": os.environ.get("USERNAME", os.environ.get("USER", "Unknown")),
        "os": platform.platform(),
        "admin": is_admin(),
        "duration_seconds": round(elapsed, 1),
        "risk_score": risk_score,
        "summary": {
            "total_findings": len(findings),
            "critical": risk_counts.get(RiskLevel.CRITICAL, 0),
            "high": risk_counts.get(RiskLevel.HIGH, 0),
            "medium": risk_counts.get(RiskLevel.MEDIUM, 0),
            "info": risk_counts.get(RiskLevel.INFO, 0),
        },
        "mitre_techniques": dict(mitre_counts.most_common(20)),
        "module_timings": module_timings or {},
        "findings": [
            {
                "module": f.module,
                "risk": f.risk.value,
                "title": f.title,
                "description": f.description,
                "mitre_id": f.mitre_id,
                "remediation": f.remediation,
                "details": f.details,
            }
            for f in findings
        ],
    }

    # Include online enrichment summary if --online was used
    if enrichment_summary:
        data["enrichment"] = enrichment_summary

    # Include diff data if --diff was used
    if diff_data:
        data["diff"] = {
            "previous_report": diff_data.get("previous_report", ""),
            "previous_scan_time": diff_data.get("previous_scan_time", ""),
            "previous_risk_score": diff_data.get("previous_risk_score", -1),
            "summary": diff_data.get("summary", {}),
            "new_findings": [
                {
                    "module": f.module,
                    "risk": f.risk.value,
                    "title": f.title,
                    "description": f.description,
                    "mitre_id": f.mitre_id,
                }
                for f in diff_data.get("new", [])
            ],
            "resolved_findings": diff_data.get("resolved", []),
        }

    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)

    return filepath
