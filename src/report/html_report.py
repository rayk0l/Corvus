"""
html_report.py - HTML report generator.
Produces a standalone, dark-themed HTML report with executive summary,
risk score, MITRE ATT&CK mapping, and per-module findings.
"""

import os
import socket
import platform
from datetime import datetime
from typing import List, Dict, Optional
from collections import Counter

from scanner_core.utils import Finding, RiskLevel, calculate_risk_score
from scanners import SCANNER_REGISTRY


def _get_system_info() -> dict:
    """Collect basic system information for the report."""
    return {
        "hostname": socket.gethostname(),
        "os": f"{platform.system()} {platform.release()} ({platform.version()})",
        "architecture": platform.machine(),
        "username": os.environ.get("USERNAME", os.environ.get("USER", "Unknown")),
        "scan_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    }


def _score_color(score: int) -> str:
    """Return a color based on the risk score."""
    if score >= 90:
        return "#22c55e"
    elif score >= 70:
        return "#38bdf8"
    elif score >= 50:
        return "#eab308"
    elif score >= 30:
        return "#f97316"
    else:
        return "#ef4444"


def _score_label(score: int) -> str:
    """Return a human-readable label for the risk score."""
    if score >= 90:
        return "Excellent"
    elif score >= 70:
        return "Good"
    elif score >= 50:
        return "Fair"
    elif score >= 30:
        return "Poor"
    else:
        return "Critical"


def _risk_badge(risk: RiskLevel) -> str:
    """Generate an HTML badge for a risk level."""
    styles = {
        RiskLevel.CRITICAL: "background:rgba(239,68,68,0.15);color:#ef4444",
        RiskLevel.HIGH: "background:rgba(249,115,22,0.15);color:#f97316",
        RiskLevel.MEDIUM: "background:rgba(234,179,8,0.15);color:#eab308",
        RiskLevel.INFO: "background:rgba(56,189,248,0.15);color:#38bdf8",
    }
    style = styles.get(risk, "background:rgba(100,116,139,0.15);color:#64748b")
    return f'<span class="badge" style="{style}">{risk.value}</span>'


def _escape_html(text: str) -> str:
    """Escape HTML special characters."""
    return (
        str(text)
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
        .replace("'", "&#39;")
    )


def _highest_risk_color(findings: List[Finding], module_name: str) -> str:
    """Return the badge color for a module based on its highest severity finding."""
    mod_findings = [f for f in findings if f.module == module_name]
    if not mod_findings:
        return "#22c55e"
    risks = {f.risk for f in mod_findings}
    if RiskLevel.CRITICAL in risks:
        return "#ef4444"
    if RiskLevel.HIGH in risks:
        return "#f97316"
    if RiskLevel.MEDIUM in risks:
        return "#eab308"
    return "#38bdf8"


# ---------------------------------------------------------------------------
# MITRE ATT&CK Kill Chain Mapping
# ---------------------------------------------------------------------------
_KILL_CHAIN_ORDER = [
    "Reconnaissance", "Resource Development", "Initial Access", "Execution",
    "Persistence", "Privilege Escalation", "Defense Evasion",
    "Credential Access", "Discovery", "Lateral Movement", "Collection",
    "Command and Control", "Exfiltration", "Impact",
]

# Technique ID → Primary Tactic (some techniques span multiple, we pick primary)
_MITRE_TACTIC_MAP = {
    # Initial Access
    "T1190": "Initial Access", "T1200": "Initial Access",
    "T1091": "Initial Access", "T1204.002": "Initial Access",
    # Execution
    "T1059": "Execution", "T1059.001": "Execution", "T1059.003": "Execution",
    "T1059.005": "Execution", "T1047": "Execution",
    "T1218": "Execution", "T1218.001": "Execution", "T1218.005": "Execution",
    "T1218.010": "Execution", "T1218.011": "Execution",
    # Persistence
    "T1053.005": "Persistence", "T1543.003": "Persistence",
    "T1547.001": "Persistence", "T1547.004": "Persistence",
    "T1547.005": "Persistence", "T1546.003": "Persistence",
    "T1546.010": "Persistence", "T1546.012": "Persistence",
    "T1542.003": "Persistence", "T1137.006": "Persistence",
    "T1176": "Persistence",
    # Privilege Escalation
    "T1055": "Privilege Escalation", "T1055.001": "Privilege Escalation",
    "T1548.002": "Privilege Escalation",
    # Defense Evasion
    "T1027": "Defense Evasion", "T1027.002": "Defense Evasion",
    "T1036": "Defense Evasion", "T1036.005": "Defense Evasion",
    "T1140": "Defense Evasion", "T1553.004": "Defense Evasion",
    "T1553.005": "Defense Evasion", "T1562.001": "Defense Evasion",
    "T1562.002": "Defense Evasion", "T1562.004": "Defense Evasion",
    "T1564.003": "Defense Evasion", "T1564.004": "Defense Evasion",
    "T1574.001": "Defense Evasion", "T1070.001": "Defense Evasion",
    "T1197": "Defense Evasion", "T1220": "Defense Evasion",
    # Credential Access
    "T1003": "Credential Access", "T1003.001": "Credential Access",
    "T1110": "Credential Access", "T1552.001": "Credential Access",
    "T1552.002": "Credential Access", "T1552.004": "Credential Access",
    "T1078.001": "Credential Access",
    # Discovery
    "T1082": "Discovery", "T1083": "Discovery",
    # Lateral Movement
    "T1021.001": "Lateral Movement",
    # Collection
    "T1005": "Collection", "T1052.001": "Collection",
    # Command and Control
    "T1071": "Command and Control", "T1071.001": "Command and Control",
    "T1071.004": "Command and Control", "T1090": "Command and Control",
    "T1090.003": "Command and Control", "T1105": "Command and Control",
    "T1568.002": "Command and Control", "T1571": "Command and Control",
    # Exfiltration
    "T1041": "Exfiltration",
    # Impact
    "T1490": "Impact", "T1565.001": "Impact", "T1542": "Impact",
    # Account Manipulation → Persistence
    "T1098": "Persistence", "T1136.001": "Persistence",
}


def _build_killchain_data(findings: List[Finding]) -> Dict:
    """Map findings to MITRE ATT&CK kill chain tactics.

    Returns dict keyed by tactic name with count, max_risk, and techniques.
    """
    tactic_data: Dict[str, Dict] = {}
    for tactic in _KILL_CHAIN_ORDER:
        tactic_data[tactic] = {
            "count": 0,
            "max_risk": None,
            "techniques": set(),
            "findings": [],
        }

    for f in findings:
        mid = f.mitre_id
        if not mid:
            continue
        tactic = _MITRE_TACTIC_MAP.get(mid)
        if not tactic:
            continue
        td = tactic_data[tactic]
        td["count"] += 1
        td["techniques"].add(mid)
        if td["max_risk"] is None or f.risk.order < td["max_risk"].order:
            td["max_risk"] = f.risk
        if len(td["findings"]) < 3:
            td["findings"].append(f.title)

    # Convert sets to sorted lists for JSON serialization
    for td in tactic_data.values():
        td["techniques"] = sorted(td["techniques"])

    return tactic_data


def _build_killchain_section(findings: List[Finding]) -> str:
    """Build the MITRE ATT&CK Kill Chain HTML visualization."""
    tactic_data = _build_killchain_data(findings)

    # Find max count for bar scaling
    max_count = max((td["count"] for td in tactic_data.values()), default=1) or 1

    rows = ""
    active_count = 0
    for tactic in _KILL_CHAIN_ORDER:
        td = tactic_data[tactic]
        count = td["count"]
        if count > 0:
            active_count += 1
            risk = td["max_risk"]
            color = risk.color if risk else "#334155"
            bar_pct = min(100, int((count / max_count) * 100))
            techs = ", ".join(td["techniques"][:5])
            tooltip = f'{count} finding(s): {techs}'
        else:
            color = "#1e293b"
            bar_pct = 0
            tooltip = "No findings"

        rows += f"""
        <div style="display:flex;align-items:center;margin:4px 0;gap:10px;">
          <div style="width:180px;font-size:12px;color:#94a3b8;text-align:right;
                      flex-shrink:0;" title="{_escape_html(tooltip)}">
            {_escape_html(tactic)}
          </div>
          <div style="flex:1;background:#1e293b;border-radius:4px;height:22px;
                      position:relative;overflow:hidden;">
            <div style="width:{bar_pct}%;height:100%;background:{color};
                        border-radius:4px;transition:width 0.3s;"></div>
            {'<span style="position:absolute;right:6px;top:2px;font-size:11px;color:#e2e8f0;">' + str(count) + '</span>' if count > 0 else ''}
          </div>
        </div>"""

    total_findings = sum(td["count"] for td in tactic_data.values())
    total_techniques = len(set(t for td in tactic_data.values() for t in td["techniques"]))

    return f"""
    <div style="background:#111827;border:1px solid #1f2937;border-radius:12px;
                padding:24px;margin:20px 0;">
      <h2 style="color:#f1f5f9;margin:0 0 6px 0;font-size:18px;">
        &#9876; MITRE ATT&amp;CK Kill Chain Coverage
      </h2>
      <p style="color:#64748b;margin:0 0 16px 0;font-size:13px;">
        {active_count} / {len(_KILL_CHAIN_ORDER)} tactics active &mdash;
        {total_techniques} techniques across {total_findings} findings
      </p>
      {rows}
    </div>"""


def _build_executive_summary(
    findings: List[Finding],
    risk_score: int,
    elapsed: float,
    module_timings: Dict[str, float],
) -> str:
    """Build the executive summary HTML section."""
    score_color = _score_color(risk_score)
    score_label = _score_label(risk_score)
    risk_counts = Counter(f.risk for f in findings)
    total = len(findings)

    # Top MITRE ATT&CK techniques
    mitre_counter = Counter()
    for f in findings:
        if f.mitre_id:
            mitre_counter[f.mitre_id] += 1
    top_mitre = mitre_counter.most_common(5)

    mitre_rows = ""
    for technique_id, count in top_mitre:
        mitre_url = f"https://attack.mitre.org/techniques/{technique_id.replace('.', '/')}/"
        mitre_rows += f"""
            <tr>
                <td><a href="{mitre_url}" target="_blank" style="color:#38bdf8;text-decoration:none">{technique_id}</a></td>
                <td style="text-align:center">{count}</td>
            </tr>"""

    if not mitre_rows:
        mitre_rows = '<tr><td colspan="2" style="color:#64748b;text-align:center;padding:12px">No MITRE ATT&CK mappings</td></tr>'

    # Top critical/high findings only
    top_findings_html = ""
    critical_high = [f for f in findings if f.risk in (RiskLevel.CRITICAL, RiskLevel.HIGH)]
    critical_high.sort(key=lambda f: f.risk.order)
    for f in critical_high[:5]:
        badge = _risk_badge(f.risk)
        top_findings_html += f"""
            <div style="padding:8px 12px;background:rgba(56,189,248,0.03);border-radius:8px;margin-bottom:6px;border-left:3px solid {f.risk.color}">
                {badge} <span style="margin-left:6px;font-size:13px">{_escape_html(f.title)}</span>
            </div>"""

    if not top_findings_html:
        top_findings_html = '<div style="color:#22c55e;text-align:center;padding:20px;font-size:13px">No critical or high risk findings</div>'

    # Module timing bars — TOP 5 only
    timing_bars = ""
    if module_timings:
        sorted_timings = sorted(module_timings.items(), key=lambda x: -x[1])[:5]
        max_time = sorted_timings[0][1] if sorted_timings else 1
        for mod_name, mod_time in sorted_timings:
            bar_width = max(5, int((mod_time / max(max_time, 0.1)) * 100))
            mod_findings = len([f for f in findings if f.module == mod_name])
            findings_badge = f'<span style="color:#ef4444;font-size:10px;margin-left:4px">({mod_findings})</span>' if mod_findings > 0 else ''
            timing_bars += f"""
                <div style="margin-bottom:6px">
                    <div style="display:flex;justify-content:space-between;font-size:11px;margin-bottom:2px">
                        <span style="color:#cbd5e1">{_escape_html(mod_name)}{findings_badge}</span>
                        <span style="color:#64748b">{mod_time:.1f}s</span>
                    </div>
                    <div style="background:#0c0e14;border-radius:3px;height:4px;overflow:hidden">
                        <div style="background:linear-gradient(90deg,#38bdf8,#22c55e);width:{bar_width}%;height:100%;border-radius:3px"></div>
                    </div>
                </div>"""

    # Assessment text
    if risk_score >= 90:
        assessment = "Your system appears to be in excellent security posture. No critical threats were detected. Continue maintaining security hygiene and regular patching."
    elif risk_score >= 70:
        assessment = "Your system is in good condition with minor issues. Review the findings below and address any high-risk items to improve your security posture."
    elif risk_score >= 50:
        assessment = "Several security concerns were identified. Prioritize addressing critical and high-risk findings immediately to reduce your attack surface."
    elif risk_score >= 30:
        assessment = "Your system has significant security vulnerabilities. Immediate action is required to address the critical findings. Consider a full incident response review."
    else:
        assessment = "URGENT: Your system shows signs of serious compromise or critical vulnerabilities. Isolate this machine from the network and begin incident response procedures immediately."

    return f"""
        <div class="exec-summary">
            <h2 class="section-title">Executive Summary</h2>
            <div class="exec-grid">
                <!-- Risk Score -->
                <div class="exec-card score-card">
                    <div class="score-circle" style="border-color:{score_color}">
                        <span class="score-number" style="color:{score_color}">{risk_score}</span>
                        <span class="score-max">/100</span>
                    </div>
                    <div class="score-label" style="color:{score_color}">{score_label}</div>
                    <div class="score-sublabel">Security Score</div>
                    <div style="margin-top:12px;font-size:12px;color:#64748b;line-height:1.5">{assessment}</div>
                </div>

                <!-- Right panels -->
                <div class="exec-right">
                    <!-- Top Findings -->
                    <div class="exec-card">
                        <h3 style="font-size:13px;color:#e2e8f0;margin-bottom:10px;font-weight:600">Top Findings</h3>
                        {top_findings_html}
                    </div>

                    <!-- MITRE & Timing Row -->
                    <div class="exec-row">
                        <div class="exec-card" style="flex:1">
                            <h3 style="font-size:13px;color:#e2e8f0;margin-bottom:10px;font-weight:600">MITRE ATT&CK</h3>
                            <table style="width:100%;font-size:12px;border-collapse:collapse">
                                <tr style="color:#64748b;border-bottom:1px solid #1e2430">
                                    <th style="text-align:left;padding:4px 8px;font-weight:500;font-size:11px">Technique</th>
                                    <th style="text-align:center;padding:4px 8px;font-weight:500;font-size:11px">Count</th>
                                </tr>
                                {mitre_rows}
                            </table>
                        </div>
                        <div class="exec-card" style="flex:1">
                            <h3 style="font-size:13px;color:#e2e8f0;margin-bottom:10px;font-weight:600">Scan Performance (Top 5)</h3>
                            <div style="margin-bottom:8px;font-size:12px;color:#cbd5e1">
                                Total: <strong>{elapsed:.1f}s</strong> &middot; Findings: <strong>{total}</strong>
                            </div>
                            {timing_bars}
                        </div>
                    </div>
                </div>
            </div>
        </div>"""


def _findings_table(findings: List[Finding], module_name: str) -> str:
    """Generate an HTML table for findings of a specific module."""
    module_findings = [f for f in findings if f.module == module_name]
    if not module_findings:
        return f'''
        <div class="no-findings">
            <span class="check-icon">&#10003;</span> No suspicious findings detected in this module.
        </div>'''

    # Sort by risk severity
    module_findings.sort(key=lambda f: f.risk.order)

    rows = ""
    for i, f in enumerate(module_findings):
        detail_rows = ""

        # Add MITRE ATT&CK ID if present
        if f.mitre_id:
            mitre_url = f"https://attack.mitre.org/techniques/{f.mitre_id.replace('.', '/')}/"
            detail_rows += f"""
                <tr>
                    <td class="detail-key">MITRE ATT&CK</td>
                    <td class="detail-value"><a href="{mitre_url}" target="_blank" style="color:#38bdf8">{_escape_html(f.mitre_id)}</a></td>
                </tr>"""

        # Add remediation if present
        if f.remediation:
            detail_rows += f"""
                <tr>
                    <td class="detail-key">Remediation</td>
                    <td class="detail-value" style="color:#22c55e">{_escape_html(f.remediation)}</td>
                </tr>"""

        # Enrichment keys to hide from generic details (shown as badges instead)
        _enrichment_hidden = {
            "vt_score", "vt_detection", "vt_total", "vt_link",
            "abuseipdb_score", "abuseipdb_reports", "abuseipdb_country", "abuseipdb_link",
            "risk_upgraded_by", "original_risk",
        }

        for key, value in f.details.items():
            if key in _enrichment_hidden:
                continue
            detail_rows += f"""
                <tr>
                    <td class="detail-key">{_escape_html(key)}</td>
                    <td class="detail-value">{_escape_html(str(value))}</td>
                </tr>"""

        # Build enrichment badges
        enrichment_badges = ""
        vt_score = f.details.get("vt_score")
        if vt_score and vt_score != "not found":
            vt_link = _escape_html(f.details.get("vt_link", "#"))
            enrichment_badges += (
                f' <a href="{vt_link}" target="_blank" style="'
                f'background:rgba(56,189,248,0.15);color:#38bdf8;'
                f'padding:2px 8px;border-radius:6px;font-size:10px;'
                f'font-weight:600;text-decoration:none;margin-left:6px;'
                f'border:1px solid rgba(56,189,248,0.3)'
                f'">VT: {_escape_html(str(vt_score))}</a>'
            )
        abuseipdb_score = f.details.get("abuseipdb_score")
        if abuseipdb_score is not None:
            ab_link = _escape_html(f.details.get("abuseipdb_link", "#"))
            ab_color = "#ef4444" if abuseipdb_score > 50 else "#a78bfa"
            ab_bg = "rgba(239,68,68,0.15)" if abuseipdb_score > 50 else "rgba(167,139,250,0.15)"
            ab_border = "rgba(239,68,68,0.3)" if abuseipdb_score > 50 else "rgba(167,139,250,0.3)"
            enrichment_badges += (
                f' <a href="{ab_link}" target="_blank" style="'
                f'background:{ab_bg};color:{ab_color};'
                f'padding:2px 8px;border-radius:6px;font-size:10px;'
                f'font-weight:600;text-decoration:none;margin-left:6px;'
                f'border:1px solid {ab_border}'
                f'">AbuseIPDB: {abuseipdb_score}/100</a>'
            )
        if f.details.get("risk_upgraded_by"):
            original = _escape_html(f.details.get("original_risk", "?"))
            enrichment_badges += (
                f' <span style="color:#eab308;font-size:10px;margin-left:4px">'
                f'\u2b06 was {original}</span>'
            )

        rows += f"""
        <div class="finding-card risk-{f.risk.value.lower()}">
            <div class="finding-header" onclick="toggleDetails('detail-{module_name}-{i}')">
                <div class="finding-title">
                    {_risk_badge(f.risk)}
                    <span>{_escape_html(f.title)}</span>{enrichment_badges}
                </div>
                <span class="toggle-icon" id="icon-detail-{module_name}-{i}">&#9654;</span>
            </div>
            <p class="finding-desc">{_escape_html(f.description)}</p>
            <div class="finding-details" id="detail-{module_name}-{i}">
                <table class="detail-table">
                    {detail_rows}
                </table>
            </div>
        </div>"""

    return rows


def _build_diff_section(diff_data: dict) -> str:
    """Build the baseline comparison HTML section when --diff is used."""
    if not diff_data:
        return ""

    summary = diff_data.get("summary", {})
    new_count = summary.get("new_count", 0)
    resolved_count = summary.get("resolved_count", 0)
    unchanged_count = summary.get("unchanged_count", 0)
    prev_score = diff_data.get("previous_risk_score", -1)
    prev_time = diff_data.get("previous_scan_time", "Unknown")

    # Score delta
    score_delta_html = ""
    if prev_score >= 0:
        score_delta_html = f"""
            <div class="meta-item">
                <div class="label">Previous Score</div>
                <div class="value">{prev_score}/100</div>
            </div>"""

    # New findings list (max 10)
    new_findings = diff_data.get("new", [])
    new_rows = ""
    for f in new_findings[:10]:
        badge = _risk_badge(f.risk) if hasattr(f, "risk") else ""
        title = _escape_html(f.title) if hasattr(f, "title") else ""
        new_rows += f"""
            <div style="padding:6px 10px;background:rgba(239,68,68,0.04);border-radius:6px;margin-bottom:4px;border-left:3px solid #ef4444;font-size:12px">
                {badge} <span style="margin-left:6px">{title}</span>
            </div>"""
    if len(new_findings) > 10:
        new_rows += f'<div style="color:#64748b;font-size:11px;padding:4px 10px">... and {len(new_findings) - 10} more</div>'

    # Resolved findings list (max 10)
    resolved_findings = diff_data.get("resolved", [])
    resolved_rows = ""
    for f in resolved_findings[:10]:
        risk_val = f.get("risk", "UNKNOWN") if isinstance(f, dict) else ""
        title_val = _escape_html(f.get("title", "")) if isinstance(f, dict) else ""
        resolved_rows += f"""
            <div style="padding:6px 10px;background:rgba(34,197,94,0.04);border-radius:6px;margin-bottom:4px;border-left:3px solid #22c55e;font-size:12px">
                <span class="badge" style="background:rgba(34,197,94,0.15);color:#22c55e">{_escape_html(risk_val)}</span>
                <span style="margin-left:6px">{title_val}</span>
            </div>"""
    if len(resolved_findings) > 10:
        resolved_rows += f'<div style="color:#64748b;font-size:11px;padding:4px 10px">... and {len(resolved_findings) - 10} more</div>'

    new_label = f'<span style="color:#ef4444;font-weight:700;font-size:28px">{new_count}</span>'
    resolved_label = f'<span style="color:#22c55e;font-weight:700;font-size:28px">{resolved_count}</span>'
    unchanged_label = f'<span style="color:#38bdf8;font-weight:700;font-size:28px">{unchanged_count}</span>'

    new_section = f"""
        <div class="exec-card" style="flex:1">
            <h3 style="font-size:13px;color:#ef4444;margin-bottom:10px;font-weight:600">🆕 New Findings ({new_count})</h3>
            {new_rows if new_rows else '<div style="color:#64748b;font-size:12px;text-align:center;padding:12px">No new findings</div>'}
        </div>"""

    resolved_section = f"""
        <div class="exec-card" style="flex:1">
            <h3 style="font-size:13px;color:#22c55e;margin-bottom:10px;font-weight:600">✅ Resolved Findings ({resolved_count})</h3>
            {resolved_rows if resolved_rows else '<div style="color:#64748b;font-size:12px;text-align:center;padding:12px">No resolved findings</div>'}
        </div>"""

    return f"""
        <div class="exec-summary" style="border-color:rgba(56,189,248,0.3)">
            <h2 class="section-title">📊 Baseline Comparison</h2>
            <div class="header-meta" style="margin-bottom:16px">
                <div class="meta-item">
                    <div class="label">Previous Scan</div>
                    <div class="value">{_escape_html(prev_time)}</div>
                </div>
                {score_delta_html}
                <div class="meta-item">
                    <div class="label">New</div>
                    <div class="value" style="color:#ef4444">{new_count}</div>
                </div>
                <div class="meta-item">
                    <div class="label">Resolved</div>
                    <div class="value" style="color:#22c55e">{resolved_count}</div>
                </div>
                <div class="meta-item">
                    <div class="label">Unchanged</div>
                    <div class="value" style="color:#38bdf8">{unchanged_count}</div>
                </div>
            </div>
            <div class="exec-row">
                {new_section}
                {resolved_section}
            </div>
        </div>"""


def generate(
    findings: List[Finding],
    output_dir: str = ".",
    elapsed: float = 0.0,
    module_timings: Optional[Dict[str, float]] = None,
    diff_data: Optional[dict] = None,
) -> str:
    """Generate the HTML report and return the file path."""
    sys_info = _get_system_info()
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"report_{sys_info['hostname']}_{timestamp}.html"
    filepath = os.path.join(output_dir, filename)

    if module_timings is None:
        module_timings = {}

    # Count findings by risk
    risk_counts = Counter(f.risk for f in findings)
    total_findings = len(findings)
    critical_count = risk_counts.get(RiskLevel.CRITICAL, 0)
    high_count = risk_counts.get(RiskLevel.HIGH, 0)
    medium_count = risk_counts.get(RiskLevel.MEDIUM, 0)
    info_count = risk_counts.get(RiskLevel.INFO, 0)

    # Calculate risk score
    risk_score = calculate_risk_score(findings)
    score_color = _score_color(risk_score)

    # Determine overall risk level
    if critical_count > 0:
        overall_risk = "CRITICAL"
        overall_color = "#ef4444"
    elif high_count > 0:
        overall_risk = "HIGH"
        overall_color = "#f97316"
    elif medium_count > 0:
        overall_risk = "MEDIUM"
        overall_color = "#eab308"
    else:
        overall_risk = "CLEAN"
        overall_color = "#22c55e"

    # Build executive summary
    exec_summary_html = _build_executive_summary(findings, risk_score, elapsed, module_timings)

    # Build Kill Chain visualization
    killchain_html = _build_killchain_section(findings)

    # Build diff section (if --diff was used)
    diff_html = _build_diff_section(diff_data) if diff_data else ""

    # Build module list dynamically from SCANNER_REGISTRY.
    # Icon + description metadata per config_key; unknown modules get safe defaults.
    _MODULE_META = {
        "file_scanner":              ("🔍", "Malicious Hash + YARA + Signature Detection"),
        "network_scanner":           ("🌐", "Suspicious Connection Analysis"),
        "persistence_scanner":       ("🔗", "Persistence Mechanism Detection"),
        "process_scanner":           ("⚙️", "Running Process Analysis"),
        "memory_scanner":            ("🧠", "Process Memory Injection Analysis"),
        "vulnerability_scanner":     ("🛡️", "Offline CVE Detection"),
        "service_scanner":           ("🔧", "Suspicious Service Detection"),
        "eventlog_scanner":          ("📋", "Security Event Analysis"),
        "security_config_scanner":   ("🔒", "System Hardening Checks"),
        "dns_scanner":               ("🌍", "Malicious Domain Detection"),
        "port_scanner":              ("🚪", "Suspicious Port Detection"),
        "hosts_scanner":             ("📄", "Hosts File Tampering Detection"),
        "ads_scanner":               ("📎", "NTFS Alternate Data Stream Detection"),
        "pipe_scanner":              ("🔌", "C2 Named Pipe Detection"),
        "dll_hijack_scanner":        ("🧩", "DLL Search Order Hijacking Detection"),
        "amcache_scanner":           ("🕵️", "Execution History Forensics"),
        "prefetch_scanner":          ("⏪", "Prefetch Execution Analysis"),
        "powershell_history_scanner":("📜", "PowerShell History Analysis"),
        "credential_scanner":        ("🔑", "Exposed Secrets Detection"),
        "browser_scanner":           ("🌐", "Browser Extension Security"),
        "attack_vector_scanner":     ("⚠️", "Dangerous File Extension Detection"),
        "certificate_store_scanner": ("🔐", "Root Certificate Trust Store Analysis"),
        "scheduled_task_scanner":    ("📅", "Scheduled Task Anomaly Detection"),
        "usb_scanner":               ("💾", "USB Device & BadUSB Detection"),
    }
    modules = []
    for _, display_name, config_key in SCANNER_REGISTRY:
        icon, desc = _MODULE_META.get(config_key, ("🔎", display_name))
        modules.append((display_name, config_key, icon, desc))

    # Add Correlation Engine if it produced findings
    if any(f.module == "Correlation Engine" for f in findings):
        modules.insert(0, (
            "Correlation Engine", "correlation_engine",
            "🔗", "Cross-Module Attack Chain Detection",
        ))

    # Build module sections
    module_sections = ""
    for mod_name, mod_id, mod_icon, mod_desc in modules:
        mod_count = len([f for f in findings if f.module == mod_name])
        if mod_count > 0:
            badge_color = _highest_risk_color(findings, mod_name)
            mod_badge = f'<span class="module-count" style="background:rgba({_hex_to_rgb(badge_color)},0.15);color:{badge_color}">{mod_count} finding{"s" if mod_count != 1 else ""}</span>'
        else:
            mod_badge = '<span class="module-clean">Clean</span>'

        module_sections += f"""
        <div class="module-section" id="section-{mod_id}">
            <div class="module-header" onclick="toggleSection('{mod_id}')">
                <div>
                    <span class="module-icon">{mod_icon}</span>
                    <h2>{mod_name}</h2>
                    <span class="module-desc">{mod_desc}</span>
                </div>
                <div class="module-header-right">
                    {mod_badge}
                    <span class="toggle-icon" id="icon-{mod_id}">&#9660;</span>
                </div>
            </div>
            <div class="module-content" id="content-{mod_id}">
                {_findings_table(findings, mod_name)}
            </div>
        </div>"""

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Corvus - {_escape_html(sys_info['hostname'])}</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            font-family: 'Inter', 'Segoe UI', -apple-system, system-ui, sans-serif;
            background: #0c0e14;
            color: #e2e8f0;
            line-height: 1.6;
            min-height: 100vh;
        }}
        .container {{ max-width: 1200px; margin: 0 auto; padding: 20px; }}

        /* Scrollbar */
        ::-webkit-scrollbar {{ width: 6px; }}
        ::-webkit-scrollbar-track {{ background: #0c0e14; }}
        ::-webkit-scrollbar-thumb {{ background: #1e2430; border-radius: 3px; }}
        ::-webkit-scrollbar-thumb:hover {{ background: #38bdf8; }}

        /* Header */
        .header {{
            background: linear-gradient(135deg, #0f1319 0%, #141820 50%, #0f1923 100%);
            border: 1px solid #1e2430;
            border-radius: 16px;
            padding: 32px;
            margin-bottom: 24px;
        }}
        .header-brand {{
            display: flex;
            align-items: center;
            gap: 16px;
            margin-bottom: 24px;
        }}
        .corvus-logo {{ filter: drop-shadow(0 0 8px rgba(56,189,248,0.3)); }}
        .header h1 {{
            font-size: 32px;
            font-weight: 700;
            color: #e2e8f0;
            letter-spacing: 3px;
        }}
        .header .subtitle {{
            color: #64748b;
            font-size: 13px;
            letter-spacing: 1px;
            text-transform: uppercase;
        }}

        /* System Info Grid */
        .header-meta {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 12px;
        }}
        .meta-item {{
            background: rgba(56,189,248,0.03);
            border: 1px solid #1e2430;
            border-radius: 10px;
            padding: 10px 14px;
        }}
        .meta-item .label {{
            color: #64748b;
            font-size: 10px;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            font-weight: 500;
        }}
        .meta-item .value {{
            color: #cbd5e1;
            font-size: 13px;
            font-weight: 500;
            margin-top: 2px;
            font-family: 'JetBrains Mono', 'Consolas', monospace;
        }}

        /* Dashboard */
        .dashboard {{
            display: grid;
            grid-template-columns: repeat(6, 1fr);
            gap: 12px;
            margin-bottom: 24px;
        }}
        .dash-card {{
            background: #141820;
            border: 1px solid #1e2430;
            border-radius: 12px;
            padding: 16px;
            text-align: center;
            transition: all 0.2s ease;
        }}
        .dash-card:hover {{
            border-color: #38bdf8;
            box-shadow: 0 0 20px rgba(56,189,248,0.06);
        }}
        .dash-card .number {{
            font-size: 32px;
            font-weight: 700;
            font-family: 'Inter', sans-serif;
        }}
        .dash-card .label {{
            color: #64748b;
            font-size: 11px;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            margin-top: 4px;
        }}

        /* Module Sections */
        .module-section {{
            background: #141820;
            border: 1px solid #1e2430;
            border-radius: 12px;
            margin-bottom: 12px;
            overflow: hidden;
            transition: border-color 0.2s ease;
        }}
        .module-section:hover {{
            border-color: rgba(56,189,248,0.2);
        }}
        .module-header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 14px 20px;
            cursor: pointer;
            transition: background 0.15s ease;
        }}
        .module-header:hover {{ background: #1a1f2b; }}
        .module-header div {{ display: flex; align-items: center; gap: 10px; }}
        .module-header h2 {{ font-size: 15px; font-weight: 600; color: #e2e8f0; }}
        .module-icon {{ font-size: 18px; }}
        .module-desc {{ color: #64748b; font-size: 11px; }}
        .module-header-right {{ display: flex; align-items: center; gap: 12px; }}
        .module-count {{
            padding: 2px 10px;
            border-radius: 8px;
            font-size: 11px;
            font-weight: 600;
        }}
        .module-clean {{
            background: rgba(34,197,94,0.1);
            color: #22c55e;
            padding: 2px 10px;
            border-radius: 8px;
            font-size: 11px;
            font-weight: 600;
        }}
        .module-content {{ padding: 0 20px 16px; }}
        .toggle-icon {{ color: #64748b; font-size: 11px; transition: transform 0.15s ease; }}

        /* Findings */
        .finding-card {{
            background: #141820;
            border: 1px solid #1e2430;
            border-radius: 10px;
            padding: 16px;
            margin-bottom: 8px;
            border-left: 3px solid #1e2430;
            transition: all 0.15s ease;
        }}
        .finding-card:hover {{ background: #1a1f2b; }}
        .finding-card.risk-critical {{ border-left-color: #ef4444; }}
        .finding-card.risk-high {{ border-left-color: #f97316; }}
        .finding-card.risk-medium {{ border-left-color: #eab308; }}
        .finding-card.risk-info {{ border-left-color: #38bdf8; }}
        .finding-header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            cursor: pointer;
        }}
        .finding-title {{ display: flex; align-items: center; gap: 8px; font-weight: 500; font-size: 13px; }}
        .finding-desc {{ color: #64748b; font-size: 12px; margin: 6px 0 0 0; line-height: 1.5; }}
        .finding-details {{
            display: none;
            margin-top: 12px;
            padding-top: 12px;
            border-top: 1px solid #1e2430;
        }}
        .finding-details.show {{ display: block; }}

        /* Badge */
        .badge {{
            display: inline-block;
            padding: 2px 8px;
            border-radius: 6px;
            font-size: 10px;
            font-weight: 600;
            letter-spacing: 0.5px;
            text-transform: uppercase;
        }}

        /* Detail Table */
        .detail-table {{ width: 100%; border-collapse: collapse; }}
        .detail-table td {{
            padding: 8px 12px;
            font-size: 12px;
            border-bottom: 1px solid #1e2430;
            word-break: break-all;
        }}
        .detail-key {{
            color: #64748b;
            width: 150px;
            font-weight: 500;
            font-size: 11px;
            letter-spacing: 0.3px;
        }}
        .detail-value {{
            color: #cbd5e1;
            font-family: 'JetBrains Mono', 'Consolas', monospace;
            font-size: 12px;
        }}

        /* No findings */
        .no-findings {{
            text-align: center;
            padding: 20px;
            color: #22c55e;
            font-size: 13px;
        }}
        .check-icon {{ font-size: 16px; margin-right: 4px; }}

        /* Executive Summary */
        .exec-summary {{
            background: #141820;
            border: 1px solid #1e2430;
            border-radius: 14px;
            padding: 24px;
            margin-bottom: 24px;
        }}
        .section-title {{
            font-size: 16px;
            font-weight: 600;
            color: #e2e8f0;
            margin-bottom: 20px;
            padding-bottom: 10px;
            border-bottom: 1px solid #1e2430;
        }}
        .exec-grid {{
            display: grid;
            grid-template-columns: 260px 1fr;
            gap: 20px;
        }}
        .exec-card {{
            background: rgba(56,189,248,0.02);
            border: 1px solid #1e2430;
            border-radius: 12px;
            padding: 18px;
        }}
        .exec-right {{
            display: flex;
            flex-direction: column;
            gap: 14px;
        }}
        .exec-row {{
            display: flex;
            gap: 14px;
        }}
        .score-card {{
            display: flex;
            flex-direction: column;
            align-items: center;
            justify-content: flex-start;
            text-align: center;
        }}
        .score-circle {{
            width: 100px;
            height: 100px;
            border-radius: 50%;
            border: 3px solid;
            display: flex;
            flex-direction: column;
            align-items: center;
            justify-content: center;
            margin-bottom: 10px;
            background: rgba(56,189,248,0.03);
        }}
        .score-number {{
            font-size: 36px;
            font-weight: 700;
            line-height: 1;
        }}
        .score-max {{
            font-size: 12px;
            color: #64748b;
        }}
        .score-label {{
            font-size: 16px;
            font-weight: 600;
        }}
        .score-sublabel {{
            font-size: 11px;
            color: #64748b;
            margin-top: 2px;
        }}

        /* Footer */
        .footer {{
            text-align: center;
            padding: 24px;
            margin-top: 32px;
            border-top: 1px solid #1e2430;
        }}
        .footer-brand {{
            font-size: 14px;
            font-weight: 700;
            letter-spacing: 3px;
            color: #38bdf8;
            margin-bottom: 4px;
        }}
        .footer-info {{
            color: #475569;
            font-size: 11px;
        }}

        /* Responsive */
        @media (max-width: 900px) {{
            .dashboard {{ grid-template-columns: repeat(3, 1fr); }}
            .exec-grid {{ grid-template-columns: 1fr; }}
            .exec-row {{ flex-direction: column; }}
        }}
        @media (max-width: 600px) {{
            .dashboard {{ grid-template-columns: repeat(2, 1fr); }}
            .header-meta {{ grid-template-columns: 1fr; }}
            .header {{ padding: 20px; }}
            .header h1 {{ font-size: 24px; }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <!-- Header -->
        <div class="header">
            <div class="header-brand">
                <svg class="corvus-logo" width="48" height="48" viewBox="0 0 100 100">
                    <!-- Crow/Raven silhouette -->
                    <!-- Body -->
                    <ellipse cx="50" cy="55" rx="22" ry="26" fill="#38bdf8" opacity="0.9"/>
                    <!-- Head -->
                    <circle cx="50" cy="28" r="16" fill="#38bdf8" opacity="0.9"/>
                    <!-- Beak -->
                    <polygon points="34,28 20,32 34,34" fill="#f0c050"/>
                    <!-- Eye -->
                    <circle cx="44" cy="26" r="3" fill="#0f172a"/>
                    <circle cx="44" cy="25.5" r="1" fill="#fff"/>
                    <!-- Left wing -->
                    <path d="M28,45 Q12,40 8,55 Q14,52 22,56 Z" fill="#2ea5d4" opacity="0.85"/>
                    <!-- Right wing -->
                    <path d="M72,45 Q88,40 92,55 Q86,52 78,56 Z" fill="#2ea5d4" opacity="0.85"/>
                    <!-- Tail feathers -->
                    <path d="M40,78 L35,92 L42,85 L50,94 L58,85 L65,92 L60,78 Z" fill="#2ea5d4" opacity="0.85"/>
                    <!-- Feet -->
                    <path d="M42,80 L38,90 M42,80 L42,92 M42,80 L46,90" stroke="#f0c050" stroke-width="2" fill="none" stroke-linecap="round"/>
                    <path d="M58,80 L54,90 M58,80 L58,92 M58,80 L62,90" stroke="#f0c050" stroke-width="2" fill="none" stroke-linecap="round"/>
                </svg>
                <div>
                    <h1>CORVUS</h1>
                    <p class="subtitle">Endpoint Threat Detection Report</p>
                </div>
            </div>
            <div class="header-meta">
                <div class="meta-item">
                    <div class="label">Hostname</div>
                    <div class="value">{_escape_html(sys_info['hostname'])}</div>
                </div>
                <div class="meta-item">
                    <div class="label">Operating System</div>
                    <div class="value">{_escape_html(sys_info['os'])}</div>
                </div>
                <div class="meta-item">
                    <div class="label">Architecture</div>
                    <div class="value">{_escape_html(sys_info['architecture'])}</div>
                </div>
                <div class="meta-item">
                    <div class="label">User</div>
                    <div class="value">{_escape_html(sys_info['username'])}</div>
                </div>
                <div class="meta-item">
                    <div class="label">Scan Time</div>
                    <div class="value">{_escape_html(sys_info['scan_time'])}</div>
                </div>
            </div>
        </div>

        <!-- Dashboard -->
        <div class="dashboard">
            <div class="dash-card">
                <div class="number" style="color:{score_color}">{risk_score}</div>
                <div class="label">Score</div>
            </div>
            <div class="dash-card">
                <div class="number" style="color:{overall_color}">{overall_risk}</div>
                <div class="label">Risk Level</div>
            </div>
            <div class="dash-card">
                <div class="number" style="color:#ef4444">{critical_count}</div>
                <div class="label">Critical</div>
            </div>
            <div class="dash-card">
                <div class="number" style="color:#f97316">{high_count}</div>
                <div class="label">High</div>
            </div>
            <div class="dash-card">
                <div class="number" style="color:#eab308">{medium_count}</div>
                <div class="label">Medium</div>
            </div>
            <div class="dash-card">
                <div class="number" style="color:#38bdf8">{info_count}</div>
                <div class="label">Info</div>
            </div>
        </div>

        <!-- Executive Summary -->
        {exec_summary_html}

        <!-- MITRE ATT&CK Kill Chain -->
        {killchain_html}

        <!-- Baseline Comparison (if --diff) -->
        {diff_html}

        <!-- Module Sections -->
        {module_sections}

        <!-- Footer -->
        <div class="footer">
            <div class="footer-brand">CORVUS</div>
            <div class="footer-info">{_escape_html(sys_info['scan_time'])} &middot; Score: {risk_score}/100 &middot; {total_findings} findings &middot; {elapsed:.1f}s</div>
        </div>
    </div>

    <script>
        function toggleDetails(id) {{
            var el = document.getElementById(id);
            var icon = document.getElementById('icon-' + id);
            if (el) {{
                el.classList.toggle('show');
                if (icon) icon.innerHTML = el.classList.contains('show') ? '&#9660;' : '&#9654;';
            }}
        }}

        function toggleSection(id) {{
            var content = document.getElementById('content-' + id);
            var icon = document.getElementById('icon-' + id);
            if (content) {{
                var isVisible = content.style.display !== 'none';
                content.style.display = isVisible ? 'none' : 'block';
                if (icon) icon.innerHTML = isVisible ? '&#9654;' : '&#9660;';
            }}
        }}

        // Collapse clean modules on page load
        document.addEventListener('DOMContentLoaded', function() {{
            document.querySelectorAll('.module-section').forEach(function(section) {{
                var badge = section.querySelector('.module-clean');
                if (badge) {{
                    var id = section.id.replace('section-', '');
                    var content = document.getElementById('content-' + id);
                    var icon = document.getElementById('icon-' + id);
                    if (content) content.style.display = 'none';
                    if (icon) icon.innerHTML = '&#9654;';
                }}
            }});
        }});
    </script>
</body>
</html>"""

    with open(filepath, "w", encoding="utf-8") as f:
        f.write(html)

    return filepath


def _hex_to_rgb(hex_color: str) -> str:
    """Convert hex color to comma-separated RGB values for use in rgba()."""
    hex_color = hex_color.lstrip('#')
    r = int(hex_color[0:2], 16)
    g = int(hex_color[2:4], 16)
    b = int(hex_color[4:6], 16)
    return f"{r},{g},{b}"
