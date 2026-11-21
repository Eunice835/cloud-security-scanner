"""Severity and CIS rule helpers."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Dict

SEVERITY_ORDER = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1}


def load_cis_rules(rules_file: str | None = None) -> Dict[str, Dict[str, str]]:
    """Load CIS mapping rules from JSON file."""
    default_path = Path(__file__).resolve().parents[1] / "rules" / "cis_rules.json"
    path = Path(rules_file) if rules_file else default_path
    with path.open("r", encoding="utf-8") as handle:
        data = json.load(handle)
    return data.get("rules", {})


def build_finding(
    service: str,
    resource_id: str,
    issue_key: str,
    rules: Dict[str, Dict[str, str]],
    fallback_issue: str,
    fallback_severity: str = "Low",
    fallback_recommendation: str = "Review this configuration.",
    fallback_cis_control_id: str = "CIS-UNMAPPED",
) -> Dict[str, str]:
    """Build a standardized finding from rules with safe fallbacks."""
    rule = rules.get(issue_key, {})
    return {
        "service": service,
        "resource_id": resource_id,
        "issue": rule.get("issue", fallback_issue),
        "severity": rule.get("severity", fallback_severity),
        "recommendation": rule.get("recommendation", fallback_recommendation),
        "cis_control_id": rule.get("cis_control_id", fallback_cis_control_id),
    }


def summarize_by_severity(findings: list[Dict[str, str]]) -> Dict[str, int]:
    """Return finding counts grouped by severity."""
    summary = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    for finding in findings:
        severity = finding.get("severity", "Low")
        if severity not in summary:
            summary[severity] = 0
        summary[severity] += 1
    return summary

