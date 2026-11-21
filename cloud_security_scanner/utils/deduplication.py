"""Shared finding deduplication for scanner modules."""

from __future__ import annotations

from typing import Dict, List


def deduplicate_findings(findings: List[Dict[str, str]]) -> List[Dict[str, str]]:
    """Remove identical findings while preserving insertion order."""
    unique_findings: List[Dict[str, str]] = []
    seen = set()
    for finding in findings:
        key = (
            finding.get("service"),
            finding.get("resource_id"),
            finding.get("issue"),
            finding.get("severity"),
            finding.get("recommendation"),
            finding.get("cis_control_id"),
        )
        if key in seen:
            continue
        seen.add(key)
        unique_findings.append(finding)
    return unique_findings
