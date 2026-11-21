"""Pacu wrapper: optional AWS privilege-escalation / recon output ingestion."""

from __future__ import annotations

import json
import os
import shutil
from pathlib import Path
from typing import Any, Dict, List

from cloud_security_scanner.utils.deduplication import deduplicate_findings
from cloud_security_scanner.utils.severity import build_finding, load_cis_rules

SERVICE = "Pacu"


def _findings_from_pacu_json(data: Any, rules: Dict) -> List[Dict[str, str]]:
    """Convert Pacu-exported JSON (flexible shape) into findings."""
    findings: List[Dict[str, str]] = []

    if isinstance(data, dict):
        items = data.get("findings") or data.get("results") or data.get("modules")
        if items is None and "module" in data:
            items = [data]
        if isinstance(items, list):
            data = items
        elif items is not None:
            data = items
        else:
            data = [data]

    if not isinstance(data, list):
        return [
            build_finding(
                SERVICE,
                "results",
                "pacu_json_unexpected_shape",
                rules,
                fallback_issue="Pacu results JSON has an unexpected structure.",
            )
        ]

    for entry in data:
        if not isinstance(entry, dict):
            continue
        module = entry.get("module") or entry.get("name") or entry.get("title", "unknown")
        detail = entry.get("details") or entry.get("message") or entry.get("output", "")
        severity_hint = str(entry.get("severity", "")).title()
        resource_id = str(module)
        issue_key = "pacu_finding_high" if severity_hint == "High" else "pacu_finding_recorded"

        findings.append(
            build_finding(
                SERVICE,
                resource_id,
                issue_key,
                rules,
                fallback_issue=f"Pacu module result: {module} — {detail}".strip(),
                fallback_cis_control_id="CIS-1.0",
            )
        )

    return findings


def scan_pacu(results_json_path: str | None = None) -> List[Dict[str, str]]:
    """
    Load Pacu results from JSON, or report CLI availability.

    Pacu is primarily interactive; this integration expects an exported JSON report via
    ``--pacu-results-json`` or ``PACU_RESULTS_JSON``. If neither a file nor meaningful Pacu
    installation is detected, returns a safe informational finding.
    """
    rules = load_cis_rules()
    path = results_json_path or os.environ.get("PACU_RESULTS_JSON", "")

    if path:
        file_path = Path(path)
        if not file_path.is_file():
            return [
                build_finding(
                    SERVICE,
                    path,
                    "pacu_results_file_missing",
                    rules,
                    fallback_issue="Pacu results JSON path does not exist.",
                )
            ]
        try:
            data = json.loads(file_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            return [
                build_finding(
                    SERVICE,
                    path,
                    "pacu_results_read_error",
                    rules,
                    fallback_issue=f"Could not read Pacu results JSON: {exc}",
                )
            ]
        parsed = _findings_from_pacu_json(data, rules)
        return deduplicate_findings(parsed) if parsed else [
            build_finding(
                SERVICE,
                path,
                "pacu_results_empty",
                rules,
                fallback_issue="Pacu results file contained no module entries.",
            )
        ]

    if shutil.which("pacu") or shutil.which("pacu-console"):
        return [
            build_finding(
                SERVICE,
                "cli",
                "pacu_cli_hint",
                rules,
                fallback_issue="Pacu CLI detected; interactive sessions are not auto-executed.",
                fallback_recommendation=(
                    "Run Pacu only in authorized lab accounts; export findings to JSON and pass "
                    "via --pacu-results-json."
                ),
                fallback_cis_control_id="CIS-1.0",
            )
        ]

    return [
        build_finding(
            SERVICE,
            "cli",
            "pacu_not_configured",
            rules,
            fallback_issue="Pacu not found and no --pacu-results-json provided.",
            fallback_recommendation=(
                "Install Pacu (https://github.com/RhinoSecurityLabs/pacu) or supply a results JSON path."
            ),
        )
    ]
