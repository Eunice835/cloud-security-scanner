"""Stratus Red Team wrapper: optional attack-simulation result ingestion."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path
from typing import Any, Dict, List

from cloud_security_scanner.utils.deduplication import deduplicate_findings
from cloud_security_scanner.utils.severity import build_finding, load_cis_rules

SERVICE = "Stratus"


def _findings_from_stratus_json(data: Any, rules: Dict) -> List[Dict[str, str]]:
    """Convert parsed Stratus-style JSON into findings."""
    findings: List[Dict[str, str]] = []

    if isinstance(data, dict):
        items = data.get("techniques") or data.get("results") or data.get("runs")
        if isinstance(items, list):
            data = items
        else:
            data = [data]

    if not isinstance(data, list):
        return [
            build_finding(
                SERVICE,
                "results",
                "stratus_json_unexpected_shape",
                rules,
                fallback_issue="Stratus results JSON has an unexpected structure.",
            )
        ]

    for entry in data:
        if not isinstance(entry, dict):
            continue
        tech_id = entry.get("technique_id") or entry.get("id") or entry.get("technique", "unknown")
        status = entry.get("status") or entry.get("result") or entry.get("state", "unknown")
        note = entry.get("note") or entry.get("message", "")
        resource_id = str(tech_id)
        issue_key = "stratus_technique_executed" if str(status).lower() in {
            "success",
            "ok",
            "executed",
        } else "stratus_technique_recorded"

        findings.append(
            build_finding(
                SERVICE,
                resource_id,
                issue_key,
                rules,
                fallback_issue=f"Stratus technique {tech_id} status={status}: {note}".strip(),
                fallback_cis_control_id="CIS-8.0",
            )
        )

    return findings


def scan_stratus(
    results_json_path: str | None = None,
    stratus_binary: str | None = None,
    timeout_seconds: int = 120,
) -> List[Dict[str, str]]:
    """
    Load Stratus Red Team results from a JSON file, or probe the CLI when no file is provided.

    Without ``results_json_path``, if ``stratus`` is on PATH, runs ``stratus list`` and emits
    a single informational finding. If neither is available, returns a safe Low finding.
    """
    rules = load_cis_rules()
    path = results_json_path or os.environ.get("STRATUS_RESULTS_JSON", "")

    if path:
        file_path = Path(path)
        if not file_path.is_file():
            return [
                build_finding(
                    SERVICE,
                    path,
                    "stratus_results_file_missing",
                    rules,
                    fallback_issue="Stratus results JSON path does not exist.",
                )
            ]
        try:
            data = json.loads(file_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            return [
                build_finding(
                    SERVICE,
                    path,
                    "stratus_results_read_error",
                    rules,
                    fallback_issue=f"Could not read Stratus results JSON: {exc}",
                )
            ]
        parsed = _findings_from_stratus_json(data, rules)
        return deduplicate_findings(parsed) if parsed else [
            build_finding(
                SERVICE,
                path,
                "stratus_results_empty",
                rules,
                fallback_issue="Stratus results file contained no technique entries.",
            )
        ]

    binary = stratus_binary or os.environ.get("STRATUS_BINARY", "stratus")
    if shutil.which(binary):
        try:
            completed = subprocess.run(
                [binary, "list"],
                capture_output=True,
                text=True,
                timeout=timeout_seconds,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired):
            return [
                build_finding(
                    SERVICE,
                    binary,
                    "stratus_cli_error",
                    rules,
                    fallback_issue="Stratus CLI list command failed or timed out.",
                )
            ]
        preview = (completed.stdout or "").strip().splitlines()
        line_count = len(preview)
        return [
            build_finding(
                SERVICE,
                "cli",
                "stratus_cli_available",
                rules,
                fallback_issue=f"Stratus CLI available; listed ~{line_count} techniques (stdout lines).",
                fallback_recommendation=(
                    "Run approved Stratus scenarios in isolated test accounts; export JSON results "
                    "and pass via --stratus-results-json."
                ),
                fallback_cis_control_id="CIS-8.0",
            )
        ]

    return [
        build_finding(
            SERVICE,
            "cli",
            "stratus_not_configured",
            rules,
            fallback_issue="Stratus CLI not found and no --stratus-results-json provided.",
            fallback_recommendation=(
                "Install Stratus Red Team or provide a results JSON file path "
                "(see https://stratus-red-team.cloud/)."
            ),
        )
    ]
