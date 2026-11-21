"""Trivy wrapper: optional container/filesystem vulnerability scanning."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from typing import Dict, List

from cloud_security_scanner.utils.deduplication import deduplicate_findings
from cloud_security_scanner.utils.severity import build_finding, load_cis_rules

SERVICE = "Trivy"


def scan_trivy(
    scan_target: str = ".",
    scan_mode: str = "fs",
    trivy_binary: str | None = None,
    timeout_seconds: int = 600,
) -> List[Dict[str, str]]:
    """
    Run Trivy when available and map results to standardized findings.

    ``scan_mode`` may be ``fs`` (filesystem) or ``image`` (container image ref).

    If the Trivy CLI is missing or the scan fails, returns Low-severity findings
    describing the condition instead of raising.
    """
    rules = load_cis_rules()
    binary = trivy_binary or os.environ.get("TRIVY_BINARY", "trivy")
    if not shutil.which(binary):
        return [
            build_finding(
                SERVICE,
                scan_target or "scan",
                "trivy_cli_missing",
                rules,
                fallback_issue="Trivy CLI not found in PATH.",
                fallback_recommendation=(
                    "Install Trivy (https://github.com/aquasecurity/trivy) or set TRIVY_BINARY."
                ),
            )
        ]

    cmd: List[str] = [binary]
    if scan_mode == "image":
        cmd.extend(["image", "--format", "json", "--quiet", scan_target])
    else:
        cmd.extend(["fs", "--format", "json", "--quiet", scan_target])

    try:
        completed = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return [
            build_finding(
                SERVICE,
                scan_target,
                "trivy_scan_timeout",
                rules,
                fallback_issue="Trivy scan timed out.",
            )
        ]
    except OSError as exc:
        return [
            build_finding(
                SERVICE,
                scan_target,
                "trivy_scan_failed",
                rules,
                fallback_issue=f"Trivy scan could not start: {exc}",
            )
        ]

    if completed.returncode != 0 and not completed.stdout.strip():
        return [
            build_finding(
                SERVICE,
                scan_target,
                "trivy_scan_failed",
                rules,
                fallback_issue="Trivy scan failed (non-zero exit).",
                fallback_recommendation=(completed.stderr or "Review Trivy output.").strip(),
            )
        ]

    try:
        payload = json.loads(completed.stdout or "{}")
    except json.JSONDecodeError:
        return [
            build_finding(
                SERVICE,
                scan_target,
                "trivy_json_parse_error",
                rules,
                fallback_issue="Could not parse Trivy JSON output.",
            )
        ]

    findings: List[Dict[str, str]] = []
    results = payload.get("Results") or []
    for result in results:
        target = result.get("Target", scan_target)
        for vuln in result.get("Vulnerabilities") or []:
            vid = vuln.get("VulnerabilityID", "UNKNOWN")
            severity_raw = (vuln.get("Severity") or "UNKNOWN").title()
            title = vuln.get("Title") or vid
            pkg = vuln.get("PkgName", "")
            resource = f"{target}|{pkg}|{vid}"
            sev_map = {
                "Critical": "trivy_vulnerability_critical",
                "High": "trivy_vulnerability_high",
                "Medium": "trivy_vulnerability_medium",
                "Low": "trivy_vulnerability_low",
            }
            issue_key = sev_map.get(severity_raw, "trivy_vulnerability_unknown")
            findings.append(
                build_finding(
                    SERVICE,
                    resource,
                    issue_key,
                    rules,
                    fallback_issue=f"Trivy: {severity_raw} — {title}",
                    fallback_recommendation="Patch or replace affected packages; rebuild container images.",
                    fallback_cis_control_id="CIS-7.0",
                )
            )

    if not findings:
        findings.append(
            build_finding(
                SERVICE,
                scan_target,
                "trivy_no_vulnerabilities_reported",
                rules,
                fallback_issue="Trivy reported no vulnerabilities for this target.",
                fallback_severity="Low",
            )
        )

    return deduplicate_findings(findings)
