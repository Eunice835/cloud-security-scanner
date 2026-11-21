"""Unit tests for optional external tool integrations."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

from cloud_security_scanner.integrations.pacu_integration import scan_pacu
from cloud_security_scanner.integrations.stratus_integration import scan_stratus
from cloud_security_scanner.integrations.trivy_integration import scan_trivy


def test_stratus_parses_results_json(tmp_path: Path) -> None:
    """Stratus JSON list maps to standardized findings."""
    payload = [
        {"technique_id": "aws.exfiltration.example", "status": "success", "note": "unit"},
    ]
    target = tmp_path / "stratus.json"
    target.write_text(json.dumps(payload), encoding="utf-8")
    findings = scan_stratus(results_json_path=str(target))
    assert any(f["resource_id"] == "aws.exfiltration.example" for f in findings)


def test_pacu_parses_results_json(tmp_path: Path) -> None:
    """Pacu JSON export maps to standardized findings."""
    payload = [
        {"module": "iam__enum_users_roles_groups_policies", "severity": "High", "details": "x"},
    ]
    target = tmp_path / "pacu.json"
    target.write_text(json.dumps(payload), encoding="utf-8")
    findings = scan_pacu(results_json_path=str(target))
    assert any("iam__enum_users_roles_groups_policies" in f["resource_id"] for f in findings)


@patch("cloud_security_scanner.integrations.trivy_integration.subprocess.run")
@patch("cloud_security_scanner.integrations.trivy_integration.shutil.which")
def test_trivy_parses_stdout_json(mock_which, mock_run) -> None:
    """Trivy stdout JSON is normalized into findings."""
    mock_which.return_value = "/fake/trivy"
    mock_run.return_value = MagicMock(
        returncode=0,
        stdout=json.dumps(
            {
                "Results": [
                    {
                        "Target": "debian",
                        "Vulnerabilities": [
                            {
                                "VulnerabilityID": "CVE-9999-1",
                                "Severity": "HIGH",
                                "Title": "Test issue",
                                "PkgName": "curl",
                            }
                        ],
                    }
                ]
            }
        ),
        stderr="",
    )
    findings = scan_trivy(scan_target=".", scan_mode="fs")
    assert any("CVE-9999-1" in f["resource_id"] for f in findings)


@patch("cloud_security_scanner.integrations.trivy_integration.shutil.which", return_value=None)
def test_trivy_missing_cli(mock_which) -> None:
    """Missing Trivy binary returns a safe finding."""
    findings = scan_trivy(scan_target=".")
    assert findings and "trivy" in findings[0]["issue"].lower()
