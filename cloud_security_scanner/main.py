"""CLI entry point for cloud security posture scanning."""

from __future__ import annotations

import argparse
from typing import Callable, Dict, List

from cloud_security_scanner.integrations.pacu_integration import scan_pacu
from cloud_security_scanner.integrations.stratus_integration import scan_stratus
from cloud_security_scanner.integrations.trivy_integration import scan_trivy
from cloud_security_scanner.scanners.cloudtrail_advanced import scan_cloudtrail_advanced
from cloud_security_scanner.scanners.cloudtrail_scanner import scan_cloudtrail
from cloud_security_scanner.scanners.ec2_advanced import scan_ec2_advanced
from cloud_security_scanner.scanners.ec2_scanner import scan_ec2
from cloud_security_scanner.scanners.iam_scanner import scan_iam
from cloud_security_scanner.scanners.s3_scanner import scan_s3
from cloud_security_scanner.utils.formatter import generate_report

ScannerFn = Callable[[], List[Dict[str, str]]]


def run_scanner(
    service: str,
    *,
    trivy_target: str,
    trivy_mode: str,
    stratus_results_json: str,
    pacu_results_json: str,
) -> List[Dict[str, str]]:
    """Run one scanner, grouped profiles, or all scanners and return aggregated findings."""
    aws_base_order: List[ScannerFn] = [
        scan_s3,
        scan_iam,
        scan_ec2,
        scan_cloudtrail,
    ]
    aws_extended_order: List[ScannerFn] = [
        scan_s3,
        scan_iam,
        scan_ec2,
        scan_ec2_advanced,
        scan_cloudtrail,
        scan_cloudtrail_advanced,
    ]

    scanner_map: Dict[str, ScannerFn] = {
        "s3": scan_s3,
        "iam": scan_iam,
        "ec2": scan_ec2,
        "ec2_advanced": scan_ec2_advanced,
        "cloudtrail": scan_cloudtrail,
        "cloudtrail_advanced": scan_cloudtrail_advanced,
        "trivy": lambda: scan_trivy(
            scan_target=trivy_target,
            scan_mode=trivy_mode,
        ),
        "stratus": lambda: scan_stratus(
            results_json_path=stratus_results_json or None,
        ),
        "pacu": lambda: scan_pacu(
            results_json_path=pacu_results_json or None,
        ),
    }

    if service == "all":
        findings: List[Dict[str, str]] = []
        for scanner in aws_base_order:
            findings.extend(scanner())
        return findings

    if service == "all_aws":
        findings = []
        for scanner in aws_extended_order:
            findings.extend(scanner())
        return findings

    scanner = scanner_map.get(service)
    if scanner is None:
        raise ValueError(
            "Invalid service. Choose from: s3, iam, ec2, ec2_advanced, cloudtrail, "
            "cloudtrail_advanced, all, all_aws, trivy, stratus, pacu"
        )
    return scanner()


def parse_args() -> argparse.Namespace:
    """Parse CLI arguments."""
    parser = argparse.ArgumentParser(description="Cloud Security Posture Scanner")
    parser.add_argument(
        "--service",
        required=True,
        choices=[
            "s3",
            "iam",
            "ec2",
            "ec2_advanced",
            "cloudtrail",
            "cloudtrail_advanced",
            "all",
            "all_aws",
            "trivy",
            "stratus",
            "pacu",
        ],
        help="Scanner to run, AWS profile (all / all_aws), or external tool.",
    )
    parser.add_argument(
        "--output",
        default="security_report.html",
        help="Output HTML report filename.",
    )
    parser.add_argument(
        "--trivy-target",
        default=".",
        help="Filesystem path or image reference for Trivy (when --service trivy).",
    )
    parser.add_argument(
        "--trivy-mode",
        choices=["fs", "image"],
        default="fs",
        help="Trivy scan mode: filesystem or container image.",
    )
    parser.add_argument(
        "--stratus-results-json",
        default="",
        help="Path to Stratus JSON results file to parse (optional).",
    )
    parser.add_argument(
        "--pacu-results-json",
        default="",
        help="Path to Pacu JSON export to parse (optional).",
    )
    return parser.parse_args()


def main() -> None:
    """Run scanners and generate report outputs."""
    args = parse_args()
    findings = run_scanner(
        args.service,
        trivy_target=args.trivy_target,
        trivy_mode=args.trivy_mode,
        stratus_results_json=args.stratus_results_json,
        pacu_results_json=args.pacu_results_json,
    )
    report_path = generate_report(findings, args.output)
    print(f"Scan completed. Findings: {len(findings)}")
    print(f"HTML report: {report_path}")


if __name__ == "__main__":
    main()
