"""Report generation helpers for scanner findings."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Dict, List

from jinja2 import Environment, FileSystemLoader, select_autoescape

from cloud_security_scanner.utils.severity import SEVERITY_ORDER, summarize_by_severity

MAX_HTML_FINDINGS = 1000


def _sort_findings(findings: List[Dict[str, str]]) -> List[Dict[str, str]]:
    """Sort findings by severity desc, then service/resource/issue."""
    return sorted(
        findings,
        key=lambda item: (
            -SEVERITY_ORDER.get(item.get("severity", "Low"), 1),
            item.get("service", ""),
            item.get("resource_id", ""),
            item.get("issue", ""),
        ),
    )


def _summarize_by_service(findings: List[Dict[str, str]]) -> Dict[str, int]:
    """Return finding counts grouped by service."""
    service_summary: Dict[str, int] = {}
    for finding in findings:
        service = finding.get("service", "Unknown")
        service_summary[service] = service_summary.get(service, 0) + 1
    return dict(sorted(service_summary.items(), key=lambda pair: pair[0]))


def generate_report(findings: List[Dict[str, str]], output_file: str) -> Path:
    """Generate HTML and JSON reports from findings."""
    package_root = Path(__file__).resolve().parents[1]
    templates_dir = package_root / "reports" / "templates"
    output_dir = package_root / "reports" / "output"
    output_dir.mkdir(parents=True, exist_ok=True)

    sorted_findings = _sort_findings(findings)
    summary = summarize_by_severity(sorted_findings)
    service_summary = _summarize_by_service(sorted_findings)
    displayed_findings = sorted_findings[:MAX_HTML_FINDINGS]
    truncated_count = max(0, len(sorted_findings) - len(displayed_findings))
    recommendations = sorted(
        {f.get("recommendation", "") for f in sorted_findings if f.get("recommendation")}
    )
    cis_controls = sorted(
        {f.get("cis_control_id", "") for f in sorted_findings if f.get("cis_control_id")}
    )

    env = Environment(
        loader=FileSystemLoader(str(templates_dir)),
        autoescape=select_autoescape(["html", "xml"]),
    )
    template = env.get_template("report.html")
    html_output = template.render(
        findings=displayed_findings,
        total_findings=len(sorted_findings),
        displayed_findings_count=len(displayed_findings),
        truncated_count=truncated_count,
        summary=summary,
        service_summary=service_summary,
        recommendations=recommendations,
        cis_controls=cis_controls,
    )

    html_path = output_dir / output_file
    json_path = output_dir / f"{Path(output_file).stem}.json"

    html_path.write_text(html_output, encoding="utf-8")
    json_path.write_text(
        json.dumps(
            {
                "summary": summary,
                "service_summary": service_summary,
                "recommendations": recommendations,
                "cis_controls": cis_controls,
                "findings": sorted_findings,
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    return html_path

