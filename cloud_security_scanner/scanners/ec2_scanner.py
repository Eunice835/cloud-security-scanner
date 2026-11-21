"""EC2 scanner for risky inbound security group rules."""

from __future__ import annotations

from typing import Dict, List, Set

import boto3
from botocore.exceptions import BotoCoreError, ClientError

from cloud_security_scanner.utils.severity import build_finding, load_cis_rules

SERVICE = "EC2"
CRITICAL_PORTS = {22, 80, 443, 3389}
SECURITY_GROUP_BATCH_SIZE = 100


def _deduplicate_findings(findings: List[Dict[str, str]]) -> List[Dict[str, str]]:
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


def _paginate_instances(ec2_client) -> List[Dict]:
    """Paginate through all EC2 instance reservation pages."""
    paginator = ec2_client.get_paginator("describe_instances")
    reservations: List[Dict] = []
    for page in paginator.paginate():
        reservations.extend(page.get("Reservations", []))
    return reservations


def _chunked(values: List[str], size: int) -> List[List[str]]:
    """Split a list into fixed-size chunks."""
    return [values[idx : idx + size] for idx in range(0, len(values), size)]


def _is_public_range(ip_permissions: List[Dict]) -> bool:
    """Return True if any IPv4 permission allows 0.0.0.0/0."""
    for permission in ip_permissions:
        for ip_range in permission.get("IpRanges", []):
            if ip_range.get("CidrIp") == "0.0.0.0/0":
                return True
    return False


def _has_critical_port_exposure(ip_permissions: List[Dict]) -> bool:
    """Return True when critical ports are exposed publicly."""
    for permission in ip_permissions:
        protocol = permission.get("IpProtocol")
        from_port = permission.get("FromPort")
        to_port = permission.get("ToPort")
        if protocol == "-1":
            return _is_public_range([permission])
        if from_port is None or to_port is None:
            continue
        for port in CRITICAL_PORTS:
            if from_port <= port <= to_port and _is_public_range([permission]):
                return True
    return False


def scan_ec2() -> List[Dict[str, str]]:
    """Scan EC2 instances and attached security groups for open critical ports."""
    ec2_client = boto3.client("ec2")
    rules = load_cis_rules()
    findings: List[Dict[str, str]] = []

    try:
        reservations = _paginate_instances(ec2_client)
    except (ClientError, BotoCoreError):
        return [
            build_finding(
                SERVICE,
                "account",
                "unable_validate_ec2_list",
                rules,
                fallback_issue="Unable to list EC2 instances.",
            )
        ]

    for reservation in reservations:
        for instance in reservation.get("Instances", []):
            instance_id = instance.get("InstanceId", "unknown-instance")
            security_group_ids: Set[str] = {
                sg.get("GroupId")
                for sg in instance.get("SecurityGroups", [])
                if sg.get("GroupId")
            }
            if not security_group_ids:
                continue
            try:
                group_ids = sorted(security_group_ids)
                for group_batch in _chunked(group_ids, SECURITY_GROUP_BATCH_SIZE):
                    groups = ec2_client.describe_security_groups(
                        GroupIds=group_batch
                    ).get("SecurityGroups", [])
                    for group in groups:
                        if _has_critical_port_exposure(group.get("IpPermissions", [])):
                            findings.append(
                                build_finding(
                                    SERVICE,
                                    instance_id,
                                    "ec2_sg_open_critical_ports",
                                    rules,
                                    fallback_issue="EC2 instance security group exposes critical ports.",
                                )
                            )
                            break
                    else:
                        continue
                    break
            except (ClientError, BotoCoreError):
                findings.append(
                    build_finding(
                        SERVICE,
                        instance_id,
                        "unable_validate_ec2_sg",
                        rules,
                        fallback_issue="Unable to validate EC2 security group rules.",
                    )
                )
    return _deduplicate_findings(findings)

