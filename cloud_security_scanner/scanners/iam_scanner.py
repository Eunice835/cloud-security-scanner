"""IAM scanner for over-permissive access and inactive credentials."""

from __future__ import annotations

from typing import Dict, Iterable, List

import boto3
from botocore.exceptions import BotoCoreError, ClientError

from cloud_security_scanner.utils.severity import build_finding, load_cis_rules

SERVICE = "IAM"


def _deduplicate_findings(findings: List[Dict[str, str]]) -> List[Dict[str, str]]:
    """Remove identical findings while preserving order."""
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


def _paginate(iam_client, operation_name: str, result_key: str, **kwargs) -> List[Dict]:
    """Use IAM paginator for list calls and flatten paged results."""
    paginator = iam_client.get_paginator(operation_name)
    items: List[Dict] = []
    for page in paginator.paginate(**kwargs):
        items.extend(page.get(result_key, []))
    return items


def _to_list(value) -> List[str]:
    """Normalize IAM policy values to list format."""
    if isinstance(value, list):
        return value
    if isinstance(value, str):
        return [value]
    return []


def _is_over_permissive(policy_document: Dict) -> bool:
    """Check if a policy statement allows wildcard action and resource."""
    statements = policy_document.get("Statement", [])
    if isinstance(statements, dict):
        statements = [statements]

    for statement in statements:
        if statement.get("Effect") != "Allow":
            continue
        actions = _to_list(statement.get("Action"))
        resources = _to_list(statement.get("Resource"))
        action_wildcard = "*" in actions or any(a.endswith(":*") for a in actions)
        resource_wildcard = "*" in resources
        if action_wildcard and resource_wildcard:
            return True
    return False


def _iter_policies(iam_client, entity_type: str, entity_name: str) -> Iterable[Dict]:
    """Yield all inline and attached managed policy documents for an entity."""
    if entity_type == "user":
        inline = _paginate(
            iam_client,
            "list_user_policies",
            "PolicyNames",
            UserName=entity_name,
        )
        for name in inline:
            yield iam_client.get_user_policy(UserName=entity_name, PolicyName=name).get(
                "PolicyDocument", {}
            )
        attached = _paginate(
            iam_client,
            "list_attached_user_policies",
            "AttachedPolicies",
            UserName=entity_name,
        )
    elif entity_type == "group":
        inline = _paginate(
            iam_client,
            "list_group_policies",
            "PolicyNames",
            GroupName=entity_name,
        )
        for name in inline:
            yield iam_client.get_group_policy(GroupName=entity_name, PolicyName=name).get(
                "PolicyDocument", {}
            )
        attached = _paginate(
            iam_client,
            "list_attached_group_policies",
            "AttachedPolicies",
            GroupName=entity_name,
        )
    else:
        inline = _paginate(
            iam_client,
            "list_role_policies",
            "PolicyNames",
            RoleName=entity_name,
        )
        for name in inline:
            yield iam_client.get_role_policy(RoleName=entity_name, PolicyName=name).get(
                "PolicyDocument", {}
            )
        attached = _paginate(
            iam_client,
            "list_attached_role_policies",
            "AttachedPolicies",
            RoleName=entity_name,
        )

    for policy in attached:
        arn = policy.get("PolicyArn")
        if not arn:
            continue
        metadata = iam_client.get_policy(PolicyArn=arn).get("Policy", {})
        version_id = metadata.get("DefaultVersionId")
        if not version_id:
            continue
        yield iam_client.get_policy_version(PolicyArn=arn, VersionId=version_id).get(
            "PolicyVersion", {}
        ).get("Document", {})


def _scan_entity_permissions(
    iam_client, entity_type: str, entity_name: str, rules: Dict
) -> List[Dict[str, str]]:
    """Scan one IAM principal type for over-permissive access."""
    try:
        for policy_doc in _iter_policies(iam_client, entity_type, entity_name):
            if _is_over_permissive(policy_doc):
                return [
                    build_finding(
                        SERVICE,
                        entity_name,
                        "iam_over_permissive",
                        rules,
                        fallback_issue=f"IAM {entity_type} is over-permissive.",
                    )
                ]
        return []
    except (ClientError, BotoCoreError):
        return [
            build_finding(
                SERVICE,
                entity_name,
                "unable_validate_iam_permissions",
                rules,
                fallback_issue=f"Unable to validate IAM {entity_type} policies.",
            )
        ]


def _scan_user_credentials(iam_client, user_name: str, rules: Dict) -> List[Dict[str, str]]:
    """Detect inactive IAM user credentials."""
    try:
        access_keys = _paginate(
            iam_client,
            "list_access_keys",
            "AccessKeyMetadata",
            UserName=user_name,
        )
        for key in access_keys:
            if key.get("Status") == "Inactive":
                return [
                    build_finding(
                        SERVICE,
                        user_name,
                        "iam_inactive_credentials",
                        rules,
                        fallback_issue="IAM user has inactive access keys.",
                    )
                ]
        return []
    except (ClientError, BotoCoreError):
        return [
            build_finding(
                SERVICE,
                user_name,
                "unable_validate_iam_credentials",
                rules,
                fallback_issue="Unable to validate IAM user credentials.",
            )
        ]


def scan_iam() -> List[Dict[str, str]]:
    """Scan IAM users, groups, and roles for risky configurations."""
    iam_client = boto3.client("iam")
    rules = load_cis_rules()
    findings: List[Dict[str, str]] = []

    try:
        users = _paginate(iam_client, "list_users", "Users")
        groups = _paginate(iam_client, "list_groups", "Groups")
        roles = _paginate(iam_client, "list_roles", "Roles")
    except (ClientError, BotoCoreError):
        return [
            build_finding(
                SERVICE,
                "account",
                "unable_validate_iam_list",
                rules,
                fallback_issue="Unable to list IAM resources.",
            )
        ]

    for user in users:
        user_name = user.get("UserName")
        if not user_name:
            continue
        findings.extend(_scan_entity_permissions(iam_client, "user", user_name, rules))
        findings.extend(_scan_user_credentials(iam_client, user_name, rules))

    for group in groups:
        group_name = group.get("GroupName")
        if not group_name:
            continue
        findings.extend(_scan_entity_permissions(iam_client, "group", group_name, rules))

    for role in roles:
        role_name = role.get("RoleName")
        if not role_name:
            continue
        findings.extend(_scan_entity_permissions(iam_client, "role", role_name, rules))

    return _deduplicate_findings(findings)

