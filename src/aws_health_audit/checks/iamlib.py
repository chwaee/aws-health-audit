"""Shared IAM reads for the admin-policy and direct-policy checks."""

from typing import Any

from aws_health_audit.aws.paginate import call, collect
from aws_health_audit.checks.evaluate import is_admin_policy, is_named_admin_policy


def list_iam(client: Any, operation: str, key: str, **kwargs: Any) -> list[dict[str, Any]]:
    """Paginate an IAM list call."""
    return collect(client, operation, key, **kwargs)


def admin_reason(client: Any, kind: str, name: str) -> str | None:
    """Return the policy name that makes this identity an admin, if any.

    AWS managed policies other than AdministratorAccess and IAMFullAccess are
    not downloaded. Customer managed policies and inline policies are.
    """
    attached_operation = {
        "user": "list_attached_user_policies",
        "role": "list_attached_role_policies",
        "group": "list_attached_group_policies",
    }[kind]
    name_key = {"user": "UserName", "role": "RoleName", "group": "GroupName"}[kind]
    attached = list_iam(client, attached_operation, "AttachedPolicies", **{name_key: name})
    for policy in attached:
        policy_name = policy.get("PolicyName")
        policy_arn = policy.get("PolicyArn")
        if is_named_admin_policy(policy_name, policy_arn):
            return str(policy_name)
        if policy_arn and ":iam::aws:" in policy_arn:
            continue
        document = _customer_policy(client, policy_arn) if policy_arn else None
        if is_admin_policy(document):
            return str(policy_name)

    inline_operation = {
        "user": "list_user_policies",
        "role": "list_role_policies",
        "group": "list_group_policies",
    }[kind]
    getter = {"user": "get_user_policy", "role": "get_role_policy", "group": "get_group_policy"}[
        kind
    ]
    for policy_name in list_iam(client, inline_operation, "PolicyNames", **{name_key: name}):
        response = call(client, getter, **{name_key: name, "PolicyName": policy_name}) or {}
        if is_admin_policy(response.get("PolicyDocument")):
            return str(policy_name)
    return None


def has_direct_policy(client: Any, user_name: str) -> bool:
    """True when a user has an attached or inline policy of their own."""
    attached = list_iam(
        client, "list_attached_user_policies", "AttachedPolicies", UserName=user_name
    )
    inline = list_iam(client, "list_user_policies", "PolicyNames", UserName=user_name)
    return bool(attached or inline)


def _customer_policy(client: Any, policy_arn: str) -> dict[str, Any] | None:
    meta = call(client, "get_policy", PolicyArn=policy_arn)
    if not meta:
        return None
    version_id = meta["Policy"]["DefaultVersionId"]
    version = call(client, "get_policy_version", PolicyArn=policy_arn, VersionId=version_id)
    if not version:
        return None
    document = version["PolicyVersion"]["Document"]
    return document if isinstance(document, dict) else None
