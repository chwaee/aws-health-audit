"""Decision helpers do not talk to AWS."""

from datetime import UTC, datetime, timedelta
from pathlib import Path

from aws_health_audit.checks.evaluate import (
    acl_grants_are_public,
    bpa_fully_enabled,
    classify_cpu,
    credential_flag,
    effective_s3_public,
    is_admin_policy,
    is_named_admin_policy,
    is_unused,
    name_matches_globs,
    parse_credential_csv,
    parse_credential_time,
    password_length_ok,
    password_reuse_ok,
    permission_opens_admin_port,
    policy_denies_insecure_transport,
    root_credential_row,
    selectors_cover_management_read_write,
    snapshot_is_stale,
    transfer_kind,
    waste_severity,
)
from aws_health_audit.config import Thresholds
from aws_health_audit.models import Severity

NOW = datetime(2026, 4, 1, tzinfo=UTC)
THRESHOLDS = Thresholds()


def test_waste_severity_boundaries():
    assert waste_severity(None, THRESHOLDS) is None
    assert waste_severity(0, THRESHOLDS) is Severity.INFO
    assert waste_severity(19.99, THRESHOLDS) is Severity.LOW
    assert waste_severity(20, THRESHOLDS) is Severity.MEDIUM
    assert waste_severity(100, THRESHOLDS) is Severity.HIGH
    assert waste_severity(500, THRESHOLDS) is Severity.CRITICAL


def test_admin_policy_matrix():
    assert is_admin_policy({"Statement": {"Effect": "Allow", "Action": "*", "Resource": "*"}})
    assert is_admin_policy({"Statement": [{"Effect": "Allow", "Action": "iam:*", "Resource": "*"}]})
    assert not is_admin_policy(
        {"Statement": {"Effect": "Allow", "NotAction": "*", "Resource": "*"}}
    )
    assert not is_admin_policy({"Statement": {"Effect": "Deny", "Action": "*", "Resource": "*"}})
    assert not is_admin_policy(
        {
            "Statement": {
                "Effect": "Allow",
                "Action": "*",
                "Resource": "*",
                "Condition": {"Bool": {"aws:MultiFactorAuthPresent": "true"}},
            }
        }
    )
    assert not is_admin_policy(
        {"Statement": {"Effect": "Allow", "Action": "*", "Resource": "arn:aws:s3:::bucket"}}
    )
    assert is_named_admin_policy("AdministratorAccess")
    assert is_named_admin_policy("Other", "arn:aws:iam::aws:policy/IAMFullAccess")
    assert not is_named_admin_policy("ReadOnlyAccess", "arn:aws:iam::aws:policy/ReadOnlyAccess")


def test_security_group_admin_ports():
    world = {
        "IpProtocol": "tcp",
        "FromPort": 22,
        "ToPort": 22,
        "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
    }
    assert permission_opens_admin_port(world) == {22}
    wide = {
        "IpProtocol": "tcp",
        "FromPort": 0,
        "ToPort": 65535,
        "Ipv6Ranges": [{"CidrIpv6": "::/0"}],
    }
    assert permission_opens_admin_port(wide) == {22, 3389}
    everything = {"IpProtocol": "-1", "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}
    assert permission_opens_admin_port(everything) == {22, 3389}
    private = {
        "IpProtocol": "tcp",
        "FromPort": 22,
        "ToPort": 22,
        "IpRanges": [{"CidrIp": "10.0.0.0/8"}],
    }
    assert permission_opens_admin_port(private) == set()
    udp = {"IpProtocol": "udp", "FromPort": 22, "ToPort": 22, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}
    assert permission_opens_admin_port(udp) == set()


def test_effective_public_access_respects_block_public_access():
    assert effective_s3_public(
        policy_public=True, acl_public=False, bucket_bpa=None, account_bpa=None
    )
    assert not effective_s3_public(
        policy_public=True,
        acl_public=True,
        bucket_bpa=None,
        account_bpa={
            "IgnorePublicAcls": True,
            "RestrictPublicBuckets": True,
        },
    )
    assert effective_s3_public(
        policy_public=False,
        acl_public=True,
        bucket_bpa={"IgnorePublicAcls": False},
        account_bpa=None,
    )
    assert acl_grants_are_public(
        [{"Grantee": {"URI": "http://acs.amazonaws.com/groups/global/AllUsers"}}]
    )
    assert bpa_fully_enabled(
        {
            "BlockPublicAcls": True,
            "IgnorePublicAcls": True,
            "BlockPublicPolicy": True,
            "RestrictPublicBuckets": True,
        }
    )
    assert not bpa_fully_enabled({"BlockPublicAcls": True})


def test_tls_deny_and_trail_selectors():
    policy = {
        "Statement": {
            "Effect": "Deny",
            "Principal": "*",
            "Action": "s3:*",
            "Resource": "*",
            "Condition": {"Bool": {"aws:SecureTransport": "false"}},
        }
    }
    assert policy_denies_insecure_transport(policy)
    assert not policy_denies_insecure_transport({"Statement": []})
    assert selectors_cover_management_read_write(None)
    assert selectors_cover_management_read_write({})
    assert selectors_cover_management_read_write(
        {"EventSelectors": [{"IncludeManagementEvents": True, "ReadWriteType": "All"}]}
    )
    assert not selectors_cover_management_read_write(
        {"EventSelectors": [{"IncludeManagementEvents": True, "ReadWriteType": "WriteOnly"}]}
    )
    assert selectors_cover_management_read_write(
        {
            "AdvancedEventSelectors": [
                {"FieldSelectors": [{"Field": "eventCategory", "Equals": ["Management"]}]}
            ]
        }
    )


def test_cpu_idle_excludes_overprovisioned():
    idle_samples = [(NOW - timedelta(hours=index), 1.0) for index in range(48)]
    idle = classify_cpu(idle_samples, NOW, THRESHOLDS)
    assert idle.kind == "idle"
    over_samples = [(NOW - timedelta(hours=index), 10.0) for index in range(24 * 14)]
    over = classify_cpu(over_samples, NOW, THRESHOLDS)
    assert over.kind == "overprovisioned"
    busy = [(NOW - timedelta(hours=index), 40.0) for index in range(48)]
    assert classify_cpu(busy, NOW, THRESHOLDS).kind == "ok"
    short = [(NOW - timedelta(hours=1), 0.1)]
    assert classify_cpu(short, NOW, THRESHOLDS).kind == "insufficient"


def test_snapshot_age_and_ami_exclusion():
    start = NOW - timedelta(days=120)
    assert snapshot_is_stale(start, "snap-old", set(), NOW, 90)
    assert not snapshot_is_stale(start, "snap-ami", {"snap-ami"}, NOW, 90)
    assert not snapshot_is_stale(NOW - timedelta(days=10), "snap-new", set(), NOW, 90)


def test_credential_report_and_password_policy():
    text = Path("tests/fixtures/credential_report.csv").read_text(encoding="utf-8")
    rows = parse_credential_csv(text)
    root = root_credential_row(rows)
    assert root is not None
    assert not credential_flag(root, "mfa_active")
    assert credential_flag(root, "access_key_1_active")
    rotated = parse_credential_time("2020-01-01T00:00:00.000+0000")
    assert rotated is not None
    assert rotated.tzinfo is not None
    assert is_unused(None, NOW - timedelta(days=90), NOW, 45)
    assert not is_unused(NOW - timedelta(days=3), NOW - timedelta(days=90), NOW, 45)
    assert password_length_ok({"MinimumPasswordLength": 14})
    assert not password_length_ok(None)
    assert password_reuse_ok({"PasswordReusePrevention": 24})
    assert not password_reuse_ok({"PasswordReusePrevention": 5})
    assert name_matches_globs("prod-logs", ("prod-*",))
    assert not name_matches_globs("dev-logs", ("prod-*",))


def test_transfer_kind():
    assert transfer_kind("USE1-DataTransfer-Out-Bytes") == "internet-egress"
    assert transfer_kind("DataTransfer-Regional-Bytes") == "inter-region"
    assert transfer_kind("USE1-USE2-AWS-Out-Bytes") == "inter-region"
    assert transfer_kind("USE2-DataTransfer-In-Bytes") is None
    assert transfer_kind("BoxUsage:t3.micro") is None
