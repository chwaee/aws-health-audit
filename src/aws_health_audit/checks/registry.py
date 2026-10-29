"""The check catalog. Help text and the runner both use this list."""

from aws_health_audit.checks.base import Check
from aws_health_audit.checks.compliance.access_analyzer import AccessAnalyzerCheck
from aws_health_audit.checks.compliance.cloudtrail_controls import (
    CloudTrailBucketLoggingCheck,
    CloudTrailKmsCheck,
    CloudTrailValidationCheck,
)
from aws_health_audit.checks.compliance.organization import OrganizationCheck
from aws_health_audit.checks.compliance.password_policy import (
    PasswordLengthCheck,
    PasswordReuseCheck,
)
from aws_health_audit.checks.compliance.regional_controls import (
    ConfigRecorderCheck,
    DefaultSecurityGroupCheck,
    EbsDefaultEncryptionCheck,
    GuardDutyCheck,
    Imdsv2Check,
)
from aws_health_audit.checks.compliance.root_hardware_mfa import RootHardwareMfaCheck
from aws_health_audit.checks.compliance.root_keys import RootKeysCheck
from aws_health_audit.checks.compliance.root_use import RootUseCheck
from aws_health_audit.checks.compliance.s3_controls import (
    S3AccountBpaCheck,
    S3BucketBpaCheck,
    S3TlsCheck,
)
from aws_health_audit.checks.compliance.unused_credentials import UnusedCredentialsCheck
from aws_health_audit.checks.compliance.user_mfa import UserMfaCheck
from aws_health_audit.checks.compliance.user_policies import UserDirectPolicyCheck
from aws_health_audit.checks.financial.data_transfer import DataTransferCheck
from aws_health_audit.checks.financial.empty_s3 import EmptyS3Check
from aws_health_audit.checks.financial.idle_ec2 import IdleEc2Check
from aws_health_audit.checks.financial.idle_load_balancers import IdleLoadBalancerCheck
from aws_health_audit.checks.financial.lambda_memory import LambdaMemoryCheck
from aws_health_audit.checks.financial.overprovisioned_ec2 import OverprovisionedEc2Check
from aws_health_audit.checks.financial.stale_snapshots import StaleSnapshotCheck
from aws_health_audit.checks.financial.unattached_ebs import UnattachedEbsCheck
from aws_health_audit.checks.financial.unused_eips import UnusedEipCheck
from aws_health_audit.checks.security.admin_policies import AdminPolicyCheck
from aws_health_audit.checks.security.cloudtrail import CloudTrailCheck
from aws_health_audit.checks.security.old_access_keys import OldAccessKeyCheck
from aws_health_audit.checks.security.open_security_groups import OpenSecurityGroupCheck
from aws_health_audit.checks.security.public_rds import PublicRdsCheck
from aws_health_audit.checks.security.public_s3 import PublicS3Check
from aws_health_audit.checks.security.root_mfa import RootMfaCheck
from aws_health_audit.checks.security.s3_versioning import S3VersioningCheck
from aws_health_audit.checks.security.ssm_agent import SsmAgentCheck
from aws_health_audit.checks.security.unencrypted_ebs import UnencryptedEbsCheck
from aws_health_audit.checks.security.unencrypted_rds import UnencryptedRdsCheck
from aws_health_audit.checks.security.vpc_flow_logs import VpcFlowLogCheck

_CLASSES: tuple[type[Check], ...] = (
    IdleEc2Check,
    OverprovisionedEc2Check,
    UnattachedEbsCheck,
    UnusedEipCheck,
    StaleSnapshotCheck,
    IdleLoadBalancerCheck,
    EmptyS3Check,
    LambdaMemoryCheck,
    DataTransferCheck,
    PublicS3Check,
    PublicRdsCheck,
    OpenSecurityGroupCheck,
    RootMfaCheck,
    OldAccessKeyCheck,
    AdminPolicyCheck,
    UnencryptedEbsCheck,
    UnencryptedRdsCheck,
    CloudTrailCheck,
    S3VersioningCheck,
    VpcFlowLogCheck,
    SsmAgentCheck,
    RootKeysCheck,
    RootHardwareMfaCheck,
    RootUseCheck,
    PasswordLengthCheck,
    PasswordReuseCheck,
    UserMfaCheck,
    UnusedCredentialsCheck,
    UserDirectPolicyCheck,
    S3TlsCheck,
    S3BucketBpaCheck,
    S3AccountBpaCheck,
    EbsDefaultEncryptionCheck,
    CloudTrailValidationCheck,
    ConfigRecorderCheck,
    CloudTrailBucketLoggingCheck,
    CloudTrailKmsCheck,
    DefaultSecurityGroupCheck,
    Imdsv2Check,
    GuardDutyCheck,
    AccessAnalyzerCheck,
    OrganizationCheck,
)


def all_checks() -> list[Check]:
    """Return a new instance of every check, in catalog order."""
    return [cls() for cls in _CLASSES]
