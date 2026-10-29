"""Build a boto3 session from the default chain, a profile, or AssumeRole."""

from boto3.session import Session
from botocore.exceptions import (
    ClientError,
    EndpointConnectionError,
    NoCredentialsError,
    PartialCredentialsError,
    ProfileNotFound,
)

from aws_health_audit.aws.clients import RETRY_CONFIG
from aws_health_audit.aws.errors import CredentialsError

ROLE_SESSION_NAME = "aws-health-audit"


def build_session(
    profile: str | None,
    role_arn: str | None = None,
    external_id: str | None = None,
) -> Session:
    """Return a session. AssumeRole uses the base session's credential chain."""
    try:
        base = Session(profile_name=profile) if profile else Session()
    except ProfileNotFound as exc:
        raise CredentialsError(str(exc)) from exc
    if not role_arn:
        return base
    sts = base.client("sts", config=RETRY_CONFIG)
    kwargs: dict[str, str] = {
        "RoleArn": role_arn,
        "RoleSessionName": ROLE_SESSION_NAME,
    }
    if external_id:
        kwargs["ExternalId"] = external_id
    try:
        response = sts.assume_role(**kwargs)
    except (NoCredentialsError, PartialCredentialsError) as exc:
        raise CredentialsError(_credential_message(exc)) from exc
    except ClientError as exc:
        message = exc.response.get("Error", {}).get("Message", str(exc))
        raise CredentialsError(f"AssumeRole failed: {message}") from exc
    except EndpointConnectionError as exc:
        raise CredentialsError(f"Could not reach AWS STS: {exc}") from exc
    credentials = response["Credentials"]
    return Session(
        aws_access_key_id=credentials["AccessKeyId"],
        aws_secret_access_key=credentials["SecretAccessKey"],
        aws_session_token=credentials["SessionToken"],
    )


def require_account_id(session: Session) -> str:
    """Call STS GetCallerIdentity or raise CredentialsError."""
    sts = session.client("sts", config=RETRY_CONFIG)
    try:
        identity = sts.get_caller_identity()
    except (NoCredentialsError, PartialCredentialsError) as exc:
        raise CredentialsError(_credential_message(exc)) from exc
    except ClientError as exc:
        message = exc.response.get("Error", {}).get("Message", str(exc))
        raise CredentialsError(f"Could not resolve the AWS account: {message}") from exc
    except EndpointConnectionError as exc:
        raise CredentialsError(f"Could not reach AWS STS: {exc}") from exc
    return str(identity["Account"])


def discover_regions(session: Session) -> list[str]:
    """Return opted-in region names."""
    home = session.region_name or "us-east-1"
    ec2 = session.client("ec2", region_name=home, config=RETRY_CONFIG)
    try:
        response = ec2.describe_regions(AllRegions=False)
    except (NoCredentialsError, PartialCredentialsError) as exc:
        raise CredentialsError(_credential_message(exc)) from exc
    except ClientError as exc:
        message = exc.response.get("Error", {}).get("Message", str(exc))
        raise CredentialsError(f"Could not list AWS regions: {message}") from exc
    names = sorted(region["RegionName"] for region in response.get("Regions", []))
    if not names:
        raise CredentialsError("No enabled AWS regions were returned.")
    return names


def _credential_message(exc: Exception) -> str:
    text = str(exc).strip()
    if text:
        return text
    return "No AWS credentials found. Set a profile, environment keys, or an instance role."
