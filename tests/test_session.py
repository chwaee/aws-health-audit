"""AssumeRole forwards the external id."""

from datetime import UTC, datetime

import boto3
import pytest
from botocore.stub import Stubber

from aws_health_audit.aws.errors import CredentialsError
from aws_health_audit.session import build_session


def test_assume_role_passes_external_id(monkeypatch: pytest.MonkeyPatch):
    base = boto3.Session()
    sts = base.client("sts", region_name="us-east-1")
    stubber = Stubber(sts)
    stubber.add_response(
        "assume_role",
        {
            "Credentials": {
                "AccessKeyId": "AKIATESTTESTTEST",
                "SecretAccessKey": "secret",
                "SessionToken": "token",
                "Expiration": datetime(2026, 4, 1, tzinfo=UTC),
            }
        },
        {
            "RoleArn": "arn:aws:iam::123456789012:role/Audit",
            "RoleSessionName": "aws-health-audit",
            "ExternalId": "outside",
        },
    )
    stubber.activate()
    calls = {"count": 0}

    class _First:
        def client(self, name: str, **_kwargs: object) -> object:
            assert name == "sts"
            return sts

    def factory(**_kwargs: object) -> object:
        calls["count"] += 1
        if calls["count"] == 1:
            return _First()
        return boto3.Session(
            aws_access_key_id="AKIATESTTESTTEST",
            aws_secret_access_key="secret",
            aws_session_token="token",
        )

    monkeypatch.setattr("aws_health_audit.session.Session", factory)
    session = build_session(
        None,
        "arn:aws:iam::123456789012:role/Audit",
        "outside",
    )
    credentials = session.get_credentials()
    assert credentials is not None
    assert credentials.access_key == "AKIATESTTESTTEST"
    stubber.assert_no_pending_responses()


def test_missing_profile(monkeypatch: pytest.MonkeyPatch):
    def factory(**_kwargs: object) -> object:
        from botocore.exceptions import ProfileNotFound

        raise ProfileNotFound(profile="missing")

    monkeypatch.setattr("aws_health_audit.session.Session", factory)
    with pytest.raises(CredentialsError):
        build_session("missing")
