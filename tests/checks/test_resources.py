"""Checks against moto resources and small fake clients."""

from datetime import UTC, datetime, timedelta

import boto3
from botocore.exceptions import ClientError
from moto import mock_aws

from aws_health_audit.aws.errors import AccessDeniedError
from aws_health_audit.aws.pricing import downsize_instance_type, lambda_recommended_memory
from aws_health_audit.checks.financial.data_transfer import DataTransferCheck
from aws_health_audit.checks.financial.idle_ec2 import IdleEc2Check
from aws_health_audit.checks.financial.lambda_memory import LambdaMemoryCheck
from aws_health_audit.checks.financial.overprovisioned_ec2 import OverprovisionedEc2Check
from aws_health_audit.checks.financial.unattached_ebs import UnattachedEbsCheck
from aws_health_audit.checks.financial.unused_eips import UnusedEipCheck
from aws_health_audit.checks.security.open_security_groups import OpenSecurityGroupCheck
from aws_health_audit.checks.security.public_s3 import PublicS3Check
from aws_health_audit.config import AppConfig
from aws_health_audit.context import AuditContext, BucketInfo


def test_pricing_helpers():
    assert downsize_instance_type("t3.large") == "t3.medium"
    assert downsize_instance_type("t3.nano") is None
    assert lambda_recommended_memory(100) == 128
    assert lambda_recommended_memory(400) == 512


class _CpuCtx:
    def __init__(
        self, samples: list[tuple[datetime, float]], memory: dict[str, float] | None = None
    ):
        self.account_id = "123456789012"
        self.config = AppConfig()
        self._samples = samples
        self._memory = {} if memory is None else memory

    def instances(self, region: str) -> list[dict]:
        return [
            {
                "InstanceId": "i-abc",
                "InstanceType": "t3.large",
                "State": {"Name": "running"},
                "LaunchTime": datetime.now(UTC) - timedelta(days=30),
                "Tags": [],
            }
        ]

    def cpu_samples(self, region: str) -> dict:
        return {"i-abc": self._samples}

    def memory_used_percent(self, region: str) -> dict[str, float]:
        return self._memory

    def is_ignored(self, *_args: object, **_kwargs: object) -> bool:
        return False


def test_idle_instance_is_not_also_overprovisioned():
    now = datetime.now(UTC)
    samples = [(now - timedelta(hours=index), 1.0) for index in range(48)]
    idle = IdleEc2Check().run(_CpuCtx(samples), "us-east-1")  # type: ignore[arg-type]
    over = OverprovisionedEc2Check().run(_CpuCtx(samples), "us-east-1")  # type: ignore[arg-type]
    assert len(idle) == 1
    assert idle[0].check_id == "COST-EC2-IDLE"
    assert idle[0].estimated_monthly_waste_usd is not None
    assert over == []


def test_overprovisioned_recommends_smaller_type():
    now = datetime.now(UTC)
    samples = [(now - timedelta(hours=index), 10.0) for index in range(24 * 14)]
    findings = OverprovisionedEc2Check().run(
        _CpuCtx(samples, {"i-abc": 15.0}),  # type: ignore[arg-type]
        "us-east-1",
    )
    assert len(findings) == 1
    assert "t3.medium" in findings[0].title
    assert findings[0].evidence["memory_used_percent"] == 15.0


class _DeniedCostExplorer:
    def get_cost_and_usage(self, **_kwargs: object) -> dict:
        raise ClientError(
            {"Error": {"Code": "AccessDeniedException", "Message": "ce:GetCostAndUsage"}},
            "GetCostAndUsage",
        )


class _Clients:
    def client(self, service: str, region: str | None = None) -> _DeniedCostExplorer:
        assert service == "ce"
        return _DeniedCostExplorer()


def test_data_transfer_access_denied_names_the_action():
    ctx = AuditContext(
        session=None,  # type: ignore[arg-type]
        account_id="123456789012",
        regions=["us-east-1"],
        config=AppConfig(),
        clients=_Clients(),  # type: ignore[arg-type]
    )
    try:
        DataTransferCheck().run(ctx, None)
    except AccessDeniedError as exc:
        assert "ce:GetCostAndUsage" in str(exc)
    else:
        raise AssertionError("expected AccessDeniedError")


class _LambdaClient:
    def can_paginate(self, _operation: str) -> bool:
        return False

    def list_functions(self) -> dict:
        return {
            "Functions": [
                {
                    "FunctionName": "billing-hook",
                    "FunctionArn": "arn:aws:lambda:us-east-1:123456789012:function:billing-hook",
                    "MemorySize": 1024,
                    "LastModified": "2020-01-01T00:00:00.000+0000",
                }
            ]
        }


class _LogsClient:
    def can_paginate(self, _operation: str) -> bool:
        return False

    def describe_log_groups(self, **_kwargs: object) -> dict:
        return {"logGroups": [{"logGroupName": "/aws/lambda/billing-hook"}]}

    def start_query(self, **_kwargs: object) -> dict:
        return {"queryId": "q1"}

    def get_query_results(self, **_kwargs: object) -> dict:
        return {
            "status": "Complete",
            "results": [
                [
                    {"field": "@log", "value": "123456789012:/aws/lambda/billing-hook"},
                    {"field": "maxmem", "value": "120"},
                ]
            ],
        }


class _MetricClient:
    def get_metric_data(self, **_kwargs: object) -> dict:
        queries = _kwargs["MetricDataQueries"]
        results = []
        for query in queries:
            metric = query["MetricStat"]["Metric"]["MetricName"]
            value = 1000.0 if metric == "Invocations" else 200.0
            results.append(
                {"Id": query["Id"], "Timestamps": [datetime.now(UTC)], "Values": [value]}
            )
        return {"MetricDataResults": results}


class _Router:
    def client(self, service: str, region: str | None = None) -> object:
        return {"lambda": _LambdaClient(), "logs": _LogsClient(), "cloudwatch": _MetricClient()}[
            service
        ]


def test_lambda_memory_uses_report_lines():
    ctx = AuditContext(
        session=None,  # type: ignore[arg-type]
        account_id="123456789012",
        regions=["us-east-1"],
        config=AppConfig(),
        clients=_Router(),  # type: ignore[arg-type]
    )
    findings = LambdaMemoryCheck().run(ctx, "us-east-1")
    assert len(findings) == 1
    assert findings[0].evidence["max_used_mb"] == 120
    assert findings[0].evidence["recommended_mb"] == 256
    assert findings[0].estimated_monthly_waste_usd is not None


@mock_aws
def test_open_security_group_volume_and_eip():
    ec2 = boto3.client("ec2", region_name="us-east-1")
    vpc_id = ec2.describe_vpcs()["Vpcs"][0]["VpcId"]
    group = ec2.create_security_group(GroupName="ssh-open", Description="test", VpcId=vpc_id)
    ec2.authorize_security_group_ingress(
        GroupId=group["GroupId"],
        IpPermissions=[
            {
                "IpProtocol": "tcp",
                "FromPort": 22,
                "ToPort": 22,
                "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
            }
        ],
    )
    ec2.run_instances(
        ImageId="ami-12345678",
        MinCount=1,
        MaxCount=1,
        InstanceType="t3.micro",
        SecurityGroupIds=[group["GroupId"]],
    )
    ec2.create_volume(AvailabilityZone="us-east-1a", Size=100, VolumeType="gp3")
    ec2.allocate_address(Domain="vpc")
    session = boto3.Session()
    ctx = AuditContext(session, "123456789012", ["us-east-1"], AppConfig())

    groups = OpenSecurityGroupCheck().run(ctx, "us-east-1")
    opened = [item for item in groups if item.resource_id == group["GroupId"]]
    assert opened
    assert opened[0].severity.value == "HIGH"
    assert 22 in opened[0].evidence["ports"]

    volumes = UnattachedEbsCheck().run(ctx, "us-east-1")
    assert volumes
    assert volumes[0].evidence["size_gib"] == 100

    addresses = UnusedEipCheck().run(ctx, None)
    assert addresses.findings
    assert addresses.findings[0].check_id == "COST-EIP-UNUSED"


@mock_aws
def test_public_bucket_acl_is_critical_when_block_public_access_is_off():
    account = boto3.client("sts", region_name="us-east-1").get_caller_identity()["Account"]
    s3 = boto3.client("s3", region_name="us-east-1")
    s3.create_bucket(Bucket="public-data")
    s3.put_public_access_block(
        Bucket="public-data",
        PublicAccessBlockConfiguration={
            "BlockPublicAcls": False,
            "IgnorePublicAcls": False,
            "BlockPublicPolicy": False,
            "RestrictPublicBuckets": False,
        },
    )
    s3.put_bucket_acl(Bucket="public-data", ACL="public-read")
    session = boto3.Session()
    ctx = AuditContext(session, account, ["us-east-1"], AppConfig())
    result = PublicS3Check().run(ctx, None)
    public = [item for item in result.findings if item.resource_id == "public-data"]
    assert result.errors == []
    assert len(public) == 1
    assert public[0].severity.value == "CRITICAL"


def test_ignored_bucket_tag(monkeypatch):
    bucket = BucketInfo(
        "kept", "us-east-1", "arn:aws:s3:::kept", (("aws-health-audit:ignore", "true"),)
    )
    ctx = AuditContext(
        session=None,  # type: ignore[arg-type]
        account_id="123456789012",
        regions=["us-east-1"],
        config=AppConfig(),
        clients=object(),  # type: ignore[arg-type]
    )
    monkeypatch.setattr(ctx, "bucket_index", lambda: [bucket])
    monkeypatch.setattr(ctx, "account_public_access_block", lambda: None)
    result = PublicS3Check().run(ctx, None)
    assert result.findings == []
    assert ctx.ignored_resources == 1
