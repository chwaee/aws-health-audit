"""Pagination walks every page, not the first hundred."""

import boto3
from moto import mock_aws

from aws_health_audit.aws.paginate import paginate


@mock_aws
def test_describe_volumes_returns_every_page():
    ec2 = boto3.client("ec2", region_name="us-east-1")
    for _ in range(120):
        ec2.create_volume(AvailabilityZone="us-east-1a", Size=1, VolumeType="gp3")
    pages = list(paginate(ec2, "describe_volumes", PaginationConfig={"PageSize": 50}))
    volume_ids = [volume["VolumeId"] for page in pages for volume in page.get("Volumes", [])]
    assert len(volume_ids) == 120
    assert len(set(volume_ids)) == 120


def test_manual_next_token_is_followed():
    class _Client:
        def can_paginate(self, _operation: str) -> bool:
            return False

        def describe_volumes(self, **kwargs: object) -> dict:
            if kwargs.get("NextToken") is None:
                first = [{"VolumeId": f"vol-{index}"} for index in range(10)]
                return {"Volumes": first, "NextToken": "page-2"}
            rest = [{"VolumeId": f"vol-{index}"} for index in range(10, 25)]
            return {"Volumes": rest}

    pages = list(paginate(_Client(), "describe_volumes"))
    volume_ids = [volume["VolumeId"] for page in pages for volume in page["Volumes"]]
    assert volume_ids == [f"vol-{index}" for index in range(25)]
