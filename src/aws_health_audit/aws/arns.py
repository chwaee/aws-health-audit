"""ARN builders for resources that do not return one."""


def ec2_arn(region: str, account_id: str, resource: str, resource_id: str) -> str:
    return f"arn:aws:ec2:{region}:{account_id}:{resource}/{resource_id}"


def s3_arn(bucket: str) -> str:
    return f"arn:aws:s3:::{bucket}"


def classic_elb_arn(region: str, account_id: str, name: str) -> str:
    return f"arn:aws:elasticloadbalancing:{region}:{account_id}:loadbalancer/{name}"
