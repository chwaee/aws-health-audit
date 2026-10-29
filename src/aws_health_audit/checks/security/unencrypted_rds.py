"""RDS storage that is not encrypted."""

from aws_health_audit.aws.paginate import collect
from aws_health_audit.checks.base import Check, Scope, finding
from aws_health_audit.context import AuditContext
from aws_health_audit.models import Category, Finding, Severity


class UnencryptedRdsCheck(Check):
    """Unencrypted clusters, plus unencrypted instances that are not in a cluster."""

    id = "SEC-RDS-UNENCRYPTED"
    title = "Unencrypted RDS storage"
    category = Category.SECURITY
    scope = Scope.REGIONAL
    description = "RDS instances and clusters without storage encryption."

    def run(self, ctx: AuditContext, region: str | None) -> list[Finding]:
        assert region is not None
        client = ctx.client("rds", region)
        findings: list[Finding] = []
        for cluster in collect(client, "describe_db_clusters", "DBClusters"):
            if cluster.get("StorageEncrypted"):
                continue
            name = cluster.get("DBClusterIdentifier", "unknown")
            arn = cluster.get("DBClusterArn")
            if ctx.is_ignored(self.id, resource_id=name, arn=arn):
                continue
            findings.append(_item(self, region, name, arn, "cluster", cluster.get("Engine")))
        for instance in collect(client, "describe_db_instances", "DBInstances"):
            if instance.get("StorageEncrypted") or instance.get("DBClusterIdentifier"):
                continue
            name = instance.get("DBInstanceIdentifier", "unknown")
            arn = instance.get("DBInstanceArn")
            if ctx.is_ignored(self.id, resource_id=name, arn=arn):
                continue
            findings.append(_item(self, region, name, arn, "instance", instance.get("Engine")))
        return findings


def _item(
    check: Check, region: str, name: str, arn: str | None, kind: str, engine: str | None
) -> Finding:
    return finding(
        check,
        title=f"Unencrypted RDS {kind}: {name}",
        severity=Severity.HIGH,
        impact="Database storage and its automated backups can be read without a KMS key.",
        recommendation=(
            f"Restore {name} from a snapshot into an encrypted {kind}. "
            "Encryption cannot be turned on in place."
        ),
        region=region,
        resource_arn=arn,
        resource_id=name,
        evidence={"engine": engine, "resource_kind": kind},
    )
