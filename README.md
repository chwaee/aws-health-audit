# aws-health-audit

Read-only audit of one AWS account. It looks for cost waste, exposed resources, and a practical subset of the CIS AWS Foundations Benchmark v3.0.0, then writes a report a person can read and a JSON document a pipeline can parse.

Run it before a bill review, a security questionnaire, or a handover. It does not change the account, schedule itself, or crawl member accounts.

## Related tools

| Tool | Use it for |
| --- | --- |
| [HarderAWS](https://github.com/chwaee/HarderAWS) | Apply security hardening after the audit |
| [tf-cost-preview](https://github.com/chwaee/tf-cost-preview) | Estimate plan costs before apply |
| [secure-ci-templates](https://github.com/chwaee/secure-ci-templates) | GitHub Actions workflows for client repos |
| [appliedaiconsulting.io](https://appliedaiconsulting.io) | Consulting services |

## Install

Python 3.11 or newer.

```bash
pip install .
aws-health-audit --help
```

`pipx install .` works the same way. After this package is published, `pip install aws-health-audit` is the same entry point.

Development install:

```bash
pip install -e ".[dev]"
```

## Usage

```bash
aws-health-audit --profile client-audit
aws-health-audit --profile client-audit --regions us-east-1,eu-west-1
aws-health-audit --role-arn arn:aws:iam::123456789012:role/Audit --external-id engagement-42
aws-health-audit --format json --output-file report.json
aws-health-audit --skip-checks financial,compliance
aws-health-audit --only-checks security --fail-on high
```

`--format` chooses what is written to stdout. `--output-file` writes those same bytes to disk. Progress lines go to stderr, so JSON stays pipe-safe. `--quiet` hides the progress.

Exit codes:

| Code | Meaning |
| --- | --- |
| 0 | The audit finished. Findings do not fail the process unless you set `--fail-on`. |
| 1 | A finding is at least as severe as `--fail-on`. |
| 2 | The audit could not start: bad config, missing credentials, or assume-role failed. |

A check that is denied in one region is listed under `CHECKS NOT COMPLETED`. The rest of the audit still finishes.

## Authentication

The tool uses the standard AWS credential chain: environment variables, an instance or task role, then `~/.aws`. `--profile` selects a profile. `--role-arn` calls `sts:AssumeRole` on that chain. Pass `--external-id` when the role trust policy requires one. The session name is `aws-health-audit`.

No keys are written to disk. Temporary assume-role credentials live only in the process.

## Checks

CIS ids are from the CIS AWS Foundations Benchmark v3.0.0. A blank CIS column means the check is not labeled as a current v3.0.0 control. `SEC-IAM-ADMIN` used to be control 1.16 in v1.4. v3.0.0 dropped it. The finding still reports full administrator access, and it says so.

| Check | Area | CIS | What it flags |
| --- | --- | --- | --- |
| `COST-EC2-IDLE` | cost | | Running instances whose average CPU stays under the idle threshold. |
| `COST-EC2-OVERPROV` | cost | | Running instances with sustained low CPU that can move down a size. |
| `COST-EBS-UNATTACHED` | cost | | EBS volumes in the available state. |
| `COST-EIP-UNUSED` | cost | | Elastic IP addresses that are not associated with a resource. |
| `COST-SNAP-STALE` | cost | | Snapshots older than the age threshold that no owned AMI references. |
| `COST-ELB-IDLE` | cost | | Load balancers that have no registered targets. |
| `COST-S3-EMPTY` | cost | | Empty or near-empty buckets, and incomplete multipart uploads. |
| `COST-LAMBDA-MEM` | cost | | Functions with unused memory headroom or no recent invocations. |
| `COST-DATA-TRANSFER` | cost | | Internet egress and cross-region data transfer above the cost threshold. |
| `SEC-S3-PUBLIC` | security | | Buckets whose ACL or policy allows public access despite Block Public Access. |
| `SEC-RDS-PUBLIC` | security | | RDS instances that have a publicly reachable endpoint. |
| `SEC-SG-ADMIN-OPEN` | security | 5.2, 5.3 | Security groups that allow SSH or RDP from the internet. |
| `SEC-IAM-ROOT-MFA` | security | 1.5 | Root user without MFA enabled. |
| `SEC-IAM-OLD-KEYS` | security | 1.14 | Active IAM access keys older than the rotation threshold. |
| `SEC-IAM-ADMIN` | security | | IAM users, groups, and roles with administrator or iam:* access. |
| `SEC-EBS-UNENCRYPTED` | security | | EBS volumes that do not have encryption at rest. |
| `SEC-RDS-UNENCRYPTED` | security | | RDS instances and clusters without storage encryption. |
| `SEC-CLOUDTRAIL` | security | 3.1 | No multi-region CloudTrail trail logging read and write management events. |
| `SEC-S3-VERSIONING` | security | | S3 buckets that do not have versioning enabled. |
| `SEC-VPC-FLOW-LOGS` | security | 3.7 | VPCs that do not have an active VPC-level flow log. |
| `SEC-SSM-AGENT` | security | | Running EC2 instances where the SSM agent is not online. |
| `CIS-1.4-ROOT-KEYS` | compliance | 1.4 | Root user has an active access key. |
| `CIS-1.6-ROOT-HW-MFA` | compliance | 1.6 | Root MFA is a virtual device instead of a hardware key. |
| `CIS-1.7-ROOT-USE` | compliance | 1.7 | Root password or access key was used recently. |
| `CIS-1.8-PASSWORD-LENGTH` | compliance | 1.8 | IAM password policy does not require 14 characters. |
| `CIS-1.9-PASSWORD-REUSE` | compliance | 1.9 | IAM password policy does not remember 24 passwords. |
| `CIS-1.10-USER-MFA` | compliance | 1.10 | IAM users with a console password and no MFA. |
| `CIS-1.12-UNUSED-CREDS` | compliance | 1.12 | IAM passwords or access keys unused for 45 days or more. |
| `CIS-1.15-USER-POLICIES` | compliance | 1.15 | IAM users with a policy attached directly instead of through a group. |
| `CIS-2.1.1-S3-TLS` | compliance | 2.1.1 | S3 buckets that do not deny non-TLS requests. |
| `CIS-2.1.4-S3-BPA` | compliance | 2.1.4 | S3 buckets missing one or more Block Public Access settings. |
| `CIS-S3-ACCOUNT-BPA` | compliance | | Account-level S3 Block Public Access is not fully enabled. |
| `CIS-2.2.1-EBS-DEFAULT-ENC` | compliance | 2.2.1 | Regions where EBS encryption by default is disabled. |
| `CIS-3.2-CT-VALIDATION` | compliance | 3.2 | Multi-region trails that are logging without log file validation. |
| `CIS-3.3-CONFIG` | compliance | 3.3 | Regions where AWS Config is not recording. |
| `CIS-3.4-CT-BUCKET-LOGGING` | compliance | 3.4 | CloudTrail log buckets that do not have S3 server access logging. |
| `CIS-3.5-CT-KMS` | compliance | 3.5 | Multi-region trails that are logging without a KMS key. |
| `CIS-5.4-DEFAULT-SG` | compliance | 5.4 | Default security groups that allow inbound or outbound traffic. |
| `CIS-5.6-IMDSV2` | compliance | 5.6 | Running instances that do not require IMDSv2. |
| `CIS-GUARDDUTY` | compliance | | Regions with no enabled GuardDuty detector. |
| `CIS-ACCESS-ANALYZER` | compliance | | No active IAM Access Analyzer in the account. |
| `GRD-ORG` | compliance | | Organization, SCP, organization trail, and Control Tower posture. |

`aws-health-audit --help` prints the same ids.

## How to read a finding

Severity is about what to do next, not a compliance score.

- **Critical.** Public data, root without MFA, a root access key, CloudTrail not logging, or estimated waste of at least $500 a month.
- **High.** Internet SSH or RDP on a group that is in use, a public or unencrypted database, administrator access on a user, IMDSv1 on a running instance, GuardDuty off, or waste of at least $100 a month.
- **Medium.** Fix in the next change window. Includes most CIS gaps and waste of at least $20 a month.
- **Low.** Cleanup. Unused addresses, empty buckets, direct user policies.
- **Info.** Context, not a failure. A standalone account, a new instance still inside the SSM grace period, or incomplete metrics.

Dollar amounts are estimates. `estimate_source` in the JSON is `rate_card` or `cost_explorer`. Rate-card figures use public us-east-1 style on-demand prices and are directional. Snapshot figures use the source volume size, which is higher than the incremental data AWS bills. Data transfer figures are Cost Explorer unblended cost for the last 30 days.

`CHECKS NOT COMPLETED` means that check did not get to decide. The usual cause is a missing permission. The line names the API error. Grant it and rerun. Do not treat a missing section as a pass.

`FINANCIAL FINDINGS` repeats the cost items, sorted by estimated waste, and reuses the numbers from the severity sections.

JSON reports use `schema_version` `1.0`.

## Configuration

Copy `config.example.yaml` to `config.yaml` in the working directory, or pass `--config`. CLI flags win over the file for regions, skipped checks, and worker count.

Unknown keys are an error, so a typo does not silently do nothing.

Skip a category or a check:

```yaml
checks:
  disabled:
    - financial
    - CIS-GUARDDUTY
```

`financial` is an alias for `cost`.

Ignore a resource with the tag `aws-health-audit:ignore` set to `true` or to the check id, or list its id or ARN under `ignore_resources`. The JSON metadata counts how many resources were ignored.

`critical_buckets` is a list of globs. A bucket that matches and has versioning off is HIGH instead of LOW.

## Permissions

Attach [docs/readonly-policy.json](docs/readonly-policy.json) to the role you audit with.

Two calls are easy to miss:

- `iam:GenerateCredentialReport` refreshes the credential report. It does not change users, keys, or policies. IAM still classifies it as a write action, so a blanket `iam:Get*` policy is not enough.
- `ce:GetCostAndUsage` is required for the data transfer check. Without it, that check shows up under `CHECKS NOT COMPLETED` and the rest of the report still runs.

`organizations:DescribeOrganization` denied on a standalone account becomes an informational finding, not a failed check.

## Limits

- One account per run. `--role-arn` is a single assume-role hop, not a crawl of an organization.
- No remediation. The report tells you what to change. It does not change it.
- Prices are not an invoice. Confirm anything you would put in front of a finance owner in Cost Explorer.
- EC2 memory headroom needs the CloudWatch agent metric `mem_used_percent`. Without it, the overprovisioned check says memory is unknown and still reports low CPU.
- Lambda memory comes from `REPORT` lines in CloudWatch Logs. A function that has not logged a report in the lookback window is judged on invocations instead.
- S3 size uses the daily `BucketSizeBytes` metric. A brand-new bucket may not have it yet. The check then lists at most one object.
- Multipart upload pricing stops after 200 uploads per bucket and says so in the evidence.
- This is not a CIS certification. It is the high-value slice of v3.0.0 plus the cost and exposure checks above.

## Development

```bash
ruff check .
ruff format --check .
pytest
```

Tests use moto and fake clients. They do not call AWS.

## Consulting

I run this audit against your account and walk through every critical and high finding with you. You supply a role that can assume the read-only policy above, with an external id if you want one. The output is the report from this tool, plus the conversation about which items are real risk and which are accepted.

CONTACT: hello@appliedaiconsulting.io
