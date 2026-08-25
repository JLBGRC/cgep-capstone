# Acme Health capstone write-up (cause you said I needed this)

Framework I picked: **HIPAA Security Rule**. The OSCAL `control-implementation.source` is [NIST SP 800-66 Rev. 2](https://csrc.nist.gov/pubs/sp/800/66/r2/final), which is the implementation catalog FRAMEWORKS.md tells us to use because there is no official HIPAA OSCAL catalog. What are you gonna do *shrug*. Anyway, HITRUST CSF IDs are a **crosswalk only**: they live in Rego `secondary_controls` and OSCAL `props`. They are never the policy package primary and never the OSCAL catalog, so the grader’s “one declared catalog” chain stays intact - but some HITRUST stuff seemed kinda natural to me.

This workload is a patient intake HTTP API. That is PHI - so that's gotta be protected, amiright? Encryption at rest under a customer CMK, TLS in transit, least privilege, audit logging, and contingency (S3 versioning plus DynamoDB PITR) are the controls that actually matter here. SOC 2 or CMMC would map onto the same Terraform; they would be a second conversation, not a second design. But this is a capstone, so this is just kinda for fun right now.

## Here's the stuff I did:

All eight starter gaps are closed in Terraform, denied in Rego if they reappear, and described on the OSCAL component.


| Gap    | Why it is a HIPAA issue                                                                  | Terraform                                              | Policy                  |
| ------ | ---------------------------------------------------------------------------------------- | ------------------------------------------------------ | ----------------------- |
| GAP-01 | 164.312(a)(2)(iv), PHI keys under our custody                                            | SSE-KMS + `bucket_key_enabled` on uploads              | `gap01_s3_cmk`          |
| GAP-02 | same encryption requirement on the submissions table                                     | DynamoDB `server_side_encryption` with the data CMK    | `gap02_ddb_cmk`         |
| GAP-03 | 164.312(e)(1): no cleartext to S3, obviously...                                          | bucket policy Deny when `aws:SecureTransport` is false | `gap03_tls`             |
| GAP-04 | 164.308(a)(7), recover overwritten PHI, cause it's important to keep versioning in place | S3 versioning Enabled                                  | `gap04_versioning`      |
| GAP-05 | 164.312(e)(1) / network isolation                                                        | Lambda in **existing** private subnets + SG            | `gap05_vpc`             |
| GAP-06 | 164.308(a)(1) activity / integrity of processing                                         | SQS DLQ, X-Ray Active                                  | `gap06_resilience`      |
| GAP-07 | 164.312(a)(1) least privilege                                                            | `PutItem` / `PutObject` only                           | `gap07_least_privilege` |
| GAP-08 | 164.312(b) audit controls on the front door                                              | API access logs, throttle; WAF ACL created             | `gap08_api_logs`        |


HITRUST mapping used in metadata only: 09.s cryptographic protection, 01.x / 01.t transmission and network, 09.g backup, 01.b least privilege, 06.d logging, 09.j / 10.m monitoring. You probably don't care a whole lot, but I thought it was a fun idea.

## VPC endpoints instead of NAT

The starter private subnets have **no NAT gateway**. Putting Lambda in those subnets without extra networking breaks DynamoDB, S3, Logs, KMS, SQS, and X-Ray. I did not add a second VPC or a NAT (cost, and a wider egress path). Gateway endpoints cover S3 and DynamoDB. Interface endpoints cover Logs, KMS, SQS, and X-Ray. `AWSLambdaVPCAccessExecutionRole` is attached so ENIs can be managed.

The first VPC placement timed out at 15 seconds. The Lambda security group originally allowed 443 only to the VPC CIDR. Gateway endpoints still present **public AWS service prefixes** as the destination, so that SG blocked S3/DynamoDB. The fix was DNS (UDP/TCP 53) to the VPC resolver plus 443 to `0.0.0.0/0`. After that, `make test` returns `"status": "received"`.

## Evidence vault: GOVERNANCE, 30 days (Just to explain)

Lab 2.5 (glad I did the labs first) used GOVERNANCE and **1 day** so the lab could be torn down quickly. The grader Cosign check needs **active** retention, so this vault is GOVERNANCE **30 days**, versioned, SSE-KMS with a dedicated vault CMK. Thus, the switch I made there, friends.

GOVERNANCE rather than COMPLIANCE is a lab choice: this account still needs a break-glass delete after the course (governance-bypass IAM). COMPLIANCE would be the honest production default for a covered entity that cannot afford a privileged delete. I am not pretending 30-day GOVERNANCE is a legal hold. I ain't here to rack up my AWS bill, even pennies. Lean is mean, ya'll.

Apply-on-merge run **32868811171** verified `CHAIN INTACT` (integrity, Cosign/Rekor, retain-until ~2026-09-24). Evidence `href` in OSCAL is the full object URI:

`s3://acme-health-evidence-vault-e6bb03bb/runs/32868811171/evidence-32868811171-f3c8458fdb282239710ba1c4fe56fd0108a4f810.tar.gz`

## Pipeline

GitHub Actions: plan → Conftest on the eight HIPAA packages → Cosign keyless → upload to **this** vault. `terraform apply -auto-approve` runs only when the event is **not** a pull_request, and only after the gate passes.

State is S3 (`acme-health-capstone-tfstate`) with a DynamoDB lock table. That was required before merge: a runner with empty local state would have tried to create a second copy of the stack. The first merge-to-main job failed on a DynamoDB lock plus `terraform plan | tee` under `pipefail` (no `tfplan` file for `terraform show`). The follow-up PR wrote plan output to a file instead of a pipe; apply-on-merge then succeeded.

OIDC trusts `JLBGRC/cgep-capstone`, including the immutable `sub` form (`owner@id` / `repo@id`) because this repo is post-2026-07-15. The account already had a GitHub OIDC provider from Lab 4.x; this stack uses a **data source**, not a second provider. Role: `cgep-capstone-gate`.

EventBridge/SNS also serves 164.312(b) / 164.308(a)(1) beyond GAP-08

**Green PR:** #1 (hardening) merged. **Red PR:** #3 restores `dynamodb:`* on the handler role and is left **unmerged**. The first red check went green because GAP-07 compared against `dynamo:`* (typo) instead of `dynamodb:`*. Fixing the policy made #3 fail closed. That one-line policy fix was cherry-picked to `main` as PR #4 so production Conftest actually matches IAM.

GAP-03 had a similar CI-only miss: on a create-plan with empty state, `planned_values` for the bucket policy JSON is unknown. The policy now also reads `data.aws_iam_policy_document.uploads` in `configuration` for `aws:SecureTransport`.

## Honest skips (My justifications for some design choices)

- **Reserved Lambda concurrency.** This account’s unreserved concurrent-execution floor is 10, so any reservation fails `PutFunctionConcurrency`. DLQ + X-Ray still implement GAP-06.
- **WAFv2 association on HTTP APIs.** `AssociateWebACL` does not accept API Gateway HTTP API stage ARNs (REST stages and ALBs only). `aws_wafv2_web_acl.intake` still exists. GAP-08 is enforced with access logs and throttle. Converting the starter to REST would rewrite the workload.
- **GuardDuty / Macie / Security Hub. Skipped for cost. Detective coverage is CloudTrail plus an EventBridge rule** `aws_cloudwatch_event_rule.kms_key_lifecycle`**) that fires on** `DisableKey` **/** `ScheduleKeyDeletion` **for our data and vault CMKs, publishes to SNS topic** `acme-health-intake-security-alerts-e6bb03bb` **(subscribe** `acme-health-security-ops`**; no emails in git), retries twice, then DLQ. Fixture tests:** `python3 -m unittest discover -s detections -v`**.**
- **Checkov. CI fails closed on HIGH/CRITICAL. Skips:** `CKV_AWS_115` **(reserved concurrency floor),** `CKV_AWS_144` **(CRR cost),** `CKV2_AWS_56` **(OIDC role needs IAM to apply),** `CKV_AWS_356` **/** `109` **/** `111` **(KMS key policies must use** `Resource = "*"`**).**



## How to check my work:

1. `terraform plan` against the S3 backend shows CMK encryption, TLS deny, versioning, `vpc_config`, DLQ/tracing, scoped IAM, API logs + throttle, CloudTrail, vault lock.
2. `opa test ./policies` is 16/16. Conftest against a starter-shaped plan fails closed (red PR #3).
3. `scripts/verify-evidence.sh 32868811171` prints `CHAIN INTACT`.
4. OSCAL `source` is 800-66 Rev. 2. Evidence `href` values are full `s3://bucket/key` URIs, not filenames.
5. `python3 -m unittest discover -s detections -v` is 4/4.
6. GitHub Actions jobs: lint, validate, security, policy-gate.

Enjoy - buddies. <3 JLB