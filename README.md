# Acme Health: CGE-P capstone

Patient Intake API for Acme Health. PHI in, HIPAA Security Rule as the primary framework, HITRUST CSF as a crosswalk in metadata only (just for fun). Narrative is in [WRITEUP.md](WRITEUP.md). Named gaps: [GAPS.md](GAPS.md).

## Grader verify

```bash
make creds AWS_PROFILE=default
make test AWS_PROFILE=default
# expect: "status": "received"

opa test ./policies -v
# expect: PASS: 16/16

export EVIDENCE_VAULT=acme-health-evidence-vault-e6bb03bb
scripts/verify-evidence.sh 32868811171 --profile default
# expect: CHAIN INTACT
```

Since I know you're looking for it: OSCAL lives under `oscal/`. Catalog source is NIST SP 800-66 Rev. 2. Evidence `href`s are full `s3://bucket/key` URIs, not filenames.

Repo vars for the gate: `AWS_ROLE_ARN` (`cgep-capstone-gate`), `EVIDENCE_VAULT` (the 30-day GOVERNANCE vault).

**Green PR:** #1 (merged). **Red PR:** #3 (`dynamodb:`*, left open). **Do not** commit `*.tfstate`. There was some funny business on the Red PR and the wildcard there with dynamo - took me a minute to diagnose. You can read all about it in [WRITEUP.md](WRITEUP.md).

## Layout

```
terraform/     # starter + HIPAA overrides (main.tf, baseline.tf, monitoring.tf)
policies/      # eight HIPAA Rego packages + tests
detections/    # EventBridge fixture tests for KMS key lifecycle
.github/workflows/grc-gate.yml
oscal/         # catalog, profile, component
scripts/       # policy-gate.sh, verify-evidence.sh
WRITEUP.md
```

SSO profiles: `eval "$(aws configure export-credentials --profile default --format env)"` before hand-running Terraform. The Makefile already does that.