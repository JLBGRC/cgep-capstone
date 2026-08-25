#!/usr/bin/env bash
set -euo pipefail

POLICY_DIR="policies"
WORKSPACE=""
EVIDENCE_DIR="evidence"

NAMESPACES=(
  compliance.hipaa.gap01_s3_cmk
  compliance.hipaa.gap02_ddb_cmk
  compliance.hipaa.gap03_tls
  compliance.hipaa.gap04_versioning
  compliance.hipaa.gap05_vpc
  compliance.hipaa.gap06_resilience
  compliance.hipaa.gap07_least_privilege
  compliance.hipaa.gap08_api_logs
)

while [[ $# -gt 0 ]]; do
  case "$1" in
    --workspace) WORKSPACE="$2"; shift 2 ;;
    --policy)    POLICY_DIR="$2"; shift 2 ;;
    --evidence)  EVIDENCE_DIR="$2"; shift 2 ;;
    *) echo "Unknown arg: $1" >&2; exit 2 ;;
  esac
done

[[ -z "$WORKSPACE" ]] && { echo "Usage: $0 --workspace <terraform-dir>" >&2; exit 2; }
mkdir -p "$EVIDENCE_DIR"

( cd "$WORKSPACE" && terraform show -json tfplan > plan.json )

EXIT=0
{
  echo "["
  FIRST=1
  for ns in "${NAMESPACES[@]}"; do
    [[ $FIRST -eq 1 ]] && FIRST=0 || printf ","
    OUT=$(conftest test --policy "$POLICY_DIR" --namespace "$ns" --output=json "$WORKSPACE/plan.json" || true)
    if echo "$OUT" | python3 -c 'import sys,json; d=json.load(sys.stdin); sys.exit(0 if all(len(r.get("failures") or [])==0 for r in d) else 1)'; then : ; else EXIT=1 ; fi
    echo "$OUT"
  done
  echo "]"
} > "$EVIDENCE_DIR/conftest-results.json"

if [[ $EXIT -eq 0 ]]; then echo "policy-gate: PASS"
else echo "policy-gate: FAIL"; echo "See $EVIDENCE_DIR/conftest-results.json"
fi
exit $EXIT
