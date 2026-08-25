# METADATA
# title: GAP-07 — No wildcard DynamoDB/S3 actions on the handler role
# custom:
#   framework: hipaa
#   controls: ["164.312(a)(1)"]
#   secondary_controls: ["HITRUST 01.b"]
#   severity: high
package compliance.hipaa.gap07_least_privilege

import rego.v1

__rego_metadata__ := {
	"id": "GAP-07",
	"title": "Lambda IAM least privilege",
	"framework": "hipaa",
	"controls": ["164.312(a)(1)"],
	"secondary_controls": ["HITRUST 01.b"],
	"severity": "HIGH",
}

deny contains msg if {
	some r in input.planned_values.root_module.resources
	r.type == "aws_iam_role_policy"
	r.name == "lambda_inline"
	some action in policy_actions(r.values.policy)
	is_store_wildcard(action)
	msg := sprintf("HIPAA 164.312(a)(1) least privilege on the handler role issue!: %q", [action])
}

policy_actions(policy) := actions if {
	is_string(policy)
	doc := json.unmarshal(policy)
	actions := {a |
		some s in as_array(doc.Statement)
		some a in as_array(s.Action)
	}
}

as_array(x) := x if is_array(x)
as_array(x) := [x] if is_string(x)

is_store_wildcard(action) if action == "dynamo:*"
is_store_wildcard(action) if action == "s3:*"
is_store_wildcard(action) if action == "*"
