# title: GAP-02 — DynamoDB intake table must use a customer CMK
# custom:
#   framework: hipaa
#   controls: ["164.312(a)(2)(iv)"]
#   secondary_controls: ["HITRUST 09.s"]
#   severity: high
package compliance.hipaa.gap02_ddb_cmk

import rego.v1

__rego_metadata__ := {
	"id": "GAP-02",
	"title": "DynamoDB CMK encryption",
	"framework": "hipaa",
	"controls": ["164.312(a)(2)(iv)"],
	"secondary_controls": ["HITRUST 09.s"],
	"severity": "HIGH",
}

deny contains msg if {
	some r in input.configuration.root_module.resources
	r.type == "aws_dynamodb_table"
	r.name == "intake"
	not table_has_cmk(r)
	msg := "HIPAA 164.312(a)(2)(iv), aws_dynamodb_table.intake, DynamoDB intake table needs to use a customer CMK"
}

table_has_cmk(r) if {
	some sse in r.expressions.server_side_encryption
	sse.enabled.constant_value == true
	object.get(sse, "kms_key_arn", null) != null
}
