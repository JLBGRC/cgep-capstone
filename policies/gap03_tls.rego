# METADATA
# title: GAP-03 — Uploads bucket must deny non-TLS
# custom:
#   framework: hipaa
#   controls: ["164.312(e)(1)"]
#   secondary_controls: ["HITRUST 09.s", "HITRUST 01.x"]
#   severity: high
package compliance.hipaa.gap03_tls

import rego.v1

__rego_metadata__ := {
	"id": "GAP-03",
	"title": "S3 Deny insecure transport",
	"framework": "hipaa",
	"controls": ["164.312(e)(1)"],
	"secondary_controls": ["HITRUST 09.s", "HITRUST 01.x"],
	"severity": "HIGH",
}

deny contains msg if {
	not uploads_denies_insecure
	msg := "HIPAA 164.312(e)(1), SecureTransport check - that uploads bucket had better deny non-TLS, buddy."
}

uploads_denies_insecure if {
	some r in input.planned_values.root_module.resources
	r.type == "aws_s3_bucket_policy"
	r.name == "uploads"
	contains(r.values.policy, "aws:SecureTransport")
	contains(r.values.policy, "false")
}

uploads_denies_insecure if {
	some r in input.configuration.root_module.resources
	r.type == "aws_iam_policy_document"
	r.name == "uploads"
	some stmt in r.expressions.statement
	some cond in stmt.condition
	cond.variable.constant_value == "aws:SecureTransport"
	some v in cond.values.constant_value
	v == "false"
}