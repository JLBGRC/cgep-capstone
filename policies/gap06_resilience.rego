# METADATA
# title: GAP-06 — Lambda DLQ and X-Ray
# custom:
#   framework: hipaa
#   controls: ["164.308(a)(1)"]
#   secondary_controls: ["HITRUST 09.j", "HITRUST 10.m"]
#   severity: medium
package compliance.hipaa.gap06_resilience

import rego.v1

__rego_metadata__ := {
	"id": "GAP-06",
	"title": "Lambda DLQ and tracing",
	"framework": "hipaa",
	"controls": ["164.308(a)(1)"],
	"secondary_controls": ["HITRUST 09.j", "HITRUST 10.m"],
	"severity": "MEDIUM",
}

deny contains msg if {
	some r in input.configuration.root_module.resources
	r.type == "aws_lambda_function"
	r.name == "intake"
	not has_dlq(r)
	msg := "HIPAA 164.308(a)(1), DLQ (dead_letter) coinfig on the Lambda ain't right."
}

deny contains msg if {
	some r in input.configuration.root_module.resources
	r.type == "aws_lambda_function"
	r.name == "intake"
	not has_xray(r)
	msg := "HIPAA 164.308(a)(1), gotta get tracing_config.mode active, my friend."
}

has_dlq(r) if object.get(r.expressions, "dead_letter_config", null) != null

has_xray(r) if {
	some t in r.expressions.tracing_config
	t.mode.constant_value == "Active"
}
