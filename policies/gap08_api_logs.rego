# title: GAP-08 — API stage access logs and throttling
# custom:
#   framework: hipaa
#   controls: ["164.312(b)"]
#   secondary_controls: ["HITRUST 06.d"]
#   severity: high
package compliance.hipaa.gap08_api_logs

import rego.v1

__rego_metadata__ := {
	"id": "GAP-08",
	"title": "API Gateway access logs and throttle",
	"framework": "hipaa",
	"controls": ["164.312(b)"],
	"secondary_controls": ["HITRUST 06.d"],
	"severity": "HIGH",
}

deny contains msg if {
	some r in input.configuration.root_module.resources
	r.type == "aws_apigatewayv2_stage"
	r.name == "default"
	not has_access_logs(r)
	msg := "HIPAA 164.312(b), Have you checked access_log? Missing access_log_settings."
}

deny contains msg if {
	some r in input.configuration.root_module.resources
	r.type == "aws_apigatewayv2_stage"
	r.name == "default"
	not has_throttle(r)
	msg := "HIPAA 164.312(b), this ain't need for speed. throttl - gotta have throttling_burst_limit set."
}

has_access_logs(r) if object.get(r.expressions, "access_log_settings", null) != null

has_throttle(r) if {
	some drs in r.expressions.default_route_settings
	object.get(drs, "throttling_rate_limit", null) != null
	object.get(drs, "throttling_burst_limit", null) != null
}
