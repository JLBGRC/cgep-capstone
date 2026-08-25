# METADATA
# title: GAP-05 — Lambda must run in private VPC subnets
# custom:
#   framework: hipaa
#   controls: ["164.312(e)(1)"]
#   secondary_controls: ["HITRUST 01.t"]
#   severity: high
package compliance.hipaa.gap05_vpc

import rego.v1

__rego_metadata__ := {
	"id": "GAP-05",
	"title": "Lambda in VPC private subnets",
	"framework": "hipaa",
	"controls": ["164.312(e)(1)"],
	"secondary_controls": ["HITRUST 01.t"],
	"severity": "HIGH",
}

deny contains msg if {
	some r in input.configuration.root_module.resources
	r.type == "aws_lambda_function"
	r.name == "intake"
	not has_vpc_config(r)
	msg := "HIPAA 164.312(e)(1), best check that vpc_config - Lambda needs to run in private VPC subnets!"
}

has_vpc_config(r) if object.get(r.expressions, "vpc_config", null) != null
