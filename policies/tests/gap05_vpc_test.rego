package compliance.hipaa.gap05_vpc_test

import rego.v1
import data.compliance.hipaa.gap05_vpc as p

good := {"configuration": {"root_module": {"resources": [{
	"type": "aws_lambda_function",
	"name": "intake",
	"expressions": {"vpc_config": [{"subnet_ids": {"references": ["aws_subnet.private"]}}]},
}]}}}

fail := {"configuration": {"root_module": {"resources": [{
	"type": "aws_lambda_function",
	"name": "intake",
	"expressions": {},
}]}}}

test_compliant_passes if {
	count(p.deny) == 0 with input as good
}

test_noncompliant_fails if {
	some msg in p.deny with input as fail
	contains(msg, "164.312(e)(1)")
	contains(msg, "vpc_config")
}
