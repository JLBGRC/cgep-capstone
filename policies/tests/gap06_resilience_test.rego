package compliance.hipaa.gap06_resilience_test

import rego.v1
import data.compliance.hipaa.gap06_resilience as p

good := {"configuration": {"root_module": {"resources": [{
	"type": "aws_lambda_function",
	"name": "intake",
	"expressions": {
		"dead_letter_config": [{"target_arn": {"references": ["aws_sqs_queue.lambda_dlq.arn"]}}],
		"tracing_config": [{"mode": {"constant_value": "Active"}}],
	},
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
	count(p.deny) == 2 with input as fail
}
