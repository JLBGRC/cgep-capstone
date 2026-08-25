package compliance.hipaa.gap08_api_logs_test

import rego.v1
import data.compliance.hipaa.gap08_api_logs as p

good := {"configuration": {"root_module": {"resources": [{
	"type": "aws_apigatewayv2_stage",
	"name": "default",
	"expressions": {
		"access_log_settings": [{"destination_arn": {"references": ["aws_cloudwatch_log_group.api.arn"]}}],
		"default_route_settings": [{
			"throttling_burst_limit": {"constant_value": 50},
			"throttling_rate_limit": {"constant_value": 25},
		}],
	},
}]}}}

fail := {"configuration": {"root_module": {"resources": [{
	"type": "aws_apigatewayv2_stage",
	"name": "default",
	"expressions": {},
}]}}}

test_compliant_passes if {
	count(p.deny) == 0 with input as good
}

test_noncompliant_fails if {
	count(p.deny) == 2 with input as fail
}
