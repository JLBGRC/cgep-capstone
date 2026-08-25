package compliance.hipaa.gap07_least_privilege_test

import rego.v1
import data.compliance.hipaa.gap07_least_privilege as p

good := {"planned_values": {"root_module": {"resources": [{
	"type": "aws_iam_role_policy",
	"name": "lambda_inline",
	"values": {"policy": "{\"Statement\":[{\"Action\":[\"dynamodb:PutItem\"],\"Effect\":\"Allow\"},{\"Action\":[\"s3:PutObject\"],\"Effect\":\"Allow\"}]}"},
}]}}}

fail := {"planned_values": {"root_module": {"resources": [{
	"type": "aws_iam_role_policy",
	"name": "lambda_inline",
	"values": {"policy": "{\"Statement\":[{\"Action\":\"dynamodb:*\",\"Effect\":\"Allow\"},{\"Action\":\"s3:*\",\"Effect\":\"Allow\"}]}"},
}]}}}

test_compliant_passes if {
	count(p.deny) == 0 with input as good
}

test_noncompliant_fails if {
	some msg in p.deny with input as fail
	contains(msg, "164.312(a)(1)")
}
