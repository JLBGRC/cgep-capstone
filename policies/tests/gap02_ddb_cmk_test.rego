package compliance.hipaa.gap02_ddb_cmk_test

import rego.v1
import data.compliance.hipaa.gap02_ddb_cmk as p

good := {"configuration": {"root_module": {"resources": [{
	"type": "aws_dynamodb_table",
	"name": "intake",
	"expressions": {"server_side_encryption": [{
		"enabled": {"constant_value": true},
		"kms_key_arn": {"references": ["aws_kms_key.data.arn"]},
	}]},
}]}}}

fail := {"configuration": {"root_module": {"resources": [{
	"type": "aws_dynamodb_table",
	"name": "intake",
	"expressions": {},
}]}}}

test_compliant_passes if {
	count(p.deny) == 0 with input as good
}

test_noncompliant_fails if {
	some msg in p.deny with input as fail
	contains(msg, "164.312(a)(2)(iv)")
	contains(msg, "aws_dynamodb_table.intake")
}
