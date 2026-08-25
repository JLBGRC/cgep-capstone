#Test that stuff...
package compliance.hipaa.gap01_s3_cmk_test

import rego.v1
import data.compliance.hipaa.gap01_s3_cmk as p

good := {"configuration": {"root_module": {"resources": [{
	"type": "aws_s3_bucket_server_side_encryption_configuration",
	"name": "uploads",
	"expressions": {
		"bucket": {"references": ["aws_s3_bucket.uploads.id"]},
		"rule": [{
			"apply_server_side_encryption_by_default": [{
				"sse_algorithm": {"constant_value": "aws:kms"},
				"kms_master_key_id": {"references": ["aws_kms_key.data.arn"]},
			}],
			"bucket_key_enabled": {"constant_value": true},
		}],
	},
}]}}}

fail := {"configuration": {"root_module": {"resources": []}}}

test_compliant_passes if {
	count(p.deny) == 0 with input as good
}

test_noncompliant_fails if {
	some msg in p.deny with input as fail
	contains(msg, "164.312(a)(2)(iv)")
	contains(msg, "aws_s3_bucket.uploads")
}
