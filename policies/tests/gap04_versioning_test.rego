package compliance.hipaa.gap04_versioning_test

import rego.v1
import data.compliance.hipaa.gap04_versioning as p

good := {"configuration": {"root_module": {"resources": [{
	"type": "aws_s3_bucket_versioning",
	"name": "uploads",
	"expressions": {
		"bucket": {"references": ["aws_s3_bucket.uploads.id"]},
		"versioning_configuration": [{"status": {"constant_value": "Enabled"}}],
	},
}]}}}

fail := {"configuration": {"root_module": {"resources": []}}}

test_compliant_passes if {
	count(p.deny) == 0 with input as good
}

test_noncompliant_fails if {
	some msg in p.deny with input as fail
	contains(msg, "164.308(a)(7)")
	contains(msg, "versioning")
}
