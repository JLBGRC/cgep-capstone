package compliance.hipaa.gap03_tls_test

import rego.v1
import data.compliance.hipaa.gap03_tls as p

good := {"planned_values": {"root_module": {"resources": [{
	"type": "aws_s3_bucket_policy",
	"name": "uploads",
	"values": {"policy": "{\"Statement\":[{\"Condition\":{\"Bool\":{\"aws:SecureTransport\":\"false\"}}}]} "},
}]}}}

fail := {"planned_values": {"root_module": {"resources": []}}}

test_compliant_passes if {
	count(p.deny) == 0 with input as good
}

test_noncompliant_fails if {
	some msg in p.deny with input as fail
	contains(msg, "164.312(e)(1)")
	contains(msg, "SecureTransport")
}
