# Let's get some controls in place, fam.
# title: GAP-01 — S3 uploads must use SSE-KMS with a customer CMK
# custom:
#   framework: hipaa
#   controls: ["164.312(a)(2)(iv)"]
#   secondary_controls: ["HITRUST 09.s"]
#   severity: high
package compliance.hipaa.gap01_s3_cmk
import rego.v1
__rego_metadata__ := {
	"id": "GAP-01",
	"title": "S3 uploads SSE-KMS customer CMK",
	"framework": "hipaa",
	"controls": ["164.312(a)(2)(iv)"],
	"secondary_controls": ["HITRUST 09.s"],
	"severity": "HIGH",
}
deny contains msg if {
	not uploads_has_cmk
	msg := "[HIPAA 164.312(a)(2)(iv)] aws_s3_bucket.uploads: missing SSE-KMS with a customer CMK. Remediation: add aws_s3_bucket_server_side_encryption_configuration with sse_algorithm=aws:kms and kms_master_key_id=aws_kms_key.data.arn."
}
uploads_has_cmk if {
	some r in input.configuration.root_module.resources
	r.type == "aws_s3_bucket_server_side_encryption_configuration"
	bucket_ref(r, "aws_s3_bucket.uploads")
	some rule in r.expressions.rule
	some sse in rule.apply_server_side_encryption_by_default
	sse.sse_algorithm.constant_value == "aws:kms"
	object.get(sse, "kms_master_key_id", null) != null
}
bucket_ref(r, addr) if {
	some ref in r.expressions.bucket.references
	ref == addr
}
bucket_ref(r, addr) if {
	some ref in r.expressions.bucket.references
	ref == sprintf("%s.id", [addr])
}
