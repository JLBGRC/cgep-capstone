# METADATA
# title: GAP-04 — Uploads bucket versioning Enabled
# custom:
#   framework: hipaa
#   controls: ["164.308(a)(7)"]
#   secondary_controls: ["HITRUST 09.g"]
#   severity: high
package compliance.hipaa.gap04_versioning

import rego.v1

__rego_metadata__ := {
	"id": "GAP-04",
	"title": "S3 versioning for PHI recovery",
	"framework": "hipaa",
	"controls": ["164.308(a)(7)"],
	"secondary_controls": ["HITRUST 09.g"],
	"severity": "HIGH",
}

deny contains msg if {
	not uploads_versioning_enabled
	msg := "HIPAA 164.308(a)(7), upload bucket needs that sweet, sweet versioning, fella."
}

uploads_versioning_enabled if {
	some r in input.configuration.root_module.resources
	r.type == "aws_s3_bucket_versioning"
	bucket_ref(r, "aws_s3_bucket.uploads")
	some vc in r.expressions.versioning_configuration
	vc.status.constant_value == "Enabled"
}

bucket_ref(r, addr) if {
	some ref in r.expressions.bucket.references
	ref == addr
}

bucket_ref(r, addr) if {
	some ref in r.expressions.bucket.references
	ref == sprintf("%s.id", [addr])
}
