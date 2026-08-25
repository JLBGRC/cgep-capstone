variable "aws_region" {
  type        = string
  description = "AWS region for the starter."
  default     = "us-east-1"
}

variable "github_org" {
  type        = string
  description = "GitHub organization or account that owns the capstone repository."
  default     = "JLBGRC"
}
variable "github_repo" {
  type        = string
  description = "GitHub repository authorized to assume the CI OIDC role."
  default     = "cgep-capstone"
}

variable "github_owner_id" {
  type        = string
  description = "Numeric GitHub owner id for immutable OIDC sub."
  default     = "308450453"
}

variable "github_repo_id" {
  type        = string
  description = "Numeric GitHub repo id for immutable OIDC sub."
  default     = "1345432830"
}
