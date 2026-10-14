variable "region" {
  description = "Region hosting the Terraform state bucket."
  type        = string
  default     = "us-west-2"
}

variable "project" {
  description = "Short project slug used to name resources."
  type        = string
  default     = "aws-security-lab"
}

variable "state_bucket_name" {
  description = <<-EOT
    Globally unique name for the Terraform state bucket. Leave empty to derive
    one from the project slug and account ID.
  EOT
  type        = string
  default     = ""
}

variable "github_repo" {
  description = <<-EOT
    GitHub repository allowed to assume the CI roles, as "owner/repo".
    Leave empty to skip creating the OIDC provider and roles entirely.
  EOT
  type        = string
  default     = ""

  validation {
    condition     = var.github_repo == "" || can(regex("^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$", var.github_repo))
    error_message = "github_repo must be empty or of the form \"owner/repo\"."
  }
}

variable "github_apply_ref" {
  description = "Git ref allowed to assume the apply role. Plan is allowed from any ref or PR."
  type        = string
  default     = "refs/heads/main"
}

variable "tags" {
  description = "Tags applied to every resource in this stack."
  type        = map(string)
  default = {
    Project   = "aws-security-lab"
    ManagedBy = "terraform"
    Stack     = "00-bootstrap"
  }
}
