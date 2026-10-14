variable "region" {
  description = "Region hosting the Identity Center instance."
  type        = string
  default     = "us-west-2"
}

variable "enable_identity_center" {
  description = <<-EOT
    Create Identity Center groups, permission sets and assignments.

    Defaults to false because the Identity Center *instance* cannot be created
    by Terraform — there is no resource for it, only the
    `aws_ssoadmin_instances` data source. Enable the instance once in the
    console (IAM Identity Center > Enable), then flip this to true.

    With this false, the stack still builds the IAM permission boundary and
    the boundary-constrained developer role, which need no instance.
  EOT
  type        = bool
  default     = false
}

variable "assignment_target_account_ids" {
  description = <<-EOT
    Accounts that permission sets are assigned into. Defaults to the caller's
    own account so the stack is self-contained.
  EOT
  type        = list(string)
  default     = []
}

variable "allowed_regions" {
  description = "Regions the permission boundary allows. Must match the region-deny SCP in 10-org."
  type        = list(string)
  default     = ["us-west-2", "us-east-1"]
}

variable "session_duration" {
  description = "Permission set session duration, ISO-8601. Keep short for privileged sets."
  type        = string
  default     = "PT4H"
}

variable "breakglass_session_duration" {
  description = "Session duration for the break-glass admin set. Deliberately shorter."
  type        = string
  default     = "PT1H"
}

variable "tags" {
  description = "Tags applied to every resource in this stack."
  type        = map(string)
  default = {
    Project   = "aws-security-lab"
    ManagedBy = "terraform"
    Stack     = "20-identity"
  }
}
