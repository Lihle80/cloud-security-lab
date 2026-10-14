variable "region" {
  description = "Region for the provider. Organizations itself is global."
  type        = string
  default     = "us-west-2"
}

variable "allowed_regions" {
  description = <<-EOT
    Regions workloads may use. The region-deny SCP blocks everything else,
    with a carve-out for global services that are only reachable via us-east-1.
  EOT
  type        = list(string)
  default     = ["us-west-2", "us-east-1"]
}

variable "attach_scps_to_root" {
  description = <<-EOT
    Attach the guardrail SCPs to the organization root as well as the OUs.

    Left at false deliberately. SCPs never apply to the management account, so
    attaching at root cannot lock you out of it, but it does apply immediately
    to every existing member account, including ones this lab did not create.
    Turn it on once you have read the policies and accept that blast radius.
  EOT
  type        = bool
  default     = false
}

variable "enable_unused_access_analyzer" {
  description = <<-EOT
    Create an org-wide IAM Access Analyzer for unused access. Charged per IAM
    role or user analyzed per month, so it is a toggle rather than a default.
  EOT
  type        = bool
  default     = false
}

variable "unused_access_age_days" {
  description = "Days of inactivity before Access Analyzer reports a role or key as unused."
  type        = number
  default     = 60

  validation {
    condition     = var.unused_access_age_days >= 1 && var.unused_access_age_days <= 365
    error_message = "unused_access_age_days must be between 1 and 365."
  }
}

variable "tags" {
  description = "Tags applied to every resource in this stack."
  type        = map(string)
  default = {
    Project   = "aws-security-lab"
    ManagedBy = "terraform"
    Stack     = "10-org"
  }
}
