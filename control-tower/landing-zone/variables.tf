variable "region" {
  description = "Control Tower home region. Cannot be changed after setup without rebuilding."
  type        = string
  default     = "us-west-2"
}

variable "create_landing_zone" {
  description = <<-EOT
    Master switch, default FALSE.

    Setting this true creates a Control Tower landing zone, which enrolls
    accounts, deploys StackSets across the organization and takes 60-90
    minutes. Decommissioning is slow and frequently leaves StackSet instances
    behind. Read ../README.md first.
  EOT
  type        = bool
  default     = false
}

variable "log_archive_account_id" {
  description = <<-EOT
    Account ID of a PRE-EXISTING Log Archive account.

    Control Tower does not create this account. Create it first with
    `aws organizations create-account` and put the resulting ID here.
  EOT
  type        = string
  default     = ""

  validation {
    condition     = var.log_archive_account_id == "" || can(regex("^[0-9]{12}$", var.log_archive_account_id))
    error_message = "Must be empty or a 12-digit account ID."
  }
}

variable "audit_account_id" {
  description = "Account ID of a PRE-EXISTING Audit account. Also not created by Control Tower."
  type        = string
  default     = ""

  validation {
    condition     = var.audit_account_id == "" || can(regex("^[0-9]{12}$", var.audit_account_id))
    error_message = "Must be empty or a 12-digit account ID."
  }
}

variable "governed_regions" {
  description = <<-EOT
    Regions Control Tower governs. Every governed region gets a Config
    recorder and CloudTrail coverage, and is billed accordingly — so this
    list is a cost decision as much as a security one.
  EOT
  type        = list(string)
  default     = ["us-west-2"]
}

variable "landing_zone_version" {
  description = <<-EOT
    Landing zone version. Must match a version Control Tower currently
    offers; check the console or `aws controltower list-landing-zones` on an
    existing deployment. Upgrading is a separate, deliberate operation.
  EOT
  type        = string
  default     = "3.3"
}

variable "security_ou_name" {
  description = "Name for the Security OU holding the Log Archive and Audit accounts."
  type        = string
  default     = "Security"
}

variable "sandbox_ou_name" {
  description = "Name for the Sandbox OU."
  type        = string
  default     = "Sandbox"
}

variable "log_retention_days" {
  description = "Retention for the centralized logging bucket."
  type        = number
  default     = 365
}

variable "access_log_retention_days" {
  description = "Retention for the access logging bucket."
  type        = number
  default     = 3650
}

variable "logging_kms_key_arn" {
  description = <<-EOT
    CMK encrypting the centralized log archive. Leave empty for SSE-S3.

    The key must live in the management account and its policy must trust
    Control Tower's service principals before the landing zone is created,
    or setup fails partway through.
  EOT
  type        = string
  default     = ""
}

variable "control_tower_manages_access" {
  description = <<-EOT
    Let Control Tower create and manage Identity Center permission sets.

    False keeps stacks/20-identity as the single owner of Identity Center,
    which avoids two systems reconciling the same permission sets against
    each other.
  EOT
  type        = bool
  default     = false
}

variable "target_ou_arn" {
  description = "ARN of the OU the controls below are applied to."
  type        = string
  default     = ""
}

variable "enabled_controls" {
  description = <<-EOT
    Control Tower control identifiers to enable on `target_ou_arn`.

    These are all preventive (SCP-backed) or detective (Config-backed), so
    they apply to Terraform-provisioned resources. Proactive controls are
    omitted on purpose: they are CloudFormation Hooks and never evaluate a
    Terraform apply.
  EOT
  type        = list(string)
  default = [
    "AWS-GR_RESTRICT_ROOT_USER",
    "AWS-GR_RESTRICT_ROOT_USER_ACCESS_KEYS",
    "AWS-GR_ENCRYPTED_VOLUMES",
    "AWS-GR_RDS_STORAGE_ENCRYPTED",
    "AWS-GR_RESTRICTED_SSH",
    "AWS-GR_DISALLOW_VPC_INTERNET_ACCESS_VIA_IGW",
    "AWS-GR_S3_BUCKET_PUBLIC_READ_PROHIBITED",
    "AWS-GR_S3_BUCKET_PUBLIC_WRITE_PROHIBITED",
  ]
}

variable "tags" {
  description = "Tags applied to every resource in this stack."
  type        = map(string)
  default = {
    Project   = "aws-security-lab"
    ManagedBy = "terraform"
    Stack     = "control-tower-landing-zone"
  }
}
