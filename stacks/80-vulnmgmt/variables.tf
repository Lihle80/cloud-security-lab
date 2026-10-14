variable "region" {
  description = "Region for Inspector and Patch Manager."
  type        = string
  default     = "us-west-2"
}

variable "project" {
  description = "Short project slug used to name resources."
  type        = string
  default     = "aws-security-lab"
}

variable "enable_inspector" {
  description = <<-EOT
    Enable Amazon Inspector.

    Cost note: billed per scanned resource — per EC2 instance-month, per
    container image pushed, per Lambda function-month. With no workloads
    running it costs nothing, which is the usual state of this lab.
  EOT
  type        = bool
  default     = true
}

variable "inspector_resource_types" {
  description = <<-EOT
    What Inspector scans.

    EC2          OS and application packages on instances, via SSM
    ECR          container images on push and on a rescan schedule
    LAMBDA       Lambda runtime dependencies
    LAMBDA_CODE  static analysis of the function code itself
  EOT
  type        = list(string)
  default     = ["EC2", "ECR", "LAMBDA", "LAMBDA_CODE"]

  validation {
    condition = alltrue([
      for t in var.inspector_resource_types :
      contains(["EC2", "ECR", "LAMBDA", "LAMBDA_CODE"], t)
    ])
    error_message = "Valid types are EC2, ECR, LAMBDA and LAMBDA_CODE."
  }
}

variable "inspector_delegated_admin_account_id" {
  description = <<-EOT
    Account to designate as Inspector delegated administrator. Leave empty to
    administer Inspector from this account.
  EOT
  type        = string
  default     = ""

  validation {
    condition     = var.inspector_delegated_admin_account_id == "" || can(regex("^[0-9]{12}$", var.inspector_delegated_admin_account_id))
    error_message = "Must be empty or a 12-digit account ID."
  }
}

variable "enable_patch_manager" {
  description = "Create the patch baseline, patch group and maintenance windows."
  type        = bool
  default     = true
}

variable "patch_group_tag_value" {
  description = <<-EOT
    Value of the `Patch Group` tag that binds instances to this baseline.

    Note the space in the tag key: SSM requires exactly `Patch Group`, and an
    instance tagged `PatchGroup` will silently never be patched.
  EOT
  type        = string
  default     = "aws-security-lab-linux"
}

variable "patch_approval_delay_days" {
  description = <<-EOT
    Days a patch must have been available before it is auto-approved.

    Seven is a deliberate compromise: long enough that a bad vendor patch is
    usually withdrawn first, short enough that exploitation windows stay
    narrow. Critical security patches below are approved with zero delay.
  EOT
  type        = number
  default     = 7
}

variable "patch_window_schedule" {
  description = "Cron for the patching maintenance window, in UTC."
  type        = string
  default     = "cron(0 3 ? * SUN *)"
}

variable "scan_window_schedule" {
  description = "Cron for the compliance scan window. Runs more often than patching."
  type        = string
  default     = "cron(0 2 ? * * *)"
}

variable "tags" {
  description = "Tags applied to every resource in this stack."
  type        = map(string)
  default = {
    Project   = "aws-security-lab"
    ManagedBy = "terraform"
    Stack     = "80-vulnmgmt"
  }
}
