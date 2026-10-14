variable "region" {
  description = "Home region for the trail, Security Hub and GuardDuty."
  type        = string
  default     = "us-west-2"
}

variable "project" {
  description = "Short project slug used to name resources."
  type        = string
  default     = "aws-security-lab"
}

variable "trail_name" {
  description = <<-EOT
    Name of the organization trail this stack creates.

    Must not collide with a pre-existing trail. In an Isengard-managed account
    there is already an `IsengardTrail-DO-NOT-DELETE`; this stack creates a
    separate org trail alongside it and never modifies that one.
  EOT
  type        = string
  default     = "aws-security-lab-org-trail"
}

variable "create_organization_trail" {
  description = <<-EOT
    Create a multi-region organization trail. Requires trusted access for
    cloudtrail.amazonaws.com on the organization — see
    scripts/enable-org-service-access.sh.

    Cost note: the first copy of management events is free per trail, but an
    org trail in an account that already has a trail means you are paying for
    a second copy of data events if you enable them.
  EOT
  type        = bool
  default     = true
}

variable "create_guardduty_detector" {
  description = <<-EOT
    Create the GuardDuty detector. Defaults to false because GuardDuty is
    already enabled in many sandbox accounts and a second detector per region
    is not permitted — the stack reads the existing one instead.
  EOT
  type        = bool
  default     = false
}

variable "guardduty_finding_publishing_frequency" {
  description = "How often GuardDuty exports findings to EventBridge for existing findings."
  type        = string
  default     = "FIFTEEN_MINUTES"

  validation {
    condition = contains(
      ["FIFTEEN_MINUTES", "ONE_HOUR", "SIX_HOURS"],
      var.guardduty_finding_publishing_frequency
    )
    error_message = "Must be FIFTEEN_MINUTES, ONE_HOUR or SIX_HOURS."
  }
}

variable "delegated_admin_account_id" {
  description = <<-EOT
    Member account to designate as delegated administrator for GuardDuty and
    Security Hub. Leave empty to run both services from this (management)
    account.

    Production guidance is a dedicated Security account in the Security OU;
    the management account is used here only because this lab has no such
    account to vend into.
  EOT
  type        = string
  default     = ""

  validation {
    condition     = var.delegated_admin_account_id == "" || can(regex("^[0-9]{12}$", var.delegated_admin_account_id))
    error_message = "delegated_admin_account_id must be empty or a 12-digit account ID."
  }
}

variable "enable_security_hub" {
  description = <<-EOT
    Enable Security Hub with the FSBP and CIS standards.

    Cost note: Security Hub charges per security check per region per month.
    Enabling two standards roughly doubles the check count. Expect single-digit
    dollars per month in a small lab account.
  EOT
  type        = bool
  default     = true
}

variable "enable_cis_standard" {
  description = "Subscribe to the CIS AWS Foundations Benchmark in addition to FSBP."
  type        = bool
  default     = true
}

variable "alert_email" {
  description = <<-EOT
    Email subscribed to the findings SNS topic. Leave empty to create the topic
    without a subscription.

    AWS sends a confirmation email that must be clicked; Terraform will show
    the subscription as `pending confirmation` until then, which is expected
    and not an error.
  EOT
  type        = string
  default     = ""
}

variable "minimum_alert_severity" {
  description = <<-EOT
    Lowest GuardDuty numeric severity that raises an alert.
    1.0-3.9 Low, 4.0-6.9 Medium, 7.0-8.9 High, 9.0+ Critical.
    Set to 4 so Low-severity noise does not page anyone.
  EOT
  type        = number
  default     = 4

  validation {
    condition     = var.minimum_alert_severity >= 1 && var.minimum_alert_severity <= 10
    error_message = "minimum_alert_severity must be between 1 and 10."
  }
}

variable "log_retention_days" {
  description = "Retention for the CloudTrail CloudWatch Logs group."
  type        = number
  default     = 90
}

variable "tags" {
  description = "Tags applied to every resource in this stack."
  type        = map(string)
  default = {
    Project   = "aws-security-lab"
    ManagedBy = "terraform"
    Stack     = "30-detection"
  }
}
