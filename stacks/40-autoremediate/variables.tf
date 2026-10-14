variable "region" {
  description = "Region for the Config recorder and remediation."
  type        = string
  default     = "us-west-2"
}

variable "project" {
  description = "Short project slug used to name resources."
  type        = string
  default     = "aws-security-lab"
}

variable "record_all_resource_types" {
  description = <<-EOT
    Record every supported resource type.

    Cost note: Config bills per configuration item recorded. Recording
    everything in a busy account gets expensive; in a small lab it is cents.
    Set false to narrow to `recorded_resource_types`.
  EOT
  type        = bool
  default     = true
}

variable "recorded_resource_types" {
  description = "Resource types to record when `record_all_resource_types` is false."
  type        = list(string)
  default = [
    "AWS::S3::Bucket",
    "AWS::EC2::SecurityGroup",
    "AWS::EC2::Instance",
    "AWS::IAM::Role",
    "AWS::IAM::Policy",
    "AWS::KMS::Key",
    "AWS::RDS::DBInstance",
  ]
}

variable "enable_automatic_remediation" {
  description = <<-EOT
    Let Config execute the remediation automatically on a NON_COMPLIANT result.

    This is the one genuinely mutating control in the lab: a bucket that goes
    public gets locked down without a human in the loop. Set false to create
    the remediation configuration but require manual invocation, which is the
    safer default outside a lab.
  EOT
  type        = bool
  default     = true
}

variable "remediation_retry_seconds" {
  description = "How long Config keeps retrying a failed remediation."
  type        = number
  default     = 600
}

variable "remediation_max_attempts" {
  description = "Maximum remediation attempts within the retry window."
  type        = number
  default     = 5
}

variable "config_retention_days" {
  description = "How long Config keeps configuration history. Minimum 30."
  type        = number
  default     = 90

  validation {
    condition     = var.config_retention_days >= 30 && var.config_retention_days <= 2557
    error_message = "config_retention_days must be between 30 and 2557."
  }
}

variable "create_demo_bucket" {
  description = <<-EOT
    Create a deliberately misconfigured bucket to prove the remediation fires.

    The bucket is created WITHOUT a public access block so that the Config
    rule flags it; the remediation then applies one. See
    docs/TESTING.md for how to watch the loop close.
  EOT
  type        = bool
  default     = false
}

variable "tags" {
  description = "Tags applied to every resource in this stack."
  type        = map(string)
  default = {
    Project   = "aws-security-lab"
    ManagedBy = "terraform"
    Stack     = "40-autoremediate"
  }
}
