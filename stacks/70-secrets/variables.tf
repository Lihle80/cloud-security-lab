variable "region" {
  description = "Region for the secret, parameter and database."
  type        = string
  default     = "us-west-2"
}

variable "project" {
  description = "Short project slug used to name resources."
  type        = string
  default     = "aws-security-lab"
}

variable "enable_rds" {
  description = <<-EOT
    Create the RDS instance whose master password Secrets Manager rotates.

    Off by default because this is the most expensive resource in the lab:
    roughly $12-15/month for db.t4g.micro plus storage, and it keeps billing
    until destroyed. Everything else in this stack works without it.

    Requires stack 50-network to have been applied — the database is placed in
    the isolated subnets it creates, discovered by tag.
  EOT
  type        = bool
  default     = false
}

variable "db_instance_class" {
  description = "Instance class. db.t4g.micro is the cheapest Graviton option."
  type        = string
  default     = "db.t4g.micro"
}

variable "db_engine_version" {
  description = <<-EOT
    PostgreSQL major version. Left as a major-only string so AWS selects the
    current minor, which is what you want for patching.
  EOT
  type        = string
  default     = "16"
}

variable "db_allocated_storage" {
  description = "Storage in GB. 20 is the minimum for gp3."
  type        = number
  default     = 20
}

variable "rotation_days" {
  description = <<-EOT
    Days between automatic rotations of the database master password.

    Seven is the AWS default for managed rotation. Shorter windows mean a
    leaked credential is valid for less time, at the cost of more rotation
    events for applications to pick up.
  EOT
  type        = number
  default     = 7

  validation {
    condition     = var.rotation_days >= 1 && var.rotation_days <= 365
    error_message = "rotation_days must be between 1 and 365."
  }
}

variable "vpc_name_tag" {
  description = "Name tag of the VPC created by stack 50-network, used for discovery."
  type        = string
  default     = "aws-security-lab-vpc"
}

variable "tags" {
  description = "Tags applied to every resource in this stack."
  type        = map(string)
  default = {
    Project   = "aws-security-lab"
    ManagedBy = "terraform"
    Stack     = "70-secrets"
  }
}
