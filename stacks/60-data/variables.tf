variable "region" {
  description = "Region for keys, buckets and the backup vault."
  type        = string
  default     = "us-west-2"
}

variable "project" {
  description = "Short project slug used to name resources."
  type        = string
  default     = "aws-security-lab"
}

variable "key_administrator_arns" {
  description = <<-EOT
    Principals allowed to administer the data key — schedule deletion, edit the
    policy — but NOT to use it for encrypt or decrypt.

    Separating administration from use is the point. An admin who cannot
    decrypt cannot read the data; a user who cannot administer cannot delete
    the key. Empty means only the account root, via IAM.
  EOT
  type        = list(string)
  default     = []
}

variable "key_user_arns" {
  description = "Principals allowed to encrypt and decrypt with the data key, but not administer it."
  type        = list(string)
  default     = []
}

variable "cross_account_principal_arns" {
  description = <<-EOT
    Principals in OTHER accounts granted decrypt access to the data key.

    Cross-account KMS needs grants on BOTH sides: this key policy, and an IAM
    policy in the remote account. Listing an ARN here is necessary but not
    sufficient — see docs/CROSS-ACCOUNT-KMS.md.

    In the lab org, the second account is 256716302976.
  EOT
  type        = list(string)
  default     = []

  validation {
    condition = alltrue([
      for arn in var.cross_account_principal_arns : can(regex("^arn:aws[a-z-]*:iam::[0-9]{12}:", arn))
    ])
    error_message = "Each entry must be an IAM ARN, e.g. arn:aws:iam::123456789012:root."
  }
}

variable "enable_backup" {
  description = <<-EOT
    Create the AWS Backup vault, plan and selection.

    Cost note: backup storage is billed per GB-month. With nothing tagged for
    backup the plan runs and finds no resources, which costs nothing.
  EOT
  type        = bool
  default     = true
}

variable "enable_vault_lock" {
  description = <<-EOT
    Apply AWS Backup Vault Lock.

    Read `vault_lock_mode` before enabling. Vault Lock is the control that
    makes backups genuinely ransomware-resistant, and also the one that can
    leave you with undeletable resources.
  EOT
  type        = bool
  default     = false
}

variable "vault_lock_mode" {
  description = <<-EOT
    "governance" or "compliance".

    governance  Lock can be removed by a principal holding
                backup:DeleteBackupVaultLockConfiguration. Correct for a lab
                and for most production use.

    compliance  IRREVERSIBLE once `changeable_for_days` elapses. AWS support
                cannot remove it. The vault and every recovery point in it
                cannot be deleted until its retention expires, and you keep
                paying for that storage the entire time.

    This lab defaults to governance deliberately. Only choose compliance if a
    regulator requires WORM backups and you accept the cost commitment.
  EOT
  type        = string
  default     = "governance"

  validation {
    condition     = contains(["governance", "compliance"], var.vault_lock_mode)
    error_message = "vault_lock_mode must be \"governance\" or \"compliance\"."
  }
}

variable "vault_lock_changeable_days" {
  description = <<-EOT
    Grace period before a compliance-mode lock becomes permanent. AWS requires
    at least 3 days. Ignored in governance mode.

    Treat this as your only window to undo a mistake.
  EOT
  type        = number
  default     = 3

  validation {
    condition     = var.vault_lock_changeable_days >= 3
    error_message = "AWS requires at least 3 days before a compliance lock becomes immutable."
  }
}

variable "backup_retention_days" {
  description = "Retention for daily recovery points."
  type        = number
  default     = 35
}

variable "vault_lock_min_retention_days" {
  description = "Minimum retention the vault will accept. Must be <= backup_retention_days."
  type        = number
  default     = 7
}

variable "vault_lock_max_retention_days" {
  description = "Maximum retention the vault will accept. Must be >= backup_retention_days."
  type        = number
  default     = 365
}

variable "tags" {
  description = "Tags applied to every resource in this stack."
  type        = map(string)
  default = {
    Project   = "aws-security-lab"
    ManagedBy = "terraform"
    Stack     = "60-data"
  }
}
