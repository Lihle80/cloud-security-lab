#######################################################################
# AWS Backup with Vault Lock — lab item 6
#
# Vault Lock is what turns backups from "probably fine" into genuinely
# ransomware-resistant: once locked, a recovery point cannot be deleted
# before its retention expires, by anyone, including the account root
# and including AWS.
#
# ----------------------------------------------------------------------
# READ BEFORE SETTING vault_lock_mode = "compliance"
#
# Governance mode  removable by a principal with
#                  backup:DeleteBackupVaultLockConfiguration. Reversible.
#
# Compliance mode  after `changeable_for_days` elapses it is PERMANENT.
#                  Not removable by you, by the root user, or by AWS
#                  Support. The vault cannot be deleted while it holds
#                  recovery points, and those points cannot be deleted
#                  before `max_retention_days`. You pay for that storage
#                  for the full term.
#
#                  In a lab that means a resource you cannot clean up
#                  for up to a year. This stack defaults to governance
#                  for that reason.
# ----------------------------------------------------------------------
#######################################################################

resource "aws_backup_vault" "this" {
  count = var.enable_backup ? 1 : 0

  name        = "${var.project}-vault"
  kms_key_arn = aws_kms_key.backup[0].arn

  # Refuses to destroy a vault that still holds recovery points, rather
  # than failing partway through a destroy.
  force_destroy = false

  tags = { Name = "${var.project}-vault" }
}

resource "aws_backup_vault_lock_configuration" "this" {
  count = var.enable_backup && var.enable_vault_lock ? 1 : 0

  backup_vault_name = aws_backup_vault.this[0].name

  # Presence of this argument is what selects compliance mode. Null —
  # the governance case — omits it entirely.
  changeable_for_days = var.vault_lock_mode == "compliance" ? var.vault_lock_changeable_days : null

  min_retention_days = var.vault_lock_min_retention_days
  max_retention_days = var.vault_lock_max_retention_days
}

#######################################################################
# Role AWS Backup assumes
#######################################################################

data "aws_iam_policy_document" "backup_assume" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["backup.amazonaws.com"]
    }

    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [local.account_id]
    }
  }
}

resource "aws_iam_role" "backup" {
  count = var.enable_backup ? 1 : 0

  name               = "${var.project}-backup"
  description        = "Role AWS Backup assumes to take and restore backups"
  assume_role_policy = data.aws_iam_policy_document.backup_assume.json
}

resource "aws_iam_role_policy_attachment" "backup" {
  count = var.enable_backup ? 1 : 0

  role       = aws_iam_role.backup[0].name
  policy_arn = "arn:${local.partition}:iam::aws:policy/service-role/AWSBackupServiceRolePolicyForBackup"
}

# Restore permissions are separate from backup permissions. Attached here
# because a backup you cannot restore is not a backup.
resource "aws_iam_role_policy_attachment" "restore" {
  count = var.enable_backup ? 1 : 0

  role       = aws_iam_role.backup[0].name
  policy_arn = "arn:${local.partition}:iam::aws:policy/service-role/AWSBackupServiceRolePolicyForRestores"
}

#######################################################################
# Plan
#######################################################################

resource "aws_backup_plan" "this" {
  count = var.enable_backup ? 1 : 0

  name = "${var.project}-plan"

  rule {
    rule_name         = "daily"
    target_vault_name = aws_backup_vault.this[0].name

    # 05:00 UTC — outside business hours for US regions.
    schedule = "cron(0 5 * * ? *)"

    # Window for the job to start, and how long it may run.
    start_window      = 60
    completion_window = 300

    lifecycle {
      delete_after = var.backup_retention_days
    }

    recovery_point_tags = merge(var.tags, {
      BackupPlan = "${var.project}-plan"
    })
  }

  # Continuous backup enables point-in-time restore for supported
  # services, so recovery is not limited to the last daily snapshot.
  rule {
    rule_name         = "continuous-pitr"
    target_vault_name = aws_backup_vault.this[0].name
    schedule          = "cron(0 6 * * ? *)"

    enable_continuous_backup = true

    lifecycle {
      # PITR retention is capped at 35 days by AWS, regardless of what
      # the daily rule retains.
      delete_after = min(var.backup_retention_days, 35)
    }
  }

  tags = { Name = "${var.project}-plan" }
}

#######################################################################
# Selection
#
# Tag-driven rather than listing ARNs: anything tagged
# `Backup = "true"` is picked up automatically, including resources
# created after this stack was applied.
#
# With nothing tagged, the plan runs, finds no resources and costs
# nothing — which is the expected state in a fresh lab.
#######################################################################

resource "aws_backup_selection" "tagged" {
  count = var.enable_backup ? 1 : 0

  name         = "${var.project}-tagged-resources"
  iam_role_arn = aws_iam_role.backup[0].arn
  plan_id      = aws_backup_plan.this[0].id

  selection_tag {
    type  = "STRINGEQUALS"
    key   = "Backup"
    value = "true"
  }
}

#######################################################################
# Backup failure alarms
#
# A silently failing backup job is worse than no backup, because you
# believe you are covered. This surfaces failures as EventBridge events.
#######################################################################

resource "aws_backup_vault_notifications" "this" {
  count = var.enable_backup ? 1 : 0

  backup_vault_name = aws_backup_vault.this[0].name
  sns_topic_arn     = aws_sns_topic.backup_alerts[0].arn

  backup_vault_events = [
    "BACKUP_JOB_FAILED",
    "BACKUP_JOB_EXPIRED",
    "RESTORE_JOB_FAILED",
    "COPY_JOB_FAILED",
  ]
}

# The AWS-managed SNS key is adequate here and a CMK is not: AWS Backup
# publishes through its own service principal, which alias/aws/sns
# already trusts. Contrast with the EventBridge topic in 30-detection,
# where a CMK is mandatory because the managed key's policy cannot be
# edited to trust events.amazonaws.com.
#tfsec:ignore:AVD-AWS-0136
resource "aws_sns_topic" "backup_alerts" {
  count = var.enable_backup ? 1 : 0

  name = "${var.project}-backup-alerts"

  # The AWS-managed SNS key is sufficient here: AWS Backup publishes via
  # its own service principal, which the managed key already trusts.
  kms_master_key_id = "alias/aws/sns"
}

data "aws_iam_policy_document" "backup_alerts" {
  count = var.enable_backup ? 1 : 0

  statement {
    sid       = "AllowBackupPublish"
    effect    = "Allow"
    actions   = ["sns:Publish"]
    resources = [aws_sns_topic.backup_alerts[0].arn]

    principals {
      type        = "Service"
      identifiers = ["backup.amazonaws.com"]
    }
  }

  statement {
    sid       = "DenyInsecureTransport"
    effect    = "Deny"
    actions   = ["sns:Publish"]
    resources = [aws_sns_topic.backup_alerts[0].arn]

    principals {
      type        = "AWS"
      identifiers = ["*"]
    }

    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }
}

resource "aws_sns_topic_policy" "backup_alerts" {
  count = var.enable_backup ? 1 : 0

  arn    = aws_sns_topic.backup_alerts[0].arn
  policy = data.aws_iam_policy_document.backup_alerts[0].json
}
