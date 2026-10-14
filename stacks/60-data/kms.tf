#######################################################################
# Customer-managed KMS key — lab item 6
#
# Why a CMK rather than the AWS-managed aws/s3 key:
#   - you control the key policy, so you can deny or grant across accounts
#   - you can rotate, disable or schedule deletion on your own terms
#   - CloudTrail shows every Decrypt call with the calling principal
#   - the AWS-managed key's policy cannot be edited at all, which is why
#     an SNS topic encrypted with it cannot be published to by EventBridge
#
# The policy below separates three roles deliberately:
#   administrators  may manage the key, may NOT use it
#   users           may use the key, may NOT manage it
#   cross-account   may decrypt only, and only via specific services
#######################################################################

data "aws_caller_identity" "current" {}
data "aws_partition" "current" {}

locals {
  account_id = data.aws_caller_identity.current.account_id
  partition  = data.aws_partition.current.partition

  has_key_admins    = length(var.key_administrator_arns) > 0
  has_key_users     = length(var.key_user_arns) > 0
  has_cross_account = length(var.cross_account_principal_arns) > 0
}

data "aws_iam_policy_document" "data_key" {
  # Required. Omitting this makes the key permanently unmanageable: there
  # is no break-glass path, and AWS support cannot recover it.
  statement {
    sid       = "EnableIAMPolicies"
    effect    = "Allow"
    actions   = ["kms:*"]
    resources = ["*"]

    principals {
      type        = "AWS"
      identifiers = ["arn:${local.partition}:iam::${local.account_id}:root"]
    }
  }

  # --- Administration without use ------------------------------------
  dynamic "statement" {
    for_each = local.has_key_admins ? [1] : []

    content {
      sid       = "KeyAdministration"
      effect    = "Allow"
      resources = ["*"]

      actions = [
        "kms:Create*",
        "kms:Describe*",
        "kms:Enable*",
        "kms:List*",
        "kms:Put*",
        "kms:Update*",
        "kms:Revoke*",
        "kms:Disable*",
        "kms:Get*",
        "kms:Delete*",
        "kms:TagResource",
        "kms:UntagResource",
        "kms:ScheduleKeyDeletion",
        "kms:CancelKeyDeletion",
      ]

      principals {
        type        = "AWS"
        identifiers = var.key_administrator_arns
      }
    }
  }

  # --- Use without administration ------------------------------------
  dynamic "statement" {
    for_each = local.has_key_users ? [1] : []

    content {
      sid       = "KeyUsage"
      effect    = "Allow"
      resources = ["*"]

      actions = [
        "kms:Encrypt",
        "kms:Decrypt",
        "kms:ReEncrypt*",
        "kms:GenerateDataKey*",
        "kms:DescribeKey",
      ]

      principals {
        type        = "AWS"
        identifiers = var.key_user_arns
      }
    }
  }

  # Grants are how services like AWS Backup and EBS get temporary use of
  # the key on a principal's behalf. The ViaService condition means this
  # cannot be used to hand the key to an arbitrary caller.
  dynamic "statement" {
    for_each = local.has_key_users ? [1] : []

    content {
      sid       = "AllowServiceGrants"
      effect    = "Allow"
      resources = ["*"]

      actions = [
        "kms:CreateGrant",
        "kms:ListGrants",
        "kms:RevokeGrant",
      ]

      principals {
        type        = "AWS"
        identifiers = var.key_user_arns
      }

      condition {
        test     = "Bool"
        variable = "kms:GrantIsForAWSResource"
        values   = ["true"]
      }
    }
  }

  # --- Cross-account decrypt -----------------------------------------
  #
  # Half of the story. The named principal's own account must ALSO grant
  # it kms:Decrypt on this key ARN via an IAM policy. AWS evaluates both
  # independently and requires both to allow.
  dynamic "statement" {
    for_each = local.has_cross_account ? [1] : []

    content {
      sid       = "CrossAccountDecrypt"
      effect    = "Allow"
      resources = ["*"]

      actions = [
        "kms:Decrypt",
        "kms:DescribeKey",
      ]

      principals {
        type        = "AWS"
        identifiers = var.cross_account_principal_arns
      }

      # Restricts the grant to data arriving through S3, so the remote
      # account cannot use the key as a general-purpose decryption oracle.
      condition {
        test     = "StringEquals"
        variable = "kms:ViaService"
        values   = ["s3.${var.region}.amazonaws.com"]
      }
    }
  }

  # Belt and braces: deny the dangerous operations outright to anyone who
  # is not an administrator, regardless of what IAM grants them.
  dynamic "statement" {
    for_each = local.has_key_admins ? [1] : []

    content {
      sid    = "DenyDeletionExceptByAdministrators"
      effect = "Deny"

      actions = [
        "kms:ScheduleKeyDeletion",
        "kms:DisableKey",
      ]

      resources = ["*"]

      principals {
        type        = "AWS"
        identifiers = ["*"]
      }

      condition {
        test     = "ArnNotEquals"
        variable = "aws:PrincipalArn"
        values   = var.key_administrator_arns
      }
    }
  }
}

resource "aws_kms_key" "data" {
  description = "Customer-managed key protecting lab data at rest"

  # Annual automatic rotation. The key ID stays stable, so nothing that
  # references it needs to change; KMS keeps old key material to decrypt
  # data encrypted before each rotation.
  enable_key_rotation = true

  # Shortest AWS permits. A longer window is safer in production, where
  # an accidental deletion needs time to be noticed.
  deletion_window_in_days = 7

  policy = data.aws_iam_policy_document.data_key.json

  tags = { Name = "${var.project}-data" }
}

resource "aws_kms_alias" "data" {
  name          = "alias/${var.project}-data"
  target_key_id = aws_kms_key.data.key_id
}

#######################################################################
# Separate key for backups
#
# Blast-radius separation: if the data key is compromised or destroyed,
# the backups protecting against exactly that event must not share its
# fate.
#######################################################################

data "aws_iam_policy_document" "backup_key" {
  statement {
    sid       = "EnableIAMPolicies"
    effect    = "Allow"
    actions   = ["kms:*"]
    resources = ["*"]

    principals {
      type        = "AWS"
      identifiers = ["arn:${local.partition}:iam::${local.account_id}:root"]
    }
  }

  statement {
    sid       = "AllowBackupService"
    effect    = "Allow"
    resources = ["*"]

    actions = [
      "kms:Decrypt",
      "kms:DescribeKey",
      "kms:Encrypt",
      "kms:GenerateDataKey*",
      "kms:ReEncrypt*",
      "kms:CreateGrant",
    ]

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

resource "aws_kms_key" "backup" {
  count = var.enable_backup ? 1 : 0

  description             = "Customer-managed key protecting lab backups"
  enable_key_rotation     = true
  deletion_window_in_days = 7
  policy                  = data.aws_iam_policy_document.backup_key.json

  tags = { Name = "${var.project}-backup" }
}

resource "aws_kms_alias" "backup" {
  count = var.enable_backup ? 1 : 0

  name          = "alias/${var.project}-backup"
  target_key_id = aws_kms_key.backup[0].key_id
}
