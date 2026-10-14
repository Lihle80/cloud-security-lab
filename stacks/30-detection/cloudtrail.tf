#######################################################################
# Organization CloudTrail — lab item 3
#
# One multi-region organization trail. Every account in the org writes
# into a single bucket in this account, encrypted with a customer-managed
# KMS key, with log file validation on so tampering is detectable.
#
# This stack never touches a pre-existing trail. In an Isengard account
# `IsengardTrail-DO-NOT-DELETE` keeps running untouched alongside it.
#
# PREREQUISITE: trusted access for cloudtrail.amazonaws.com must be
# enabled on the organization. See scripts/enable-org-service-access.sh.
#######################################################################

data "aws_caller_identity" "current" {}
data "aws_partition" "current" {}
data "aws_region" "current" {}
data "aws_organizations_organization" "current" {}

locals {
  account_id = data.aws_caller_identity.current.account_id
  partition  = data.aws_partition.current.partition
  org_id     = data.aws_organizations_organization.current.id

  trail_bucket_name = "${var.project}-cloudtrail-${local.account_id}"

  # Computed rather than referenced, to break the cycle between the trail
  # (needs the bucket) and the bucket policy (conditions on the trail ARN).
  trail_arn = "arn:${local.partition}:cloudtrail:${var.region}:${local.account_id}:trail/${var.trail_name}"
}

#######################################################################
# KMS key for trail encryption
#######################################################################

resource "aws_kms_key" "trail" {
  count = var.create_organization_trail ? 1 : 0

  description             = "Encrypts CloudTrail logs for ${var.project}"
  enable_key_rotation     = true
  deletion_window_in_days = 7
  policy                  = data.aws_iam_policy_document.trail_key.json
}

resource "aws_kms_alias" "trail" {
  count = var.create_organization_trail ? 1 : 0

  name          = "alias/${var.project}-cloudtrail"
  target_key_id = aws_kms_key.trail[0].key_id
}

data "aws_iam_policy_document" "trail_key" {
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

  # CloudTrail encrypts each log file with a data key from this CMK. The
  # EncryptionContext condition is what stops another account's trail
  # from using this key.
  statement {
    sid       = "AllowCloudTrailEncrypt"
    effect    = "Allow"
    actions   = ["kms:GenerateDataKey*"]
    resources = ["*"]

    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }

    condition {
      test     = "StringLike"
      variable = "kms:EncryptionContext:aws:cloudtrail:arn"
      values   = ["arn:${local.partition}:cloudtrail:*:${local.account_id}:trail/*"]
    }
  }

  statement {
    sid       = "AllowCloudTrailDescribeKey"
    effect    = "Allow"
    actions   = ["kms:DescribeKey"]
    resources = ["*"]

    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }
  }

  # Members of the org must be able to decrypt their own log files.
  statement {
    sid       = "AllowOrgDecrypt"
    effect    = "Allow"
    actions   = ["kms:Decrypt", "kms:ReEncryptFrom"]
    resources = ["*"]

    principals {
      type        = "AWS"
      identifiers = ["*"]
    }

    condition {
      test     = "StringEquals"
      variable = "aws:PrincipalOrgID"
      values   = [local.org_id]
    }

    condition {
      test     = "StringLike"
      variable = "kms:EncryptionContext:aws:cloudtrail:arn"
      values   = ["arn:${local.partition}:cloudtrail:*:${local.account_id}:trail/*"]
    }
  }

  statement {
    sid       = "AllowCloudWatchLogs"
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
      type        = "Service"
      identifiers = ["logs.${var.region}.amazonaws.com"]
    }

    condition {
      test     = "ArnLike"
      variable = "kms:EncryptionContext:aws:logs:arn"
      values   = ["arn:${local.partition}:logs:${var.region}:${local.account_id}:log-group:*"]
    }
  }
}

#######################################################################
# Log bucket
#######################################################################

# S3 access logging on the trail bucket is declined: CloudTrail already
# records every API call against it, including the ones that read the
# logs, so a separate access log adds a second copy of the same
# information. Object-lock is the control that would matter here and is
# noted in docs/RUNBOOK.md as the production hardening step.
#tfsec:ignore:AVD-AWS-0089
#tfsec:ignore:AVD-AWS-0163
resource "aws_s3_bucket" "trail" {
  count = var.create_organization_trail ? 1 : 0

  bucket        = local.trail_bucket_name
  force_destroy = false
}

resource "aws_s3_bucket_versioning" "trail" {
  count = var.create_organization_trail ? 1 : 0

  bucket = aws_s3_bucket.trail[0].id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "trail" {
  count = var.create_organization_trail ? 1 : 0

  bucket = aws_s3_bucket.trail[0].id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.trail[0].arn
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_public_access_block" "trail" {
  count = var.create_organization_trail ? 1 : 0

  bucket                  = aws_s3_bucket.trail[0].id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_ownership_controls" "trail" {
  count = var.create_organization_trail ? 1 : 0

  bucket = aws_s3_bucket.trail[0].id

  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "trail" {
  count = var.create_organization_trail ? 1 : 0

  bucket = aws_s3_bucket.trail[0].id

  rule {
    id     = "tier-and-expire"
    status = "Enabled"

    filter {}

    transition {
      days          = 90
      storage_class = "GLACIER_IR"
    }

    expiration {
      days = 400
    }

    noncurrent_version_expiration {
      noncurrent_days = 30
    }

    # Abandoned multipart uploads are invisible in the console and billed
    # indefinitely until explicitly cleaned up.
    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
  }
}

data "aws_iam_policy_document" "trail_bucket" {
  count = var.create_organization_trail ? 1 : 0

  statement {
    sid       = "AWSCloudTrailAclCheck"
    effect    = "Allow"
    actions   = ["s3:GetBucketAcl"]
    resources = [aws_s3_bucket.trail[0].arn]

    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }

    condition {
      test     = "StringEquals"
      variable = "aws:SourceArn"
      values   = [local.trail_arn]
    }
  }

  # Two prefixes: the org-wide path used by an organization trail, and the
  # single-account path CloudTrail still writes for the owning account.
  statement {
    sid     = "AWSCloudTrailWrite"
    effect  = "Allow"
    actions = ["s3:PutObject"]

    resources = [
      "${aws_s3_bucket.trail[0].arn}/AWSLogs/${local.account_id}/*",
      "${aws_s3_bucket.trail[0].arn}/AWSLogs/${local.org_id}/*",
    ]

    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }

    condition {
      test     = "StringEquals"
      variable = "s3:x-amz-acl"
      values   = ["bucket-owner-full-control"]
    }

    condition {
      test     = "StringEquals"
      variable = "aws:SourceArn"
      values   = [local.trail_arn]
    }
  }

  statement {
    sid     = "DenyInsecureTransport"
    effect  = "Deny"
    actions = ["s3:*"]

    resources = [
      aws_s3_bucket.trail[0].arn,
      "${aws_s3_bucket.trail[0].arn}/*",
    ]

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

resource "aws_s3_bucket_policy" "trail" {
  count = var.create_organization_trail ? 1 : 0

  bucket = aws_s3_bucket.trail[0].id
  policy = data.aws_iam_policy_document.trail_bucket[0].json

  depends_on = [aws_s3_bucket_public_access_block.trail]
}

#######################################################################
# CloudWatch Logs delivery
#
# Gives you metric filters and alarms on trail events, which the S3 copy
# alone cannot provide.
#######################################################################

resource "aws_cloudwatch_log_group" "trail" {
  count = var.create_organization_trail ? 1 : 0

  name              = "/aws/cloudtrail/${var.trail_name}"
  retention_in_days = var.log_retention_days
  kms_key_id        = aws_kms_key.trail[0].arn
}

data "aws_iam_policy_document" "trail_logs_assume" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }

    condition {
      test     = "StringEquals"
      variable = "aws:SourceArn"
      values   = [local.trail_arn]
    }
  }
}

resource "aws_iam_role" "trail_logs" {
  count = var.create_organization_trail ? 1 : 0

  name               = "${var.project}-cloudtrail-to-logs"
  description        = "Lets CloudTrail write the org trail into CloudWatch Logs"
  assume_role_policy = data.aws_iam_policy_document.trail_logs_assume.json
}

data "aws_iam_policy_document" "trail_logs" {
  count = var.create_organization_trail ? 1 : 0

  statement {
    effect = "Allow"

    actions = [
      "logs:CreateLogStream",
      "logs:PutLogEvents",
    ]

    # Org trails write one stream per member account, so the wildcard
    # below is the narrowest form that actually works.
    resources = ["${aws_cloudwatch_log_group.trail[0].arn}:log-stream:*"]
  }
}

resource "aws_iam_role_policy" "trail_logs" {
  count = var.create_organization_trail ? 1 : 0

  name   = "write-trail-logs"
  role   = aws_iam_role.trail_logs[0].id
  policy = data.aws_iam_policy_document.trail_logs[0].json
}

#######################################################################
# The trail
#######################################################################

resource "aws_cloudtrail" "org" {
  count = var.create_organization_trail ? 1 : 0

  name           = var.trail_name
  s3_bucket_name = aws_s3_bucket.trail[0].id

  is_organization_trail         = true
  is_multi_region_trail         = true
  include_global_service_events = true

  # Detects after-the-fact modification of delivered log files.
  enable_log_file_validation = true
  kms_key_id                 = aws_kms_key.trail[0].arn

  cloud_watch_logs_group_arn = "${aws_cloudwatch_log_group.trail[0].arn}:*"
  cloud_watch_logs_role_arn  = aws_iam_role.trail_logs[0].arn

  # Management events only. S3 and Lambda data events are high volume and
  # billed per event — enable deliberately, not by default.
  event_selector {
    read_write_type           = "All"
    include_management_events = true
  }

  depends_on = [
    aws_s3_bucket_policy.trail,
    aws_iam_role_policy.trail_logs,
  ]
}
