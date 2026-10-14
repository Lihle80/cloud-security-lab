#######################################################################
# AWS Config — lab item 4
#
# Recorder, delivery channel and the rules that drive remediation.
#
# Also the substrate Security Hub needs: most FSBP and CIS controls are
# implemented as Config rules, so stack 30-detection reports "No data"
# for much of its coverage until this recorder is running.
#######################################################################

data "aws_caller_identity" "current" {}
data "aws_partition" "current" {}

locals {
  account_id = data.aws_caller_identity.current.account_id
  partition  = data.aws_partition.current.partition

  config_bucket_name = "${var.project}-config-${local.account_id}"
}

#######################################################################
# Delivery bucket
#######################################################################

# SSE-S3 rather than a CMK, and no access logging: AWS Config delivers
# a very large number of small objects, so per-object KMS calls would
# cost more than the storage they protect, and access-logging a log
# bucket recurses. Rationale repeated at the encryption block below.
#tfsec:ignore:AVD-AWS-0089
#tfsec:ignore:AVD-AWS-0132
resource "aws_s3_bucket" "config" {
  bucket        = local.config_bucket_name
  force_destroy = false
}

resource "aws_s3_bucket_versioning" "config" {
  bucket = aws_s3_bucket.config.id

  versioning_configuration {
    status = "Enabled"
  }
}

#tfsec:ignore:AVD-AWS-0132
resource "aws_s3_bucket_server_side_encryption_configuration" "config" {
  bucket = aws_s3_bucket.config.id

  rule {
    apply_server_side_encryption_by_default {
      # SSE-S3 rather than SSE-KMS: Config delivers very many small
      # objects and per-object KMS calls would dominate the cost of this
      # stack for no real gain on non-sensitive config snapshots.
      sse_algorithm = "AES256"
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_public_access_block" "config" {
  bucket                  = aws_s3_bucket.config.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_ownership_controls" "config" {
  bucket = aws_s3_bucket.config.id

  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "config" {
  bucket = aws_s3_bucket.config.id

  rule {
    id     = "expire-config-history"
    status = "Enabled"

    filter {}

    expiration {
      days = var.config_retention_days
    }

    noncurrent_version_expiration {
      noncurrent_days = 30
    }

    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
  }
}

data "aws_iam_policy_document" "config_bucket" {
  statement {
    sid       = "AWSConfigBucketPermissionsCheck"
    effect    = "Allow"
    actions   = ["s3:GetBucketAcl", "s3:ListBucket"]
    resources = [aws_s3_bucket.config.arn]

    principals {
      type        = "Service"
      identifiers = ["config.amazonaws.com"]
    }

    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [local.account_id]
    }
  }

  statement {
    sid       = "AWSConfigBucketDelivery"
    effect    = "Allow"
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.config.arn}/AWSLogs/${local.account_id}/Config/*"]

    principals {
      type        = "Service"
      identifiers = ["config.amazonaws.com"]
    }

    condition {
      test     = "StringEquals"
      variable = "s3:x-amz-acl"
      values   = ["bucket-owner-full-control"]
    }

    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [local.account_id]
    }
  }

  statement {
    sid     = "DenyInsecureTransport"
    effect  = "Deny"
    actions = ["s3:*"]

    resources = [
      aws_s3_bucket.config.arn,
      "${aws_s3_bucket.config.arn}/*",
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

resource "aws_s3_bucket_policy" "config" {
  bucket = aws_s3_bucket.config.id
  policy = data.aws_iam_policy_document.config_bucket.json

  depends_on = [aws_s3_bucket_public_access_block.config]
}

#######################################################################
# Recorder role
#######################################################################

data "aws_iam_policy_document" "config_assume" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["config.amazonaws.com"]
    }

    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [local.account_id]
    }
  }
}

resource "aws_iam_role" "config" {
  name               = "${var.project}-config-recorder"
  description        = "Role AWS Config assumes to record and deliver configuration items"
  assume_role_policy = data.aws_iam_policy_document.config_assume.json
}

resource "aws_iam_role_policy_attachment" "config_managed" {
  role       = aws_iam_role.config.name
  policy_arn = "arn:${local.partition}:iam::aws:policy/service-role/AWS_ConfigRole"
}

# AWS_ConfigRole covers the describe/read side but not delivery to this
# specific bucket.
data "aws_iam_policy_document" "config_delivery" {
  statement {
    sid       = "DeliverConfigSnapshots"
    effect    = "Allow"
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.config.arn}/AWSLogs/${local.account_id}/Config/*"]

    condition {
      test     = "StringEquals"
      variable = "s3:x-amz-acl"
      values   = ["bucket-owner-full-control"]
    }
  }

  statement {
    sid       = "CheckBucket"
    effect    = "Allow"
    actions   = ["s3:GetBucketAcl"]
    resources = [aws_s3_bucket.config.arn]
  }
}

resource "aws_iam_role_policy" "config_delivery" {
  name   = "deliver-to-config-bucket"
  role   = aws_iam_role.config.id
  policy = data.aws_iam_policy_document.config_delivery.json
}

#######################################################################
# Recorder and delivery channel
#######################################################################

resource "aws_config_configuration_recorder" "this" {
  name     = "${var.project}-recorder"
  role_arn = aws_iam_role.config.arn

  recording_group {
    all_supported                 = var.record_all_resource_types
    include_global_resource_types = var.record_all_resource_types

    # Only honoured when all_supported is false.
    resource_types = var.record_all_resource_types ? null : var.recorded_resource_types
  }
}

resource "aws_config_delivery_channel" "this" {
  name           = "${var.project}-delivery"
  s3_bucket_name = aws_s3_bucket.config.id
  s3_key_prefix  = "AWSLogs/${local.account_id}/Config"

  snapshot_delivery_properties {
    delivery_frequency = "TwentyFour_Hours"
  }

  depends_on = [
    aws_config_configuration_recorder.this,
    aws_s3_bucket_policy.config,
  ]
}

resource "aws_config_configuration_recorder_status" "this" {
  name       = aws_config_configuration_recorder.this.name
  is_enabled = true

  depends_on = [aws_config_delivery_channel.this]
}

#######################################################################
# Rules
#
# Managed rules, evaluated by AWS rather than by Lambda functions you
# have to maintain. The public-read rule is the one wired to automatic
# remediation below.
#######################################################################

resource "aws_config_config_rule" "s3_public_read_prohibited" {
  name        = "s3-bucket-public-read-prohibited"
  description = "Flags buckets readable by the public. Wired to automatic remediation."

  source {
    owner             = "AWS"
    source_identifier = "S3_BUCKET_PUBLIC_READ_PROHIBITED"
  }

  depends_on = [aws_config_configuration_recorder_status.this]
}

resource "aws_config_config_rule" "s3_public_write_prohibited" {
  name        = "s3-bucket-public-write-prohibited"
  description = "Flags buckets writable by the public."

  source {
    owner             = "AWS"
    source_identifier = "S3_BUCKET_PUBLIC_WRITE_PROHIBITED"
  }

  depends_on = [aws_config_configuration_recorder_status.this]
}

resource "aws_config_config_rule" "s3_ssl_requests_only" {
  name        = "s3-bucket-ssl-requests-only"
  description = "Flags buckets whose policy does not deny non-TLS requests."

  source {
    owner             = "AWS"
    source_identifier = "S3_BUCKET_SSL_REQUESTS_ONLY"
  }

  depends_on = [aws_config_configuration_recorder_status.this]
}

resource "aws_config_config_rule" "encrypted_volumes" {
  name        = "encrypted-volumes"
  description = "Flags unencrypted EBS volumes."

  source {
    owner             = "AWS"
    source_identifier = "ENCRYPTED_VOLUMES"
  }

  depends_on = [aws_config_configuration_recorder_status.this]
}

resource "aws_config_config_rule" "imdsv2_required" {
  name        = "ec2-imdsv2-check"
  description = "Flags instances still permitting IMDSv1, the SSRF credential-theft path."

  source {
    owner             = "AWS"
    source_identifier = "EC2_IMDSV2_CHECK"
  }

  depends_on = [aws_config_configuration_recorder_status.this]
}
