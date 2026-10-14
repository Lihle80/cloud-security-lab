#######################################################################
# 00-bootstrap — remote state backend
#
# Creates the S3 bucket that every other stack uses as its Terraform
# backend, encrypted with a dedicated customer-managed KMS key.
#
# State locking uses S3 conditional writes (`use_lockfile = true`),
# which replaced the DynamoDB lock table in Terraform 1.11. No table
# is needed.
#######################################################################

data "aws_caller_identity" "current" {}

locals {
  account_id = data.aws_caller_identity.current.account_id

  state_bucket_name = coalesce(
    var.state_bucket_name != "" ? var.state_bucket_name : null,
    "${var.project}-tfstate-${local.account_id}"
  )
}

#######################################################################
# KMS key encrypting state at rest
#######################################################################

resource "aws_kms_key" "state" {
  description             = "Encrypts Terraform state for ${var.project}"
  enable_key_rotation     = true
  deletion_window_in_days = 7
  policy                  = data.aws_iam_policy_document.state_key.json
}

resource "aws_kms_alias" "state" {
  name          = "alias/${var.project}-tfstate"
  target_key_id = aws_kms_key.state.key_id
}

data "aws_iam_policy_document" "state_key" {
  # Without this the key becomes unmanageable; IAM policy in this account
  # governs who may actually call the key.
  statement {
    sid       = "EnableIAMPolicies"
    effect    = "Allow"
    actions   = ["kms:*"]
    resources = ["*"]

    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::${local.account_id}:root"]
    }
  }

  statement {
    sid    = "AllowS3ServiceUse"
    effect = "Allow"
    actions = [
      "kms:Decrypt",
      "kms:GenerateDataKey",
    ]
    resources = ["*"]

    principals {
      type        = "Service"
      identifiers = ["s3.amazonaws.com"]
    }

    condition {
      test     = "StringEquals"
      variable = "kms:CallerAccount"
      values   = [local.account_id]
    }
  }
}

#######################################################################
# State bucket
#######################################################################

# Access logging declined: the state bucket is written by Terraform
# only, every call is already in CloudTrail with the calling principal,
# and a second bucket to log it would itself need a backend.
#tfsec:ignore:AVD-AWS-0089
resource "aws_s3_bucket" "state" {
  bucket = local.state_bucket_name

  # A lab is meant to be torn down. Flip to `true` if you want the state
  # bucket to survive `terraform destroy` on this stack.
  force_destroy = false

  lifecycle {
    prevent_destroy = false
  }
}

resource "aws_s3_bucket_versioning" "state" {
  bucket = aws_s3_bucket.state.id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "state" {
  bucket = aws_s3_bucket.state.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.state.arn
    }
    # Cuts KMS request cost by reusing a bucket-level data key.
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_public_access_block" "state" {
  bucket                  = aws_s3_bucket.state.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_ownership_controls" "state" {
  bucket = aws_s3_bucket.state.id

  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "state" {
  bucket = aws_s3_bucket.state.id

  rule {
    id     = "expire-noncurrent-state-versions"
    status = "Enabled"

    filter {}

    noncurrent_version_expiration {
      # Keep a month of history so a bad apply can be rolled back.
      noncurrent_days = 30
    }

    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
  }
}

resource "aws_s3_bucket_policy" "state" {
  bucket = aws_s3_bucket.state.id
  policy = data.aws_iam_policy_document.state_bucket.json

  depends_on = [aws_s3_bucket_public_access_block.state]
}

data "aws_iam_policy_document" "state_bucket" {
  statement {
    sid     = "DenyInsecureTransport"
    effect  = "Deny"
    actions = ["s3:*"]
    resources = [
      aws_s3_bucket.state.arn,
      "${aws_s3_bucket.state.arn}/*",
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

  # Denies an upload that ASKS for the wrong encryption, while still
  # allowing one that asks for nothing.
  #
  # The obvious version of this statement — StringNotEquals on
  # s3:x-amz-server-side-encryption with no Null guard — breaks the S3
  # backend outright:
  #
  #   Error acquiring the state lock ... AccessDenied: not authorized to
  #   perform s3:PutObject on ".../terraform.tfstate.tflock" with an
  #   explicit deny in a resource-based policy
  #
  # Terraform writes the lock file without an encryption header and
  # relies on the bucket's default encryption, which is SSE-KMS with the
  # CMK above. A bare StringNotEquals treats the absent header as "not
  # equal" and denies the request, so the backend can never take a lock.
  #
  # The Null condition fixes it: both conditions must hold, so the deny
  # only applies when a header IS present and names something other than
  # aws:kms. Requests with no header fall through to default encryption.
  statement {
    sid       = "DenyIncorrectEncryptionHeader"
    effect    = "Deny"
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.state.arn}/*"]

    principals {
      type        = "AWS"
      identifiers = ["*"]
    }

    condition {
      test     = "StringNotEquals"
      variable = "s3:x-amz-server-side-encryption"
      values   = ["aws:kms"]
    }

    # "false" means the key is NOT null, i.e. the header was supplied.
    condition {
      test     = "Null"
      variable = "s3:x-amz-server-side-encryption"
      values   = ["false"]
    }
  }
}
