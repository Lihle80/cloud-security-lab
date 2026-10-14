#######################################################################
# S3 bucket enforcing TLS and SSE-KMS — lab item 6
#
# Four denies, each closing a gap the previous one leaves open:
#
#   1. DenyInsecureTransport       no plaintext HTTP at all
#   2. DenyOutdatedTLS             TLS 1.0/1.1 rejected even over HTTPS
#   3. DenyUnencryptedUploads      SSE-KMS required, not merely default
#   4. DenyWrongKmsKey             and specifically THIS key
#
# Default bucket encryption alone is not enough. It fills in a missing
# encryption header, but a caller who explicitly asks for AES256 still
# gets AES256. Deny 3 and 4 close that: the request itself must name
# SSE-KMS and the right key, or it fails.
#######################################################################

# Access logging declined for the lab only. This is the one bucket where
# it would genuinely add value in production — it holds the data the
# whole stack exists to protect — so it is called out in
# docs/RUNBOOK.md rather than silently skipped.
#tfsec:ignore:AVD-AWS-0089
resource "aws_s3_bucket" "protected" {
  bucket        = "${var.project}-protected-${local.account_id}"
  force_destroy = false

  tags = { Name = "${var.project}-protected" }
}

resource "aws_s3_bucket_versioning" "protected" {
  bucket = aws_s3_bucket.protected.id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "protected" {
  bucket = aws_s3_bucket.protected.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.data.arn
    }

    # One data key per bucket instead of one per object. Cuts KMS API
    # calls, and therefore cost, by orders of magnitude on write-heavy
    # buckets.
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_public_access_block" "protected" {
  bucket                  = aws_s3_bucket.protected.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_ownership_controls" "protected" {
  bucket = aws_s3_bucket.protected.id

  rule {
    # Disables ACLs entirely. Bucket policy becomes the single place
    # access is decided, which removes a whole category of confusion.
    object_ownership = "BucketOwnerEnforced"
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "protected" {
  bucket = aws_s3_bucket.protected.id

  rule {
    id     = "tier-and-clean"
    status = "Enabled"

    filter {}

    transition {
      days          = 30
      storage_class = "INTELLIGENT_TIERING"
    }

    noncurrent_version_expiration {
      noncurrent_days = 90
    }

    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
  }
}

data "aws_iam_policy_document" "protected" {
  # 1. No plaintext transport.
  statement {
    sid     = "DenyInsecureTransport"
    effect  = "Deny"
    actions = ["s3:*"]

    resources = [
      aws_s3_bucket.protected.arn,
      "${aws_s3_bucket.protected.arn}/*",
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

  # 2. HTTPS is not sufficient on its own — TLS 1.0 and 1.1 are HTTPS too.
  statement {
    sid     = "DenyOutdatedTLS"
    effect  = "Deny"
    actions = ["s3:*"]

    resources = [
      aws_s3_bucket.protected.arn,
      "${aws_s3_bucket.protected.arn}/*",
    ]

    principals {
      type        = "AWS"
      identifiers = ["*"]
    }

    condition {
      test     = "NumericLessThan"
      variable = "s3:TlsVersion"
      values   = ["1.2"]
    }
  }

  # 3. The upload must ask for SSE-KMS.
  statement {
    sid       = "DenyUnencryptedUploads"
    effect    = "Deny"
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.protected.arn}/*"]

    principals {
      type        = "AWS"
      identifiers = ["*"]
    }

    condition {
      test     = "StringNotEquals"
      variable = "s3:x-amz-server-side-encryption"
      values   = ["aws:kms"]
    }
  }

  # 4. And name this key specifically, not just any KMS key. Without
  #    this, a caller could encrypt with a key in their own account that
  #    you cannot read — a denial-of-service on your own data.
  statement {
    sid       = "DenyWrongKmsKey"
    effect    = "Deny"
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.protected.arn}/*"]

    principals {
      type        = "AWS"
      identifiers = ["*"]
    }

    condition {
      test     = "StringNotEquals"
      variable = "s3:x-amz-server-side-encryption-aws-kms-key-id"
      values   = [aws_kms_key.data.arn]
    }
  }

  # Cross-account read, when configured. Paired with the key policy's
  # CrossAccountDecrypt statement — the object grant and the key grant
  # are both required, and granting only one is the usual mistake.
  dynamic "statement" {
    for_each = local.has_cross_account ? [1] : []

    content {
      sid    = "CrossAccountRead"
      effect = "Allow"

      actions = [
        "s3:GetObject",
        "s3:ListBucket",
      ]

      resources = [
        aws_s3_bucket.protected.arn,
        "${aws_s3_bucket.protected.arn}/*",
      ]

      principals {
        type        = "AWS"
        identifiers = var.cross_account_principal_arns
      }
    }
  }
}

resource "aws_s3_bucket_policy" "protected" {
  bucket = aws_s3_bucket.protected.id
  policy = data.aws_iam_policy_document.protected.json

  depends_on = [aws_s3_bucket_public_access_block.protected]
}
