#######################################################################
# SSM Automation remediation — lab item 4
#
# The closed loop:
#
#   bucket becomes public
#     -> Config rule s3-bucket-public-read-prohibited -> NON_COMPLIANT
#     -> Config remediation invokes the SSM Automation document
#     -> document applies a full Public Access Block and asserts it
#     -> next evaluation returns COMPLIANT
#######################################################################

resource "aws_ssm_document" "block_s3_public_access" {
  name            = "${var.project}-PutS3PublicAccessBlock"
  document_type   = "Automation"
  document_format = "YAML"

  content = file("${path.module}/documents/put-s3-public-access-block.yaml")

  tags = var.tags
}

#######################################################################
# Role the automation runs as
#
# Scoped to exactly the two S3 calls the document makes. Not a wildcard,
# because a remediation role is a standing grant that fires unattended.
#######################################################################

data "aws_iam_policy_document" "remediation_assume" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["ssm.amazonaws.com"]
    }

    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [local.account_id]
    }
  }
}

resource "aws_iam_role" "remediation" {
  name               = "${var.project}-s3-remediation"
  description        = "Role SSM Automation assumes to apply an S3 public access block"
  assume_role_policy = data.aws_iam_policy_document.remediation_assume.json
}

data "aws_iam_policy_document" "remediation" {
  statement {
    sid    = "ManagePublicAccessBlock"
    effect = "Allow"

    actions = [
      "s3:PutBucketPublicAccessBlock",
      "s3:GetBucketPublicAccessBlock",
    ]

    # Any bucket in this account: Config decides which bucket is
    # non-compliant, and the set is not knowable in advance.
    resources = ["arn:${local.partition}:s3:::*"]
  }
}

resource "aws_iam_role_policy" "remediation" {
  name   = "s3-public-access-block"
  role   = aws_iam_role.remediation.id
  policy = data.aws_iam_policy_document.remediation.json
}

#######################################################################
# Wire the rule to the document
#######################################################################

resource "aws_config_remediation_configuration" "s3_public_read" {
  config_rule_name = aws_config_config_rule.s3_public_read_prohibited.name

  target_type    = "SSM_DOCUMENT"
  target_id      = aws_ssm_document.block_s3_public_access.name
  target_version = "1"

  resource_type = "AWS::S3::Bucket"

  # RESOURCE_ID resolves to the non-compliant bucket's name, which is what
  # makes one remediation configuration cover every bucket.
  parameter {
    name           = "BucketName"
    resource_value = "RESOURCE_ID"
  }

  parameter {
    name         = "AutomationAssumeRole"
    static_value = aws_iam_role.remediation.arn
  }

  automatic                  = var.enable_automatic_remediation
  maximum_automatic_attempts = var.remediation_max_attempts
  retry_attempt_seconds      = var.remediation_retry_seconds

  execution_controls {
    ssm_controls {
      # Caps how much can be remediated at once, so a mass
      # misconfiguration cannot turn into a mass unattended change.
      concurrent_execution_rate_percentage = 10
      error_percentage                     = 25
    }
  }

  depends_on = [aws_iam_role_policy.remediation]
}

#######################################################################
# Optional test fixture
#
# Deliberately created WITHOUT a public access block, so the Config rule
# has something to evaluate. It is NOT made public here: Terraform never
# creates a publicly readable bucket in this repo.
#
# To actually trigger the rule you attach a public policy yourself, with
# scripts/test-remediation.sh, which prompts before doing it.
#######################################################################

resource "aws_s3_bucket" "remediation_demo" {
  # checkov:skip=CKV2_AWS_6:The absent public access block IS the test condition — it is what the Config rule detects and what the remediation then applies.
  # checkov:skip=CKV_AWS_21:Throwaway fixture with force_destroy, holds no data worth versioning.
  count = var.create_demo_bucket ? 1 : 0

  bucket        = "${var.project}-remediation-demo-${local.account_id}"
  force_destroy = true

  tags = merge(var.tags, {
    Purpose = "Config remediation test fixture"
    Warning = "Intentionally lacks a public access block"
  })
}

resource "aws_s3_bucket_ownership_controls" "remediation_demo" {
  # checkov:skip=CKV2_AWS_65:ACLs must remain enabled, otherwise the test cannot make the bucket public and there is nothing for the rule to catch.
  count = var.create_demo_bucket ? 1 : 0

  bucket = aws_s3_bucket.remediation_demo[0].id

  rule {
    # ObjectWriter rather than BucketOwnerEnforced: ACLs must remain
    # usable for the test to be able to make the bucket public at all.
    object_ownership = "ObjectWriter"
  }
}
