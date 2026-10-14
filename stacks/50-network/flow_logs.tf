#######################################################################
# VPC flow logs — lab item 5
#
# Flow logs answer "did these two things talk, and was it allowed?",
# which is the question an incident starts with. The custom format below
# adds four fields missing from the AWS default, all of which matter:
#
#   pkt-src-aws-service / pkt-dst-aws-service
#       names the AWS service at the far end, so you can tell S3 traffic
#       from an unknown IP without reverse-resolving anything
#   flow-direction
#       ingress or egress, which the default format forces you to infer
#   traffic-path
#       whether egress went via IGW, NAT, VPC peering or a gateway
#       endpoint. This is how you prove traffic left through NAT instead
#       of the endpoint you thought you configured.
#######################################################################

locals {
  flow_log_format = join(" ", [
    "$${version}",
    "$${account-id}",
    "$${interface-id}",
    "$${srcaddr}",
    "$${dstaddr}",
    "$${srcport}",
    "$${dstport}",
    "$${protocol}",
    "$${packets}",
    "$${bytes}",
    "$${start}",
    "$${end}",
    "$${action}",
    "$${log-status}",
    "$${vpc-id}",
    "$${subnet-id}",
    "$${instance-id}",
    "$${tcp-flags}",
    "$${type}",
    "$${pkt-srcaddr}",
    "$${pkt-dstaddr}",
    "$${region}",
    "$${az-id}",
    "$${pkt-src-aws-service}",
    "$${pkt-dst-aws-service}",
    "$${flow-direction}",
    "$${traffic-path}",
  ])

  flow_logs_to_s3         = var.enable_flow_logs && var.flow_log_destination == "s3"
  flow_logs_to_cloudwatch = var.enable_flow_logs && var.flow_log_destination == "cloudwatch"
}

#######################################################################
# S3 destination — cheaper, Athena-queryable
#######################################################################

# Flow logs are append-only, high-volume and short-lived here, so
# versioning, access logging and a CMK are all declined deliberately —
# each would multiply cost without changing what an investigator can
# see. Revisit if your flow logs are themselves sensitive.
#tfsec:ignore:AVD-AWS-0088
#tfsec:ignore:AVD-AWS-0089
#tfsec:ignore:AVD-AWS-0090
#tfsec:ignore:AVD-AWS-0132
resource "aws_s3_bucket" "flow_logs" {
  count = local.flow_logs_to_s3 ? 1 : 0

  bucket        = "${var.project}-flowlogs-${local.account_id}"
  force_destroy = true

  tags = { Name = "${local.name_prefix}-flowlogs" }
}

resource "aws_s3_bucket_public_access_block" "flow_logs" {
  count = local.flow_logs_to_s3 ? 1 : 0

  bucket                  = aws_s3_bucket.flow_logs[0].id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

#tfsec:ignore:AVD-AWS-0132
resource "aws_s3_bucket_server_side_encryption_configuration" "flow_logs" {
  count = local.flow_logs_to_s3 ? 1 : 0

  bucket = aws_s3_bucket.flow_logs[0].id

  rule {
    apply_server_side_encryption_by_default {
      # SSE-S3, not SSE-KMS: flow logs arrive as a very large number of
      # small objects and per-object KMS calls would cost more than the
      # storage. Revisit if your flow logs are themselves sensitive.
      sse_algorithm = "AES256"
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_ownership_controls" "flow_logs" {
  count = local.flow_logs_to_s3 ? 1 : 0

  bucket = aws_s3_bucket.flow_logs[0].id

  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "flow_logs" {
  count = local.flow_logs_to_s3 ? 1 : 0

  bucket = aws_s3_bucket.flow_logs[0].id

  rule {
    id     = "expire-flow-logs"
    status = "Enabled"

    filter {}

    expiration {
      days = var.flow_log_retention_days
    }

    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
  }
}

data "aws_iam_policy_document" "flow_logs_bucket" {
  count = local.flow_logs_to_s3 ? 1 : 0

  statement {
    sid       = "AWSLogDeliveryWrite"
    effect    = "Allow"
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.flow_logs[0].arn}/*"]

    principals {
      type        = "Service"
      identifiers = ["delivery.logs.amazonaws.com"]
    }

    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [local.account_id]
    }
  }

  statement {
    sid       = "AWSLogDeliveryAclCheck"
    effect    = "Allow"
    actions   = ["s3:GetBucketAcl", "s3:ListBucket"]
    resources = [aws_s3_bucket.flow_logs[0].arn]

    principals {
      type        = "Service"
      identifiers = ["delivery.logs.amazonaws.com"]
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
      aws_s3_bucket.flow_logs[0].arn,
      "${aws_s3_bucket.flow_logs[0].arn}/*",
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

resource "aws_s3_bucket_policy" "flow_logs" {
  count = local.flow_logs_to_s3 ? 1 : 0

  bucket = aws_s3_bucket.flow_logs[0].id
  policy = data.aws_iam_policy_document.flow_logs_bucket[0].json

  depends_on = [aws_s3_bucket_public_access_block.flow_logs]
}

resource "aws_flow_log" "s3" {
  count = local.flow_logs_to_s3 ? 1 : 0

  vpc_id       = aws_vpc.this.id
  traffic_type = "ALL"

  log_destination      = aws_s3_bucket.flow_logs[0].arn
  log_destination_type = "s3"
  log_format           = local.flow_log_format

  # One minute instead of the ten-minute default: during an incident the
  # difference between a one and ten minute lag is the difference between
  # watching an attack and reconstructing it.
  max_aggregation_interval = 60

  destination_options {
    # Columnar and partitioned, so Athena scans a fraction of the data
    # and costs a fraction as much to query.
    file_format                = "parquet"
    per_hour_partition         = true
    hive_compatible_partitions = true
  }

  tags = { Name = "${local.name_prefix}-flowlogs-s3" }

  depends_on = [aws_s3_bucket_policy.flow_logs]
}

#######################################################################
# CloudWatch Logs destination — live queryable with Logs Insights
#######################################################################

resource "aws_cloudwatch_log_group" "flow_logs" {
  count = local.flow_logs_to_cloudwatch ? 1 : 0

  name              = "/aws/vpc/flowlogs/${local.name_prefix}"
  retention_in_days = var.flow_log_retention_days
}

data "aws_iam_policy_document" "flow_logs_assume" {
  count = local.flow_logs_to_cloudwatch ? 1 : 0

  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["vpc-flow-logs.amazonaws.com"]
    }

    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [local.account_id]
    }
  }
}

resource "aws_iam_role" "flow_logs" {
  count = local.flow_logs_to_cloudwatch ? 1 : 0

  name               = "${var.project}-flow-logs"
  description        = "Role VPC flow logs assumes to write to CloudWatch Logs"
  assume_role_policy = data.aws_iam_policy_document.flow_logs_assume[0].json
}

data "aws_iam_policy_document" "flow_logs" {
  count = local.flow_logs_to_cloudwatch ? 1 : 0

  statement {
    effect = "Allow"

    actions = [
      "logs:CreateLogStream",
      "logs:PutLogEvents",
      "logs:DescribeLogStreams",
    ]

    resources = ["${aws_cloudwatch_log_group.flow_logs[0].arn}:*"]
  }
}

resource "aws_iam_role_policy" "flow_logs" {
  count = local.flow_logs_to_cloudwatch ? 1 : 0

  name   = "write-flow-logs"
  role   = aws_iam_role.flow_logs[0].id
  policy = data.aws_iam_policy_document.flow_logs[0].json
}

resource "aws_flow_log" "cloudwatch" {
  count = local.flow_logs_to_cloudwatch ? 1 : 0

  vpc_id       = aws_vpc.this.id
  traffic_type = "ALL"

  log_destination          = aws_cloudwatch_log_group.flow_logs[0].arn
  log_destination_type     = "cloud-watch-logs"
  iam_role_arn             = aws_iam_role.flow_logs[0].arn
  log_format               = local.flow_log_format
  max_aggregation_interval = 60

  tags = { Name = "${local.name_prefix}-flowlogs-cw" }
}
