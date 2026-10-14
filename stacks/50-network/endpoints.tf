#######################################################################
# VPC endpoints — lab item 5
#
# Two different mechanisms, often conflated:
#
#   Gateway endpoint (S3, DynamoDB)
#     A route table entry pointing at a prefix list. No ENI, no IP, no
#     security group, and FREE. Only reachable from inside the VPC.
#
#   Interface endpoint (everything else)
#     An ENI with a private IP in each subnet, fronted by PrivateLink.
#     Needs a security group. Billed hourly PER AZ plus data processing,
#     which is why these are off by default here.
#
# The endpoint policies below are the part people skip. Without one, an
# endpoint happily proxies requests to ANY bucket in ANY account, which
# makes it an exfiltration path. The S3 policy restricts it to this
# organization.
#######################################################################

data "aws_organizations_organization" "current" {}

#######################################################################
# Gateway endpoints — always on, no cost
#######################################################################

resource "aws_vpc_endpoint" "s3" {
  vpc_id            = aws_vpc.this.id
  service_name      = "com.amazonaws.${var.region}.s3"
  vpc_endpoint_type = "Gateway"

  # Isolated subnets included on purpose: this is how a database with no
  # route to the internet still writes backups to S3.
  route_table_ids = concat(
    aws_route_table.private[*].id,
    [aws_route_table.isolated.id],
  )

  policy = data.aws_iam_policy_document.s3_endpoint.json

  tags = { Name = "${local.name_prefix}-s3-gateway" }
}

data "aws_iam_policy_document" "s3_endpoint" {
  statement {
    sid       = "AllowOrgTrafficOnly"
    effect    = "Allow"
    actions   = ["s3:*"]
    resources = ["*"]

    principals {
      type        = "AWS"
      identifiers = ["*"]
    }

    # Stops the endpoint being used to reach a third party's bucket.
    condition {
      test     = "StringEquals"
      variable = "aws:PrincipalOrgID"
      values   = [data.aws_organizations_organization.current.id]
    }
  }

  # An org-only policy breaks `yum update` and `docker pull`, because
  # Amazon Linux repos and ECR layer storage live in AWS-owned buckets
  # outside your organization. These are those buckets, named explicitly
  # rather than waved through with a wildcard.
  statement {
    sid     = "AllowAwsOwnedServiceBuckets"
    effect  = "Allow"
    actions = ["s3:GetObject"]

    resources = [
      # ECR image layers
      "arn:${local.partition}:s3:::prod-${var.region}-starport-layer-bucket/*",
      # Amazon Linux 2 and 2023 package repositories
      "arn:${local.partition}:s3:::amazonlinux.${var.region}.amazonaws.com/*",
      "arn:${local.partition}:s3:::amazonlinux-2-repos-${var.region}/*",
      "arn:${local.partition}:s3:::al2023-repos-${var.region}-de612dc2/*",
      # SSM agent distribution
      "arn:${local.partition}:s3:::aws-ssm-${var.region}/*",
      "arn:${local.partition}:s3:::amazon-ssm-${var.region}/*",
      # Patch Manager baseline data
      "arn:${local.partition}:s3:::patch-baseline-snapshot-${var.region}/*",
    ]

    principals {
      type        = "AWS"
      identifiers = ["*"]
    }
  }
}

resource "aws_vpc_endpoint" "dynamodb" {
  vpc_id            = aws_vpc.this.id
  service_name      = "com.amazonaws.${var.region}.dynamodb"
  vpc_endpoint_type = "Gateway"

  route_table_ids = concat(
    aws_route_table.private[*].id,
    [aws_route_table.isolated.id],
  )

  tags = { Name = "${local.name_prefix}-dynamodb-gateway" }
}

#######################################################################
# Interface endpoints — opt-in, billed per AZ
#
# With ssm, ssmmessages and ec2messages present, Session Manager reaches
# a private instance with no NAT gateway, no bastion and no inbound rule
# of any kind. That is the pattern worth internalising: shell access
# without an SSH port anywhere.
#######################################################################

resource "aws_vpc_endpoint" "interface" {
  for_each = var.enable_interface_endpoints ? toset(var.interface_endpoint_services) : toset([])

  vpc_id            = aws_vpc.this.id
  service_name      = "com.amazonaws.${var.region}.${each.value}"
  vpc_endpoint_type = "Interface"

  subnet_ids         = aws_subnet.private[*].id
  security_group_ids = [aws_security_group.endpoints[0].id]

  # Lets callers use the normal public service hostname and have it
  # resolve to the endpoint's private IP, so no client config changes.
  private_dns_enabled = true

  tags = { Name = "${local.name_prefix}-${each.value}" }
}
