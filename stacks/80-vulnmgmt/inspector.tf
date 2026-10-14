#######################################################################
# Amazon Inspector — lab item 8
#
# Continuous, agentless-ish vulnerability scanning. Worth knowing how it
# actually gets its data, because it dictates the prerequisites:
#
#   EC2     reads the package inventory the SSM agent already collects.
#           No Inspector agent. An instance that is not SSM-managed is
#           invisible to Inspector, which is the usual reason an account
#           shows zero EC2 findings and everyone assumes it is clean.
#
#   ECR     scans image layers on push, then rescans on a schedule as new
#           CVEs are published — so an image that was clean last month
#           can start failing without anything being rebuilt.
#
#   LAMBDA  inspects the dependencies in the deployment package.
#
#   LAMBDA_CODE  static analysis of your own code, not just dependencies.
#
# Findings flow into Security Hub automatically once both are enabled,
# which is why stack 30-detection comes first.
#######################################################################

data "aws_caller_identity" "current" {}
data "aws_partition" "current" {}

locals {
  account_id = data.aws_caller_identity.current.account_id
  partition  = data.aws_partition.current.partition
}

# Delegated admin must be designated before organization-wide enablement.
resource "aws_inspector2_delegated_admin_account" "this" {
  count = var.enable_inspector && var.inspector_delegated_admin_account_id != "" ? 1 : 0

  account_id = var.inspector_delegated_admin_account_id
}

resource "aws_inspector2_enabler" "this" {
  count = var.enable_inspector ? 1 : 0

  account_ids    = [local.account_id]
  resource_types = var.inspector_resource_types
}

# Auto-enables scanning in accounts that join the org later, so a newly
# vended account is not an unscanned blind spot.
resource "aws_inspector2_organization_configuration" "this" {
  count = var.enable_inspector && var.inspector_delegated_admin_account_id != "" ? 1 : 0

  auto_enable {
    ec2         = contains(var.inspector_resource_types, "EC2")
    ecr         = contains(var.inspector_resource_types, "ECR")
    lambda      = contains(var.inspector_resource_types, "LAMBDA")
    lambda_code = contains(var.inspector_resource_types, "LAMBDA_CODE")
  }

  depends_on = [
    aws_inspector2_delegated_admin_account.this,
    aws_inspector2_enabler.this,
  ]
}

#######################################################################
# Instance profile for SSM management
#
# The prerequisite that makes EC2 scanning work at all. Attach this
# profile to every instance: it enables Session Manager (no SSH port,
# no bastion), Patch Manager, and the inventory Inspector reads.
#######################################################################

data "aws_iam_policy_document" "ec2_assume" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["ec2.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "ssm_managed_instance" {
  name               = "${var.project}-ssm-managed-instance"
  description        = "Instance role enabling SSM, Patch Manager and Inspector coverage"
  assume_role_policy = data.aws_iam_policy_document.ec2_assume.json
}

resource "aws_iam_role_policy_attachment" "ssm_core" {
  role       = aws_iam_role.ssm_managed_instance.name
  policy_arn = "arn:${local.partition}:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

resource "aws_iam_instance_profile" "ssm_managed_instance" {
  name = "${var.project}-ssm-managed-instance"
  role = aws_iam_role.ssm_managed_instance.name
}

#######################################################################
# Route Inspector findings to the alerts topic from 30-detection
#
# Inspector findings also reach Security Hub, but a CRITICAL finding on
# an internet-facing resource deserves a push rather than waiting to be
# noticed in a console.
#######################################################################

data "aws_sns_topic" "alerts" {
  name = "${var.project}-security-alerts"
}

resource "aws_cloudwatch_event_rule" "inspector_critical" {
  count = var.enable_inspector ? 1 : 0

  name        = "${var.project}-inspector-critical"
  description = "Inspector CRITICAL and HIGH findings"

  event_pattern = jsonencode({
    source      = ["aws.inspector2"]
    detail-type = ["Inspector2 Finding"]
    detail = {
      severity = ["CRITICAL", "HIGH"]
      status   = ["ACTIVE"]
    }
  })
}

resource "aws_cloudwatch_event_target" "inspector_to_sns" {
  count = var.enable_inspector ? 1 : 0

  rule      = aws_cloudwatch_event_rule.inspector_critical[0].name
  target_id = "sns"
  arn       = data.aws_sns_topic.alerts.arn

  input_transformer {
    input_paths = {
      severity = "$.detail.severity"
      title    = "$.detail.title"
      resource = "$.detail.resources[0].id"
      type     = "$.detail.type"
      account  = "$.detail.awsAccountId"
    }

    input_template = <<-EOT
      "Inspector <severity> finding in account <account>"
      ""
      "Title:    <title>"
      "Type:     <type>"
      "Resource: <resource>"
    EOT
  }
}
