#######################################################################
# GuardDuty — lab item 3
#
# A region may hold only one detector, so this stack reads an existing
# one by default rather than colliding with it. Set
# `create_guardduty_detector = true` in a fresh account.
#
# Generate sample findings to exercise the EventBridge -> SNS path:
#   ./scripts/guardduty-sample-findings.sh
#######################################################################

resource "aws_guardduty_detector" "this" {
  count = var.create_guardduty_detector ? 1 : 0

  enable                       = true
  finding_publishing_frequency = var.guardduty_finding_publishing_frequency
}

data "aws_guardduty_detector" "existing" {
  count = var.create_guardduty_detector ? 0 : 1
}

locals {
  detector_id = var.create_guardduty_detector ? aws_guardduty_detector.this[0].id : data.aws_guardduty_detector.existing[0].id
}

# Protection plans below go beyond GuardDuty's always-on analysis of
# CloudTrail, VPC flow logs and DNS logs.
#
# RUNTIME_MONITORING is deliberately absent: it deploys an agent to
# EKS/ECS/EC2 and is priced per vCPU-hour, which does not belong in a lab.

#######################################################################
# Protection plans
#######################################################################

resource "aws_guardduty_detector_feature" "s3_data_events" {
  detector_id = local.detector_id
  name        = "S3_DATA_EVENTS"
  status      = "ENABLED"
}

resource "aws_guardduty_detector_feature" "eks_audit_logs" {
  detector_id = local.detector_id
  name        = "EKS_AUDIT_LOGS"
  status      = "ENABLED"
}

resource "aws_guardduty_detector_feature" "lambda_network_logs" {
  detector_id = local.detector_id
  name        = "LAMBDA_NETWORK_LOGS"
  status      = "ENABLED"
}

resource "aws_guardduty_detector_feature" "rds_login_events" {
  detector_id = local.detector_id
  name        = "RDS_LOGIN_EVENTS"
  status      = "ENABLED"
}

# Scans EBS snapshots when GuardDuty suspects an instance is compromised.
# Charged per GB scanned, and only on suspicion, so it stays cheap.
resource "aws_guardduty_detector_feature" "ebs_malware_protection" {
  detector_id = local.detector_id
  name        = "EBS_MALWARE_PROTECTION"
  status      = "ENABLED"
}

#######################################################################
# Organization wiring
#
# Delegating admin to a member account is the production pattern. With
# `delegated_admin_account_id` empty, GuardDuty is administered from this
# management account instead, which keeps the lab to two accounts.
#######################################################################

#######################################################################
# A delegated administrator is a HARD PREREQUISITE for organization
# configuration, not an optional extra. Without one,
# UpdateOrganizationConfiguration fails outright:
#
#   BadRequestException: The request failed because a delegated
#   administrator account has not been enabled.
#
# So the admin account is always designated. When
# `delegated_admin_account_id` is empty it falls back to this
# management account, which GuardDuty permits.
#
# Note the asymmetry with Security Hub below: Security Hub does NOT
# accept the management account as its delegated administrator, which
# is why that resource stays gated on an explicit member account ID
# while this one does not.
#######################################################################

locals {
  guardduty_admin_account_id = var.delegated_admin_account_id != "" ? var.delegated_admin_account_id : local.account_id
}

resource "aws_guardduty_organization_admin_account" "this" {
  admin_account_id = local.guardduty_admin_account_id

  depends_on = [aws_guardduty_detector_feature.s3_data_events]
}

# Auto-enables GuardDuty in every account that joins the org from now on,
# so a newly vended account is never a blind spot.
resource "aws_guardduty_organization_configuration" "this" {
  detector_id = local.detector_id

  # ALL = every existing and future member account.
  auto_enable_organization_members = "ALL"

  depends_on = [aws_guardduty_organization_admin_account.this]
}
