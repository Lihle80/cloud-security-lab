#######################################################################
# Security Hub — lab item 3
#
# Enables Security Hub with FSBP and CIS.
#
# DEPENDENCY WORTH KNOWING: most Security Hub controls are evaluated by
# AWS Config rules under the hood. Without a Config recorder, a large
# share of controls sit at "No data" rather than failing loudly. Stack
# 40-autoremediate turns Config on — apply it, or Security Hub here will
# look deceptively clean.
#######################################################################

resource "aws_securityhub_account" "this" {
  count = var.enable_security_hub ? 1 : 0

  # Consolidated findings: one finding per control rather than one per
  # standard, so FSBP and CIS overlap does not double-count.
  control_finding_generator = "SECURITY_CONTROL"

  # New controls added to an enabled standard switch on automatically.
  auto_enable_controls = true

  enable_default_standards = false
}

#######################################################################
# Standards
#######################################################################

resource "aws_securityhub_standards_subscription" "fsbp" {
  count = var.enable_security_hub ? 1 : 0

  standards_arn = "arn:${local.partition}:securityhub:${var.region}::standards/aws-foundational-security-best-practices/v/1.0.0"

  depends_on = [aws_securityhub_account.this]
}

resource "aws_securityhub_standards_subscription" "cis" {
  count = var.enable_security_hub && var.enable_cis_standard ? 1 : 0

  standards_arn = "arn:${local.partition}:securityhub:${var.region}::standards/cis-aws-foundations-benchmark/v/3.0.0"

  depends_on = [aws_securityhub_account.this]
}

#######################################################################
# Organization wiring
#######################################################################

resource "aws_securityhub_organization_admin_account" "this" {
  count = var.enable_security_hub && var.delegated_admin_account_id != "" ? 1 : 0

  admin_account_id = var.delegated_admin_account_id

  depends_on = [aws_securityhub_account.this]
}

resource "aws_securityhub_organization_configuration" "this" {
  count = var.enable_security_hub && var.delegated_admin_account_id != "" ? 1 : 0

  auto_enable           = false
  auto_enable_standards = "NONE"

  # Central configuration lets the delegated admin push standards and
  # control settings to members via policy, instead of each account
  # self-configuring.
  organization_configuration {
    configuration_type = "CENTRAL"
  }

  depends_on = [aws_securityhub_organization_admin_account.this]
}

#######################################################################
# Finding aggregation
#
# Without this, findings stay in the region that produced them and you
# have to check every region by hand.
#######################################################################

resource "aws_securityhub_finding_aggregator" "this" {
  count = var.enable_security_hub ? 1 : 0

  linking_mode = "ALL_REGIONS"

  depends_on = [aws_securityhub_account.this]
}
