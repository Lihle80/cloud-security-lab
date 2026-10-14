#######################################################################
# 10-org — organizational unit structure
#
# Mirrors the OU layout the AWS Security Reference Architecture and
# Control Tower both assume, so this stack stays compatible with the
# landing zone in ../../control-tower.
#
#   Root
#   ├── Security          audit + log archive accounts
#   ├── Infrastructure    shared networking, CI/CD, tooling
#   ├── Workloads
#   │   ├── Prod
#   │   └── NonProd
#   ├── Sandbox           developer accounts, heavily guardrailed
#   └── Suspended         quarantine for accounts being decommissioned
#######################################################################

data "aws_organizations_organization" "current" {}

locals {
  root_id = data.aws_organizations_organization.current.roots[0].id
}

resource "aws_organizations_organizational_unit" "security" {
  name      = "Security"
  parent_id = local.root_id
}

resource "aws_organizations_organizational_unit" "infrastructure" {
  name      = "Infrastructure"
  parent_id = local.root_id
}

resource "aws_organizations_organizational_unit" "workloads" {
  name      = "Workloads"
  parent_id = local.root_id
}

resource "aws_organizations_organizational_unit" "workloads_prod" {
  name      = "Prod"
  parent_id = aws_organizations_organizational_unit.workloads.id
}

resource "aws_organizations_organizational_unit" "workloads_nonprod" {
  name      = "NonProd"
  parent_id = aws_organizations_organizational_unit.workloads.id
}

resource "aws_organizations_organizational_unit" "sandbox" {
  name      = "Sandbox"
  parent_id = local.root_id
}

resource "aws_organizations_organizational_unit" "suspended" {
  name      = "Suspended"
  parent_id = local.root_id
}

#######################################################################
# Account placement is deliberately NOT managed here.
#
# Terraform's only handle on an existing account is `aws_organizations_
# account`, which must be imported first and — critically — attempts to
# CLOSE the account on destroy. Putting a real account under that
# resource makes `terraform destroy` a data-loss event.
#
# Moving accounts between OUs is therefore a one-line CLI operation,
# documented in docs/RUNBOOK.md:
#
#   aws organizations move-account \
#     --account-id <id> \
#     --source-parent-id <root-or-ou-id> \
#     --destination-parent-id <ou-id>
#######################################################################
