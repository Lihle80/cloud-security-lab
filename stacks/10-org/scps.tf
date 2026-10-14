#######################################################################
# Service Control Policies — lab item 2
#
# Four guardrails:
#   1. deny-unapproved-regions          region lockdown
#   2. deny-security-service-tampering  protect the detection layer
#   3. deny-root-user                   force role-based access
#   4. deny-leave-organization          stop accounts escaping guardrails
#
# SCPs cap what identity policies can grant; they never grant anything.
# They also never apply to the management account, which is both why the
# management account must stay empty of workloads and why attaching at
# root cannot lock you out of it.
#
# Hard limit: 5120 bytes per policy after whitespace is stripped.
#######################################################################

locals {
  # Services that only have endpoints in us-east-1, or that are global and
  # would break entirely under a naive region deny. Mirrors the carve-out
  # Control Tower's own region-deny control uses.
  global_service_actions = [
    "access-analyzer:*",
    "account:*",
    "acm:*",
    "artifact:*",
    "aws-marketplace:*",
    "aws-portal:*",
    "billing:*",
    "budgets:*",
    "ce:*",
    "chatbot:*",
    "cloudfront:*",
    "compute-optimizer:*",
    "config:*",
    "consolidatedbilling:*",
    "cur:*",
    "directconnect:*",
    "ec2:DescribeRegions",
    "ecr-public:*",
    "fms:*",
    "freetier:*",
    "globalaccelerator:*",
    "health:*",
    "iam:*",
    "invoicing:*",
    "kms:DescribeKey",
    "networkmanager:*",
    "notifications:*",
    "organizations:*",
    "payments:*",
    "pricing:*",
    "resource-explorer-2:*",
    "route53:*",
    "route53domains:*",
    "s3:GetAccountPublic*",
    "s3:ListAllMyBuckets",
    "s3:PutAccountPublic*",
    "savingsplans:*",
    "shield:*",
    "sso:*",
    "sts:*",
    "support:*",
    "supportplans:*",
    "tag:GetResources",
    "tax:*",
    "trustedadvisor:*",
    "waf-regional:*",
    "waf:*",
    "wafv2:*",
    "wellarchitected:*",
  ]

  deny_unapproved_regions = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "DenyUnapprovedRegions"
      Effect    = "Deny"
      NotAction = local.global_service_actions
      Resource  = "*"
      Condition = {
        StringNotEquals = {
          "aws:RequestedRegion" = var.allowed_regions
        }
        # Control Tower's own execution role must stay exempt or landing
        # zone operations break once the landing zone is deployed.
        ArnNotLike = {
          "aws:PrincipalARN" = [
            "arn:aws:iam::*:role/AWSControlTowerExecution",
            "arn:aws:iam::*:role/aws-service-role/*",
          ]
        }
      }
    }]
  })

  deny_security_service_tampering = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "ProtectCloudTrail"
        Effect = "Deny"
        Action = [
          "cloudtrail:StopLogging",
          "cloudtrail:DeleteTrail",
          "cloudtrail:UpdateTrail",
          "cloudtrail:PutEventSelectors",
          "cloudtrail:DeleteEventDataStore",
        ]
        Resource = "*"
      },
      {
        Sid    = "ProtectGuardDuty"
        Effect = "Deny"
        Action = [
          "guardduty:DeleteDetector",
          "guardduty:DisassociateFromMasterAccount",
          "guardduty:DisassociateMembers",
          "guardduty:DeleteMembers",
          "guardduty:StopMonitoringMembers",
          "guardduty:UpdateDetector",
        ]
        Resource = "*"
      },
      {
        Sid    = "ProtectConfig"
        Effect = "Deny"
        Action = [
          "config:DeleteConfigurationRecorder",
          "config:StopConfigurationRecorder",
          "config:DeleteDeliveryChannel",
          "config:DeleteConfigRule",
          "config:DeleteOrganizationConfigRule",
          "config:DeleteRetentionConfiguration",
        ]
        Resource = "*"
      },
      {
        Sid    = "ProtectSecurityHubAndAnalyzer"
        Effect = "Deny"
        Action = [
          "securityhub:DisableSecurityHub",
          "securityhub:DisassociateFromMasterAccount",
          "securityhub:DeleteMembers",
          "securityhub:BatchDisableStandards",
          "access-analyzer:DeleteAnalyzer",
        ]
        Resource = "*"
      },
    ]
  })

  deny_root_user = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid      = "DenyRootUserActions"
      Effect   = "Deny"
      Action   = "*"
      Resource = "*"
      Condition = {
        StringLike = {
          "aws:PrincipalArn" = "arn:aws:iam::*:root"
        }
      }
    }]
  })

  deny_leave_organization = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid    = "DenyLeavingOrganization"
      Effect = "Deny"
      Action = [
        "organizations:LeaveOrganization",
        "organizations:DeleteOrganization",
      ]
      Resource = "*"
    }]
  })
}

#######################################################################
# Policy resources
#######################################################################

resource "aws_organizations_policy" "deny_unapproved_regions" {
  name        = "deny-unapproved-regions"
  description = "Deny non-global service actions outside ${join(", ", var.allowed_regions)}"
  type        = "SERVICE_CONTROL_POLICY"
  content     = local.deny_unapproved_regions
}

resource "aws_organizations_policy" "deny_security_service_tampering" {
  name        = "deny-security-service-tampering"
  description = "Prevent disabling CloudTrail, GuardDuty, Config, Security Hub or Access Analyzer"
  type        = "SERVICE_CONTROL_POLICY"
  content     = local.deny_security_service_tampering
}

resource "aws_organizations_policy" "deny_root_user" {
  name        = "deny-root-user"
  description = "Deny all actions performed by an account root user"
  type        = "SERVICE_CONTROL_POLICY"
  content     = local.deny_root_user
}

resource "aws_organizations_policy" "deny_leave_organization" {
  name        = "deny-leave-organization"
  description = "Prevent member accounts from leaving the organization"
  type        = "SERVICE_CONTROL_POLICY"
  content     = local.deny_leave_organization
}

#######################################################################
# Attachments
#
# Guardrails that should hold everywhere go on every OU. The region deny
# is scoped to Workloads and Sandbox so the Security and Infrastructure
# OUs can still reach services pinned to other regions if needed.
#######################################################################

locals {
  all_ou_ids = {
    security       = aws_organizations_organizational_unit.security.id
    infrastructure = aws_organizations_organizational_unit.infrastructure.id
    prod           = aws_organizations_organizational_unit.workloads_prod.id
    nonprod        = aws_organizations_organizational_unit.workloads_nonprod.id
    sandbox        = aws_organizations_organizational_unit.sandbox.id
  }

  region_restricted_ou_ids = {
    prod    = aws_organizations_organizational_unit.workloads_prod.id
    nonprod = aws_organizations_organizational_unit.workloads_nonprod.id
    sandbox = aws_organizations_organizational_unit.sandbox.id
  }
}

resource "aws_organizations_policy_attachment" "tampering_by_ou" {
  for_each = local.all_ou_ids

  policy_id = aws_organizations_policy.deny_security_service_tampering.id
  target_id = each.value
}

resource "aws_organizations_policy_attachment" "root_user_by_ou" {
  for_each = local.all_ou_ids

  policy_id = aws_organizations_policy.deny_root_user.id
  target_id = each.value
}

resource "aws_organizations_policy_attachment" "leave_org_by_ou" {
  for_each = local.all_ou_ids

  policy_id = aws_organizations_policy.deny_leave_organization.id
  target_id = each.value
}

resource "aws_organizations_policy_attachment" "region_deny_by_ou" {
  for_each = local.region_restricted_ou_ids

  policy_id = aws_organizations_policy.deny_unapproved_regions.id
  target_id = each.value
}

# Root attachment is gated: it takes effect on every existing member
# account the moment it applies. See the variable description.
resource "aws_organizations_policy_attachment" "tampering_at_root" {
  count = var.attach_scps_to_root ? 1 : 0

  policy_id = aws_organizations_policy.deny_security_service_tampering.id
  target_id = local.root_id
}

resource "aws_organizations_policy_attachment" "leave_org_at_root" {
  count = var.attach_scps_to_root ? 1 : 0

  policy_id = aws_organizations_policy.deny_leave_organization.id
  target_id = local.root_id
}
