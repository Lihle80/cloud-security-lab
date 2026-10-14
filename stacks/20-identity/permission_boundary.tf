#######################################################################
# IAM permission boundary — lab item 2
#
# A boundary is not a grant. It is the ceiling on what any identity
# policy attached to the principal can achieve, so the effective
# permission set is (identity policy ∩ boundary).
#
# The escalation this closes: a developer who can create roles can
# otherwise create an unconstrained admin role and assume it. Statement
# `DenyPrincipalCreationWithoutBoundary` forces every principal they
# create to carry this same boundary, making the restriction transitive.
#######################################################################

data "aws_caller_identity" "current" {}
data "aws_partition" "current" {}

locals {
  account_id = data.aws_caller_identity.current.account_id
  partition  = data.aws_partition.current.partition

  boundary_name = "aws-security-lab-developer-boundary"

  # Computed rather than referencing the resource, to avoid a dependency
  # cycle: the policy document conditions on its own ARN.
  boundary_arn = "arn:${local.partition}:iam::${local.account_id}:policy/${local.boundary_name}"
}

# The wildcard below is flagged by scanners and is nonetheless correct.
# A permission boundary is not a grant: it is the upper bound on what an
# identity policy can achieve. The effective permissions are
# (identity policy AND boundary), so a boundary that did not start at
# "*" would have to re-enumerate every service a developer may ever
# use, and would silently block anything omitted. The security comes
# from the Deny statements below, which no identity policy can override.
#tfsec:ignore:AVD-AWS-0057
data "aws_iam_policy_document" "developer_boundary" {
  statement {
    sid       = "AllowServicesWithinCeiling"
    effect    = "Allow"
    actions   = ["*"]
    resources = ["*"]
  }

  statement {
    sid       = "DenyOutsideApprovedRegions"
    effect    = "Deny"
    resources = ["*"]

    not_actions = [
      "iam:*",
      "sts:*",
      "organizations:*",
      "cloudfront:*",
      "route53:*",
      "support:*",
      "budgets:*",
      "ce:*",
      "waf:*",
      "wafv2:*",
      "shield:*",
      "access-analyzer:*",
      "s3:ListAllMyBuckets",
      "s3:GetBucketLocation",
    ]

    condition {
      test     = "StringNotEquals"
      variable = "aws:RequestedRegion"
      values   = var.allowed_regions
    }
  }

  # Transitive enforcement: any role or user they create must carry this
  # boundary, so they cannot mint an unconstrained principal.
  statement {
    sid    = "DenyPrincipalCreationWithoutBoundary"
    effect = "Deny"
    actions = [
      "iam:CreateUser",
      "iam:CreateRole",
    ]
    resources = ["*"]

    condition {
      test     = "StringNotEquals"
      variable = "iam:PermissionsBoundary"
      values   = [local.boundary_arn]
    }
  }

  # Nor may they remove a boundary from an existing principal.
  statement {
    sid    = "DenyBoundaryRemoval"
    effect = "Deny"
    actions = [
      "iam:DeleteUserPermissionsBoundary",
      "iam:DeleteRolePermissionsBoundary",
    ]
    resources = ["*"]
  }

  # Nor edit the boundary policy itself to widen the ceiling.
  statement {
    sid    = "ProtectBoundaryPolicy"
    effect = "Deny"
    actions = [
      "iam:CreatePolicyVersion",
      "iam:DeletePolicy",
      "iam:DeletePolicyVersion",
      "iam:SetDefaultPolicyVersion",
    ]
    resources = [local.boundary_arn]
  }

  # Long-lived credentials are the thing this lab exists to avoid.
  statement {
    sid    = "DenyLongLivedCredentials"
    effect = "Deny"
    actions = [
      "iam:CreateAccessKey",
      "iam:CreateLoginProfile",
      "iam:UpdateAccessKey",
    ]
    resources = ["*"]
  }

  # Same protections as the SCP, repeated at the boundary layer so they
  # hold even in the management account, where SCPs do not apply.
  statement {
    sid    = "DenySecurityServiceTampering"
    effect = "Deny"
    actions = [
      "cloudtrail:StopLogging",
      "cloudtrail:DeleteTrail",
      "guardduty:DeleteDetector",
      "guardduty:UpdateDetector",
      "config:DeleteConfigurationRecorder",
      "config:StopConfigurationRecorder",
      "securityhub:DisableSecurityHub",
      "securityhub:BatchDisableStandards",
      "access-analyzer:DeleteAnalyzer",
      "kms:ScheduleKeyDeletion",
      "kms:DisableKey",
    ]
    resources = ["*"]
  }

  # Organizations and billing stay with the platform team.
  statement {
    sid    = "DenyOrganizationsAndBillingWrites"
    effect = "Deny"
    actions = [
      "organizations:*",
      "account:Put*",
      "account:Delete*",
      "aws-portal:Modify*",
    ]
    resources = ["*"]
  }
}

resource "aws_iam_policy" "developer_boundary" {
  name        = local.boundary_name
  description = "Permission boundary capping what developer principals can reach"
  policy      = data.aws_iam_policy_document.developer_boundary.json
}

#######################################################################
# A role that demonstrates the boundary in effect.
#
# PowerUserAccess as the identity policy, boundary as the ceiling. The
# role can do most things, but cannot leave the approved regions, cannot
# mint unconstrained principals, and cannot disable the detection layer
# — even though PowerUserAccess alone would allow some of that.
#######################################################################

data "aws_iam_policy_document" "developer_trust" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]

    principals {
      type        = "AWS"
      identifiers = ["arn:${local.partition}:iam::${local.account_id}:root"]
    }

    # Force MFA on human assumption of this role.
    condition {
      test     = "Bool"
      variable = "aws:MultiFactorAuthPresent"
      values   = ["true"]
    }
  }
}

resource "aws_iam_role" "developer" {
  name                 = "aws-security-lab-developer"
  description          = "Developer role constrained by the lab permission boundary"
  assume_role_policy   = data.aws_iam_policy_document.developer_trust.json
  permissions_boundary = aws_iam_policy.developer_boundary.arn
  max_session_duration = 3600
}

resource "aws_iam_role_policy_attachment" "developer_poweruser" {
  role       = aws_iam_role.developer.name
  policy_arn = "arn:${local.partition}:iam::aws:policy/PowerUserAccess"
}
