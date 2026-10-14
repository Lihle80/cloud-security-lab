#######################################################################
# IAM Identity Center — lab item 2
#
# Groups, permission sets and account assignments.
#
# The Identity Center *instance* is not managed here: AWS exposes no
# create API that Terraform wraps, so enabling it is a one-time console
# action. Everything below keys off the data source and is skipped
# entirely while `enable_identity_center` is false, which keeps the
# stack appliable before the instance exists.
#######################################################################

data "aws_ssoadmin_instances" "this" {
  count = var.enable_identity_center ? 1 : 0
}

locals {
  sso_instance_arn = try(tolist(data.aws_ssoadmin_instances.this[0].arns)[0], null)
  identity_store_id = try(
    tolist(data.aws_ssoadmin_instances.this[0].identity_store_ids)[0],
    null
  )

  # Falls back to the caller's own account so the stack is self-contained.
  target_account_ids = length(var.assignment_target_account_ids) > 0 ? var.assignment_target_account_ids : [local.account_id]

  # Job-function sets rather than one admin set. Session duration shortens
  # as privilege rises.
  permission_set_defs = {
    breakglass_admin = {
      name             = "Breakglass-Administrator"
      description      = "Emergency full access. Short session, expected to be alarmed on."
      session_duration = var.breakglass_session_duration
      managed_policies = ["arn:${local.partition}:iam::aws:policy/AdministratorAccess"]
      group_name       = "lab-breakglass"
      group_desc       = "Break-glass responders. Membership should be empty day to day."
    }

    platform_engineer = {
      name             = "Platform-Engineer"
      description      = "Builds infrastructure. PowerUser minus IAM and Organizations."
      session_duration = var.session_duration
      managed_policies = ["arn:${local.partition}:iam::aws:policy/PowerUserAccess"]
      group_name       = "lab-platform-engineers"
      group_desc       = "Engineers who provision infrastructure."
    }

    security_auditor = {
      name             = "Security-Auditor"
      description      = "Read-only plus the audit-specific reads SecurityAudit adds."
      session_duration = var.session_duration
      managed_policies = [
        "arn:${local.partition}:iam::aws:policy/SecurityAudit",
        "arn:${local.partition}:iam::aws:policy/ReadOnlyAccess",
      ]
      group_name = "lab-security-auditors"
      group_desc = "Security reviewers. Read-only by construction."
    }

    read_only = {
      name             = "Read-Only"
      description      = "Baseline visibility for anyone who needs to look but not touch."
      session_duration = var.session_duration
      managed_policies = ["arn:${local.partition}:iam::aws:policy/ReadOnlyAccess"]
      group_name       = "lab-readonly"
      group_desc       = "Default group for new joiners."
    }
  }

  permission_sets = var.enable_identity_center ? local.permission_set_defs : {}

  # Flatten (permission set x managed policy) for a single for_each.
  permission_set_policies = merge([
    for ps_key, ps in local.permission_sets : {
      for arn in ps.managed_policies :
      "${ps_key}:${basename(arn)}" => {
        permission_set_key = ps_key
        policy_arn         = arn
      }
    }
  ]...)

  # Flatten (permission set x target account) for assignments.
  assignments = merge([
    for ps_key, ps in local.permission_sets : {
      for acct in local.target_account_ids :
      "${ps_key}:${acct}" => {
        permission_set_key = ps_key
        account_id         = acct
      }
    }
  ]...)
}

#######################################################################
# Groups
#######################################################################

resource "aws_identitystore_group" "this" {
  for_each = local.permission_sets

  identity_store_id = local.identity_store_id
  display_name      = each.value.group_name
  description       = each.value.group_desc
}

#######################################################################
# Permission sets
#######################################################################

resource "aws_ssoadmin_permission_set" "this" {
  for_each = local.permission_sets

  instance_arn     = local.sso_instance_arn
  name             = each.value.name
  description      = each.value.description
  session_duration = each.value.session_duration

  # Sends the user back to the console home after federating.
  relay_state = "https://console.aws.amazon.com/console/home"

  tags = var.tags
}

resource "aws_ssoadmin_managed_policy_attachment" "this" {
  for_each = local.permission_set_policies

  instance_arn       = local.sso_instance_arn
  managed_policy_arn = each.value.policy_arn
  permission_set_arn = aws_ssoadmin_permission_set.this[each.value.permission_set_key].arn
}

#######################################################################
# Inline policy: deny outside approved regions
#
# Belt-and-braces with the region-deny SCP. The SCP does not apply to
# the management account, so without this a Platform-Engineer session in
# the management account would be unrestricted by region.
#######################################################################

data "aws_iam_policy_document" "region_restriction" {
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
}

resource "aws_ssoadmin_permission_set_inline_policy" "region_restriction" {
  # Break-glass is deliberately exempt: an incident may require acting in
  # an unexpected region.
  for_each = {
    for k, v in local.permission_sets : k => v if k != "breakglass_admin"
  }

  instance_arn       = local.sso_instance_arn
  permission_set_arn = aws_ssoadmin_permission_set.this[each.key].arn
  inline_policy      = data.aws_iam_policy_document.region_restriction.json
}

#######################################################################
# Account assignments
#######################################################################

resource "aws_ssoadmin_account_assignment" "this" {
  for_each = local.assignments

  instance_arn       = local.sso_instance_arn
  permission_set_arn = aws_ssoadmin_permission_set.this[each.value.permission_set_key].arn

  principal_id   = aws_identitystore_group.this[each.value.permission_set_key].group_id
  principal_type = "GROUP"

  target_id   = each.value.account_id
  target_type = "AWS_ACCOUNT"
}
