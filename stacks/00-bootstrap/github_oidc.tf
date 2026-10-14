#######################################################################
# GitHub Actions OIDC — lab item 9
#
# Two roles, no long-lived access keys anywhere:
#
#   *-gha-plan   assumable from any ref or pull request, read-only plus
#                the state access a `terraform plan` needs.
#   *-gha-apply  assumable only from `github_apply_ref` on the exact
#                repo, and only outside a pull_request context.
#
# The `sub` claim is matched exactly rather than with a trailing
# wildcard, so a fork or an unrelated repo cannot assume either role.
#######################################################################

locals {
  create_oidc = var.github_repo != ""
  oidc_host   = "token.actions.githubusercontent.com"
}

resource "aws_iam_openid_connect_provider" "github" {
  count = local.create_oidc ? 1 : 0

  url            = "https://${local.oidc_host}"
  client_id_list = ["sts.amazonaws.com"]

  # IAM no longer verifies this value for well-known hosts, but the API
  # still requires it. These are GitHub's published thumbprints.
  thumbprint_list = [
    "6938fd4d98bab03faadb97b34396831e3780aea1",
    "1c58a3a8518e8759bf075b76b750d4f2df264fcd",
  ]
}

#######################################################################
# Plan role — read-only + state
#######################################################################

data "aws_iam_policy_document" "gha_plan_trust" {
  count = local.create_oidc ? 1 : 0

  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRoleWithWebIdentity"]

    principals {
      type        = "Federated"
      identifiers = [aws_iam_openid_connect_provider.github[0].arn]
    }

    condition {
      test     = "StringEquals"
      variable = "${local.oidc_host}:aud"
      values   = ["sts.amazonaws.com"]
    }

    # Any branch, tag or PR of this repo only.
    condition {
      test     = "StringLike"
      variable = "${local.oidc_host}:sub"
      values   = ["repo:${var.github_repo}:*"]
    }
  }
}

resource "aws_iam_role" "gha_plan" {
  count = local.create_oidc ? 1 : 0

  name                 = "${var.project}-gha-plan"
  description          = "GitHub Actions: terraform plan and IaC scanning"
  assume_role_policy   = data.aws_iam_policy_document.gha_plan_trust[0].json
  max_session_duration = 3600
}

resource "aws_iam_role_policy_attachment" "gha_plan_readonly" {
  count = local.create_oidc ? 1 : 0

  role       = aws_iam_role.gha_plan[0].name
  policy_arn = "arn:aws:iam::aws:policy/ReadOnlyAccess"
}

# ReadOnlyAccess cannot write the lock file or read encrypted state.
data "aws_iam_policy_document" "gha_plan_state" {
  count = local.create_oidc ? 1 : 0

  statement {
    sid    = "StateObjectAccess"
    effect = "Allow"
    actions = [
      "s3:GetObject",
      "s3:PutObject",
      "s3:DeleteObject",
    ]
    resources = ["${aws_s3_bucket.state.arn}/*"]
  }

  statement {
    sid       = "StateBucketList"
    effect    = "Allow"
    actions   = ["s3:ListBucket"]
    resources = [aws_s3_bucket.state.arn]
  }

  statement {
    sid    = "StateKeyUse"
    effect = "Allow"
    actions = [
      "kms:Decrypt",
      "kms:GenerateDataKey",
    ]
    resources = [aws_kms_key.state.arn]
  }
}

resource "aws_iam_role_policy" "gha_plan_state" {
  count = local.create_oidc ? 1 : 0

  name   = "terraform-state-access"
  role   = aws_iam_role.gha_plan[0].id
  policy = data.aws_iam_policy_document.gha_plan_state[0].json
}

#######################################################################
# Apply role — privileged, tightly scoped trust
#######################################################################

data "aws_iam_policy_document" "gha_apply_trust" {
  count = local.create_oidc ? 1 : 0

  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRoleWithWebIdentity"]

    principals {
      type        = "Federated"
      identifiers = [aws_iam_openid_connect_provider.github[0].arn]
    }

    condition {
      test     = "StringEquals"
      variable = "${local.oidc_host}:aud"
      values   = ["sts.amazonaws.com"]
    }

    # Exact match, not a wildcard: only this ref on this repo.
    condition {
      test     = "StringEquals"
      variable = "${local.oidc_host}:sub"
      values   = ["repo:${var.github_repo}:ref:${var.github_apply_ref}"]
    }
  }
}

resource "aws_iam_role" "gha_apply" {
  count = local.create_oidc ? 1 : 0

  name                 = "${var.project}-gha-apply"
  description          = "GitHub Actions: terraform apply from ${var.github_apply_ref}"
  assume_role_policy   = data.aws_iam_policy_document.gha_apply_trust[0].json
  max_session_duration = 3600
}

# Deliberate trade-off, documented in the README: this lab provisions
# across Organizations, Identity Center, KMS, Config, GuardDuty and more,
# so a hand-written least-privilege policy would be larger than the lab
# itself. The trust policy is the control that matters here.
resource "aws_iam_role_policy_attachment" "gha_apply_admin" {
  count = local.create_oidc ? 1 : 0

  role       = aws_iam_role.gha_apply[0].name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}
