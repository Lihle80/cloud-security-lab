#######################################################################
# Account Factory for Terraform — lab item 1, the Terraform angle
#
# NOT APPLIED. See ../README.md.
#
# AFT is the GitOps front end to Account Factory: you commit an account
# request as Terraform, and a pipeline provisions, enrolls and
# customises the account.
#
# ----------------------------------------------------------------------
# WHAT THIS DEPLOYS, before you decide to run it
#
# Into a DEDICATED fifth account (the AFT management account):
#   - CodePipeline and CodeBuild projects, one set per vended account
#   - Step Functions state machines orchestrating the vending workflow
#   - DynamoDB tables holding account request state
#   - SQS queues, SNS topics, Lambda functions, EventBridge rules
#   - KMS keys, VPC with NAT gateway (unless you opt out)
#   - four CodeCommit repositories, or your own Git provider
#
# Most of that cost is fixed: it exists whether you vend one account a
# year or fifty. The NAT gateway alone is ~$32/month.
#
# PREREQUISITES
#   1. A working Control Tower landing zone (../landing-zone).
#   2. FIVE account IDs: management, log archive, audit, plus a fresh
#      dedicated AFT management account.
#   3. The AFT management account must NOT be any of the other four.
#   4. Run from the management account with Organizations access.
#   5. First apply takes 30-45 minutes; AFT then needs another ~15
#      minutes of self-bootstrapping before it can vend anything.
# ----------------------------------------------------------------------
#######################################################################

terraform {
  required_version = ">= 1.11.0"

  required_providers {
    # NOTE: 6.x here, while every stack under ../../stacks pins ~> 5.70.
    #
    # AFT 1.14 requires `hashicorp/aws >= 6.0.0, < 7.0.0`. Pinning 5.70
    # here produces an unsatisfiable constraint at init:
    #
    #   no available releases match the given constraints
    #   >= 4.9.0, >= 4.27.0, ~> 5.70, >= 6.0.0, < 7.0.0
    #
    # Divergence is safe because this directory is a separate Terraform
    # root with its own state and its own provider instance — nothing is
    # shared with the numbered stacks. Downgrade AFT to ~> 1.13 instead
    # if you would rather keep one provider version repo-wide.
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0"
    }
  }
}

provider "aws" {
  # Must be the Control Tower home region.
  region = var.region
}

#######################################################################
# NOTE ON THE MISSING `count`
#
# The AFT module declares its own provider configurations internally,
# and Terraform forbids count, for_each and depends_on on such a module:
#
#   "Module ... contains provider configurations, and so calls to it may
#    not use the count, for_each, or depends_on arguments."
#
# So the usual `count = var.enabled ? 1 : 0` guard is unavailable here.
# The guard is instead `i_understand_aft_costs`, a variable with no
# default and a validation that rejects false — so `terraform plan` in
# this directory fails immediately unless the cost note above has been
# read and acknowledged explicitly.
#######################################################################

module "aft" {
  source  = "aws-ia/control_tower_account_factory/aws"
  version = "~> 1.14"

  # --- Core account wiring -------------------------------------------
  ct_management_account_id    = var.ct_management_account_id
  log_archive_account_id      = var.log_archive_account_id
  audit_account_id            = var.audit_account_id
  aft_management_account_id   = var.aft_management_account_id
  ct_home_region              = var.region
  tf_backend_secondary_region = var.tf_backend_secondary_region

  # --- Git provider --------------------------------------------------
  #
  # "github" keeps account requests in the same place as this repo,
  # which is the whole point of the GitOps angle. "codecommit" avoids
  # needing a PAT but puts the repos somewhere nobody looks.
  vcs_provider = var.vcs_provider

  account_request_repo_name                     = var.account_request_repo
  account_customizations_repo_name              = var.account_customizations_repo
  global_customizations_repo_name               = var.global_customizations_repo
  account_provisioning_customizations_repo_name = var.account_provisioning_customizations_repo

  # --- Features ------------------------------------------------------

  # Deletes the default VPC in every vended account. Worth having on:
  # a default VPC has a public subnet in every AZ and an attached
  # internet gateway, which nobody audits because nobody created it.
  aft_feature_delete_default_vpcs_enabled = true

  # Enrolls vended accounts into the delegated-admin security services
  # automatically.
  aft_feature_enterprise_support = var.aft_feature_enterprise_support

  # Cloudtrail data events are expensive at scale; off unless needed.
  aft_feature_cloudtrail_data_events = false

  # --- Cost controls -------------------------------------------------

  # AFT builds its own VPC with NAT gateways by default. Using VPC
  # endpoints instead removes ~$32/month per NAT, at the cost of
  # ~$7.20/month per endpoint per AZ — cheaper only for small
  # deployments, which a lab is.
  aft_vpc_endpoints = var.aft_vpc_endpoints

  aft_backend_bucket_access_logs_object_expiration_days = 90

  # Terraform distribution AFT uses inside its pipelines.
  terraform_version      = var.terraform_version
  terraform_distribution = "oss"

  tags = var.tags
}
