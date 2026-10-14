#######################################################################
# Control Tower landing zone — lab item 1
#
# NOT APPLIED. See ../README.md for why.
#
# Prerequisites that Terraform cannot create for you:
#   1. Log Archive and Audit accounts must already exist. The landing
#      zone consumes their account IDs; it does not create them.
#   2. Trusted access for Control Tower on the organization.
#   3. No existing landing zone in the organization.
#   4. IAM Identity Center must be enabled, or Control Tower will enable
#      it and take ownership of the instance.
#######################################################################

terraform {
  required_version = ">= 1.11.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.70"
    }
  }
}

provider "aws" {
  region = var.region

  default_tags {
    tags = var.tags
  }
}

data "aws_caller_identity" "current" {}
data "aws_organizations_organization" "current" {}

locals {
  # The landing zone manifest. Shape and allowed keys are fixed by
  # Control Tower, which is why this is a literal structure rather than
  # something more Terraform-idiomatic.
  manifest = {
    governedRegions = var.governed_regions

    organizationStructure = {
      security = {
        name = var.security_ou_name
      }
      sandbox = {
        name = var.sandbox_ou_name
      }
    }

    centralizedLogging = {
      accountId = var.log_archive_account_id
      enabled   = true

      configurations = {
        loggingBucket = {
          retentionDays = var.log_retention_days
        }
        accessLoggingBucket = {
          retentionDays = var.access_log_retention_days
        }
        # Encrypts the centralized log archive with a CMK rather than
        # SSE-S3. Omit the whole block to use SSE-S3.
        kmsKeyArn = var.logging_kms_key_arn != "" ? var.logging_kms_key_arn : null
      }
    }

    securityRoles = {
      accountId = var.audit_account_id
    }

    accessManagement = {
      # true lets Control Tower create and manage Identity Center
      # permission sets for the core accounts. Set false if you want
      # stacks/20-identity to remain the only thing managing Identity
      # Center, which avoids two systems fighting over permission sets.
      enabled = var.control_tower_manages_access
    }
  }
}

resource "aws_controltower_landing_zone" "this" {
  count = var.create_landing_zone ? 1 : 0

  manifest_json = jsonencode(local.manifest)
  version       = var.landing_zone_version

  tags = var.tags

  # Setup runs for 60-90 minutes and cannot be interrupted safely.
  timeouts {
    create = "180m"
    update = "180m"
    delete = "180m"
  }
}

#######################################################################
# Controls
#
# Control Tower's own guardrails, applied per OU. Identifiers follow
# the pattern:
#   arn:aws:controltower:<region>::control/<CONTROL_NAME>
# for legacy controls, and
#   arn:aws:controlcatalog:::control/<uuid>
# for newer ones in the Control Catalog.
#
# Only PREVENTIVE (SCP-backed) and DETECTIVE (Config-backed) controls
# affect Terraform-provisioned resources. PROACTIVE controls are
# CloudFormation Hooks and never fire for a Terraform apply — see
# ../README.md.
#######################################################################

resource "aws_controltower_control" "guardrails" {
  for_each = var.create_landing_zone ? toset(var.enabled_controls) : toset([])

  control_identifier = "arn:aws:controltower:${var.region}::control/${each.value}"
  target_identifier  = var.target_ou_arn

  depends_on = [aws_controltower_landing_zone.this]
}
