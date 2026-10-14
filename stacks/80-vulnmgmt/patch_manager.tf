#######################################################################
# SSM Patch Manager — lab item 8
#
# Inspector tells you what is vulnerable; Patch Manager fixes it. The
# pieces and how they connect:
#
#   patch baseline      which patches are approved, and after how long
#   patch group         a tag that binds instances to a baseline
#   maintenance window  when patching is allowed to happen
#   window target       which instances, selected by tag
#   window task         what runs — AWS-RunPatchBaseline
#
# Two windows on purpose: a nightly Scan that only reports compliance,
# and a weekly Install that actually reboots things. Scanning daily
# means the compliance picture is never more than a day stale, without
# rebooting anything daily.
#######################################################################

#######################################################################
# Baseline
#
# Rule order matters: the Critical/Important security rule approves with
# zero delay, while everything else waits `patch_approval_delay_days`.
# A patch matching both gets the shortest delay.
#######################################################################

locals {
  # Patch baseline names may not begin with "AWS-" or "AWS:" — reserved
  # for AWS-managed baselines, and the check is case-insensitive:
  #
  #   ValidationException: Patch Baseline Name:
  #   aws-security-lab-amazon-linux cannot starts with: AWS- or AWS:
  #
  # Third place this project slug collides with a reserved prefix, after
  # the SSM document name and the Parameter Store path.
  patch_baseline_name = "${replace(var.project, "/^aws-/", "")}-amazon-linux"
}

resource "aws_ssm_patch_baseline" "linux" {
  count = var.enable_patch_manager ? 1 : 0

  name             = local.patch_baseline_name
  description      = "Amazon Linux 2023: security patches fast, everything else delayed"
  operating_system = "AMAZON_LINUX_2023"

  # NOTE: CLASSIFICATION values are case-SENSITIVE and capitalised.
  # Valid values are Security, Bugfix, Enhancement, Recommended and
  # Newpackage; lowercase "security" is rejected outright.

  # Security patches rated Critical or Important: no waiting.
  approval_rule {
    approve_after_days  = 0
    compliance_level    = "CRITICAL"
    enable_non_security = false

    patch_filter {
      key    = "CLASSIFICATION"
      values = ["Security"]
    }

    patch_filter {
      key    = "SEVERITY"
      values = ["Critical", "Important"]
    }
  }

  # Bugfixes and lower-severity security patches: soak first.
  approval_rule {
    approve_after_days  = var.patch_approval_delay_days
    compliance_level    = "HIGH"
    enable_non_security = true

    patch_filter {
      key    = "CLASSIFICATION"
      values = ["Security", "Bugfix"]
    }
  }

  # Everything else, including enhancements and recommended updates.
  approval_rule {
    approve_after_days  = 30
    compliance_level    = "MEDIUM"
    enable_non_security = true

    patch_filter {
      key    = "PRODUCT"
      values = ["*"]
    }
  }

  tags = { Name = "${var.project}-amazon-linux" }
}

# Binds every instance tagged `Patch Group = <value>` to the baseline.
# The space in the tag key is mandatory and easy to get wrong.
resource "aws_ssm_patch_group" "linux" {
  count = var.enable_patch_manager ? 1 : 0

  baseline_id = aws_ssm_patch_baseline.linux[0].id
  patch_group = var.patch_group_tag_value
}

#######################################################################
# Role the maintenance window runs as
#######################################################################

data "aws_iam_policy_document" "maintenance_assume" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["ssm.amazonaws.com"]
    }

    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [local.account_id]
    }
  }
}

resource "aws_iam_role" "maintenance_window" {
  count = var.enable_patch_manager ? 1 : 0

  name               = "${var.project}-maintenance-window"
  description        = "Role Systems Manager assumes to run maintenance window tasks"
  assume_role_policy = data.aws_iam_policy_document.maintenance_assume.json
}

resource "aws_iam_role_policy_attachment" "maintenance_window" {
  count = var.enable_patch_manager ? 1 : 0

  role       = aws_iam_role.maintenance_window[0].name
  policy_arn = "arn:${local.partition}:iam::aws:policy/service-role/AmazonSSMMaintenanceWindowRole"
}

#######################################################################
# Scan window — nightly, reports only, never reboots
#######################################################################

resource "aws_ssm_maintenance_window" "scan" {
  count = var.enable_patch_manager ? 1 : 0

  name     = "${var.project}-patch-scan"
  schedule = var.scan_window_schedule

  # Hours the window stays open, and how long before it closes that new
  # tasks stop being started.
  duration = 2
  cutoff   = 1

  schedule_timezone = "UTC"

  tags = { Name = "${var.project}-patch-scan" }
}

resource "aws_ssm_maintenance_window_target" "scan" {
  count = var.enable_patch_manager ? 1 : 0

  window_id     = aws_ssm_maintenance_window.scan[0].id
  resource_type = "INSTANCE"
  name          = "${var.project}-scan-targets"

  targets {
    key    = "tag:Patch Group"
    values = [var.patch_group_tag_value]
  }
}

resource "aws_ssm_maintenance_window_task" "scan" {
  count = var.enable_patch_manager ? 1 : 0

  window_id        = aws_ssm_maintenance_window.scan[0].id
  task_type        = "RUN_COMMAND"
  task_arn         = "AWS-RunPatchBaseline"
  priority         = 1
  service_role_arn = aws_iam_role.maintenance_window[0].arn

  # Percentages rather than counts, so this scales with the fleet.
  max_concurrency = "50%"
  max_errors      = "25%"

  targets {
    key    = "WindowTargetIds"
    values = [aws_ssm_maintenance_window_target.scan[0].id]
  }

  task_invocation_parameters {
    run_command_parameters {
      parameter {
        name   = "Operation"
        values = ["Scan"]
      }
    }
  }
}

#######################################################################
# Install window — weekly, applies patches and may reboot
#######################################################################

resource "aws_ssm_maintenance_window" "install" {
  count = var.enable_patch_manager ? 1 : 0

  name     = "${var.project}-patch-install"
  schedule = var.patch_window_schedule

  duration = 4
  cutoff   = 1

  schedule_timezone = "UTC"

  tags = { Name = "${var.project}-patch-install" }
}

resource "aws_ssm_maintenance_window_target" "install" {
  count = var.enable_patch_manager ? 1 : 0

  window_id     = aws_ssm_maintenance_window.install[0].id
  resource_type = "INSTANCE"
  name          = "${var.project}-install-targets"

  targets {
    key    = "tag:Patch Group"
    values = [var.patch_group_tag_value]
  }
}

resource "aws_ssm_maintenance_window_task" "install" {
  count = var.enable_patch_manager ? 1 : 0

  window_id        = aws_ssm_maintenance_window.install[0].id
  task_type        = "RUN_COMMAND"
  task_arn         = "AWS-RunPatchBaseline"
  priority         = 1
  service_role_arn = aws_iam_role.maintenance_window[0].arn

  # Deliberately lower than the scan window: patching reboots, so a bad
  # patch should take out a quarter of the fleet at most, and the 10%
  # error budget stops the rollout early.
  max_concurrency = "25%"
  max_errors      = "10%"

  targets {
    key    = "WindowTargetIds"
    values = [aws_ssm_maintenance_window_target.install[0].id]
  }

  task_invocation_parameters {
    run_command_parameters {
      parameter {
        name   = "Operation"
        values = ["Install"]
      }

      # RebootIfNeeded lets the agent reboot only when a patch requires
      # it, rather than unconditionally.
      parameter {
        name   = "RebootOption"
        values = ["RebootIfNeeded"]
      }
    }
  }
}
