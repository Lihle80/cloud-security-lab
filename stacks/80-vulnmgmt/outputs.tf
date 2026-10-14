output "inspector_enabled_for" {
  description = "Resource types Inspector is scanning."
  value       = var.enable_inspector ? var.inspector_resource_types : []
}

output "ssm_instance_profile_name" {
  description = <<-EOT
    Instance profile to attach to EC2 instances. Required for Inspector EC2
    coverage, Patch Manager and Session Manager.
  EOT
  value       = aws_iam_instance_profile.ssm_managed_instance.name
}

output "patch_baseline_id" {
  description = "Custom patch baseline ID."
  value       = try(aws_ssm_patch_baseline.linux[0].id, null)
}

output "patch_group_tag" {
  description = "Tag an instance with this to bring it under the baseline."
  value       = var.enable_patch_manager ? { "Patch Group" = var.patch_group_tag_value } : null
}

output "maintenance_windows" {
  description = "Scan and install window IDs."
  value = {
    scan    = try(aws_ssm_maintenance_window.scan[0].id, null)
    install = try(aws_ssm_maintenance_window.install[0].id, null)
  }
}
