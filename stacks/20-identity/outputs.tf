output "permission_boundary_arn" {
  description = "ARN of the developer permission boundary."
  value       = aws_iam_policy.developer_boundary.arn
}

output "developer_role_arn" {
  description = "Role demonstrating the boundary in effect."
  value       = aws_iam_role.developer.arn
}

output "identity_center_enabled" {
  description = "Whether the Identity Center portion of this stack is active."
  value       = var.enable_identity_center
}

output "sso_instance_arn" {
  description = "Identity Center instance ARN, null while disabled."
  value       = local.sso_instance_arn
}

output "permission_set_arns" {
  description = "Map of permission set key to ARN."
  value       = { for k, v in aws_ssoadmin_permission_set.this : k => v.arn }
}

output "group_ids" {
  description = "Map of permission set key to the Identity Store group ID assigned to it."
  value       = { for k, v in aws_identitystore_group.this : k => v.group_id }
}
