output "db_endpoint" {
  description = "Database endpoint, if provisioned."
  value       = try(aws_db_instance.this[0].address, null)
}

output "db_master_secret_arn" {
  description = <<-EOT
    ARN of the RDS-managed master user secret. The ARN is safe to output;
    the credential itself never enters Terraform state.
  EOT
  value       = try(aws_db_instance.this[0].master_user_secret[0].secret_arn, null)
}

output "rotation_days" {
  description = "Configured rotation interval for the master password."
  value       = var.enable_rds ? var.rotation_days : null
}

output "parameter_names" {
  description = "Parameters created, for comparison with Secrets Manager."
  value = compact([
    aws_ssm_parameter.api_key.name,
    aws_ssm_parameter.db_endpoint.name,
    try(aws_ssm_parameter.db_secret_arn[0].name, ""),
  ])
}

output "param_reader_role_arn" {
  description = "Role permitted to read the parameters and the database secret."
  value       = aws_iam_role.param_reader.arn
}
