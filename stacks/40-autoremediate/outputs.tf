output "config_bucket" {
  description = "Bucket receiving Config snapshots and history."
  value       = aws_s3_bucket.config.id
}

output "config_recorder_name" {
  description = "Name of the Config recorder."
  value       = aws_config_configuration_recorder.this.name
}

output "config_rule_names" {
  description = "Config rules created by this stack."
  value = [
    aws_config_config_rule.s3_public_read_prohibited.name,
    aws_config_config_rule.s3_public_write_prohibited.name,
    aws_config_config_rule.s3_ssl_requests_only.name,
    aws_config_config_rule.encrypted_volumes.name,
    aws_config_config_rule.imdsv2_required.name,
  ]
}

output "remediation_document_name" {
  description = "SSM Automation document invoked on a non-compliant bucket."
  value       = aws_ssm_document.block_s3_public_access.name
}

output "remediation_role_arn" {
  description = "Role the remediation automation assumes."
  value       = aws_iam_role.remediation.arn
}

output "automatic_remediation_enabled" {
  description = "Whether Config remediates without a human in the loop."
  value       = var.enable_automatic_remediation
}

output "demo_bucket" {
  description = "Test fixture bucket, if created."
  value       = try(aws_s3_bucket.remediation_demo[0].id, null)
}
