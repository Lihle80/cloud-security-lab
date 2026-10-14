output "data_key_arn" {
  description = "Customer-managed key protecting data at rest."
  value       = aws_kms_key.data.arn
}

output "data_key_alias" {
  description = "Alias for the data key."
  value       = aws_kms_alias.data.name
}

output "backup_key_arn" {
  description = "Separate key protecting backups."
  value       = try(aws_kms_key.backup[0].arn, null)
}

output "protected_bucket" {
  description = "Bucket enforcing TLS 1.2+ and SSE-KMS with the data key."
  value       = aws_s3_bucket.protected.id
}

output "backup_vault_name" {
  description = "Backup vault name."
  value       = try(aws_backup_vault.this[0].name, null)
}

output "backup_vault_arn" {
  description = "Backup vault ARN."
  value       = try(aws_backup_vault.this[0].arn, null)
}

output "vault_lock_state" {
  description = "Vault lock mode in effect, or \"none\"."
  value       = var.enable_backup && var.enable_vault_lock ? var.vault_lock_mode : "none"
}

output "backup_alerts_topic_arn" {
  description = "Topic receiving backup job failure notifications."
  value       = try(aws_sns_topic.backup_alerts[0].arn, null)
}

output "cross_account_configured" {
  description = "Whether cross-account key and bucket access was granted."
  value       = local.has_cross_account
}
