output "trail_arn" {
  description = "Organization CloudTrail ARN."
  value       = try(aws_cloudtrail.org[0].arn, null)
}

output "trail_bucket" {
  description = "Bucket receiving organization trail logs."
  value       = try(aws_s3_bucket.trail[0].id, null)
}

output "trail_kms_key_arn" {
  description = "KMS key encrypting trail logs."
  value       = try(aws_kms_key.trail[0].arn, null)
}

output "guardduty_detector_id" {
  description = "Detector ID in use, whether created here or pre-existing."
  value       = local.detector_id
}

output "security_hub_enabled" {
  description = "Whether Security Hub was enabled by this stack."
  value       = var.enable_security_hub
}

output "enabled_standards" {
  description = "Security Hub standards subscribed to."
  value = compact([
    try(aws_securityhub_standards_subscription.fsbp[0].standards_arn, ""),
    try(aws_securityhub_standards_subscription.cis[0].standards_arn, ""),
  ])
}

output "alerts_topic_arn" {
  description = "SNS topic receiving GuardDuty and Security Hub alerts."
  value       = aws_sns_topic.alerts.arn
}

output "alerts_kms_key_arn" {
  description = "KMS key encrypting the alerts topic."
  value       = aws_kms_key.alerts.arn
}
