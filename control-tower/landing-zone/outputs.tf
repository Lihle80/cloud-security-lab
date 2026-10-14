output "landing_zone_arn" {
  description = "Landing zone ARN, null while create_landing_zone is false."
  value       = try(aws_controltower_landing_zone.this[0].arn, null)
}

output "landing_zone_identifier" {
  description = "Landing zone identifier, needed by the AFT module."
  value       = try(aws_controltower_landing_zone.this[0].id, null)
}

output "drift_status" {
  description = "Control Tower's own view of whether the landing zone has drifted."
  value       = try(aws_controltower_landing_zone.this[0].drift_status, null)
}

output "latest_available_version" {
  description = "Newest landing zone version Control Tower offers, for upgrade planning."
  value       = try(aws_controltower_landing_zone.this[0].latest_available_version, null)
}

output "enabled_control_arns" {
  description = "Controls enabled on the target OU."
  value       = [for c in aws_controltower_control.guardrails : c.id]
}
