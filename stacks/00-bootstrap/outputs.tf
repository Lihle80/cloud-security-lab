output "state_bucket" {
  description = "Name of the Terraform state bucket; use as `bucket` in each backend block."
  value       = aws_s3_bucket.state.id
}

output "state_kms_key_arn" {
  description = "KMS key encrypting Terraform state; use as `kms_key_id` in each backend block."
  value       = aws_kms_key.state.arn
}

output "backend_config" {
  description = "Copy-paste backend block for the remaining stacks."
  value       = <<-EOT
    terraform {
      backend "s3" {
        bucket       = "${aws_s3_bucket.state.id}"
        key          = "<stack-name>/terraform.tfstate"
        region       = "${var.region}"
        encrypt      = true
        kms_key_id   = "${aws_kms_key.state.arn}"
        use_lockfile = true
      }
    }
  EOT
}

output "gha_plan_role_arn" {
  description = "Role ARN for the plan/scan GitHub Actions job."
  value       = try(aws_iam_role.gha_plan[0].arn, null)
}

output "gha_apply_role_arn" {
  description = "Role ARN for the apply GitHub Actions job."
  value       = try(aws_iam_role.gha_apply[0].arn, null)
}
