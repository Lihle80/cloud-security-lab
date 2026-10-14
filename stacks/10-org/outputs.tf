output "root_id" {
  description = "Organization root ID."
  value       = local.root_id
}

output "organization_id" {
  description = "Organization ID."
  value       = data.aws_organizations_organization.current.id
}

output "ou_ids" {
  description = "Map of OU name to ID, consumed by the detection and identity stacks."
  value = {
    security       = aws_organizations_organizational_unit.security.id
    infrastructure = aws_organizations_organizational_unit.infrastructure.id
    workloads      = aws_organizations_organizational_unit.workloads.id
    prod           = aws_organizations_organizational_unit.workloads_prod.id
    nonprod        = aws_organizations_organizational_unit.workloads_nonprod.id
    sandbox        = aws_organizations_organizational_unit.sandbox.id
    suspended      = aws_organizations_organizational_unit.suspended.id
  }
}

output "scp_ids" {
  description = "Map of SCP name to ID."
  value = {
    deny_unapproved_regions         = aws_organizations_policy.deny_unapproved_regions.id
    deny_security_service_tampering = aws_organizations_policy.deny_security_service_tampering.id
    deny_root_user                  = aws_organizations_policy.deny_root_user.id
    deny_leave_organization         = aws_organizations_policy.deny_leave_organization.id
  }
}

output "external_access_analyzer_arn" {
  description = "ARN of the organization external-access analyzer."
  value       = aws_accessanalyzer_analyzer.org_external_access.arn
}
