#######################################################################
# IAM Access Analyzer — lab item 2
#
# Two analyzer types, which answer different questions:
#
#   ORGANIZATION               "what is reachable from outside the org?"
#                              Findings on resource policies that grant
#                              access to an external principal.
#
#   ORGANIZATION_UNUSED_ACCESS "what permissions are nobody using?"
#                              Findings on unused roles, unused access
#                              keys and unused service/action permissions.
#                              Billed per IAM role or user analyzed per
#                              month, hence the toggle.
#
# PREREQUISITE, not expressible in Terraform: trusted access for Access
# Analyzer must be enabled on the organization first. There is no
# standalone resource for enable-aws-service-access, and importing
# `aws_organizations_organization` would put DeleteOrganization inside
# `terraform destroy`. Run scripts/enable-org-service-access.sh once.
#######################################################################

resource "aws_accessanalyzer_analyzer" "org_external_access" {
  analyzer_name = "org-external-access"
  type          = "ORGANIZATION"
}

resource "aws_accessanalyzer_analyzer" "org_unused_access" {
  count = var.enable_unused_access_analyzer ? 1 : 0

  analyzer_name = "org-unused-access"
  type          = "ORGANIZATION_UNUSED_ACCESS"

  configuration {
    unused_access {
      unused_access_age = var.unused_access_age_days
    }
  }
}
