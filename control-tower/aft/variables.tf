variable "i_understand_aft_costs" {
  description = <<-EOT
    Explicit acknowledgement, with NO DEFAULT — you must pass it.

    The AFT module declares its own providers, so it cannot be gated with
    `count` (see the note in main.tf). This variable is the guard instead:
    with no default, `terraform plan` in this directory fails until you set
    it, and the validation below rejects false.

    Setting it true asserts that you have read ../README.md and accept that
    AFT stands up CodePipeline, CodeBuild, Step Functions, DynamoDB, Lambda
    and a VPC in a dedicated account, at a largely fixed monthly cost.
  EOT
  type        = bool

  validation {
    condition     = var.i_understand_aft_costs == true
    error_message = "Refusing to plan AFT until i_understand_aft_costs = true. Read control-tower/README.md first."
  }
}

variable "region" {
  description = "Control Tower home region. AFT must be deployed into the same one."
  type        = string
  default     = "us-west-2"
}

variable "tf_backend_secondary_region" {
  description = <<-EOT
    Second region for AFT's own Terraform state replication. Must differ from
    `region` — AFT replicates its backend cross-region so a regional outage
    does not block account vending.
  EOT
  type        = string
  default     = "us-east-1"
}

variable "ct_management_account_id" {
  description = "Organization management account ID."
  type        = string
  default     = ""
}

variable "log_archive_account_id" {
  description = "Control Tower Log Archive account ID."
  type        = string
  default     = ""
}

variable "audit_account_id" {
  description = "Control Tower Audit account ID."
  type        = string
  default     = ""
}

variable "aft_management_account_id" {
  description = <<-EOT
    DEDICATED account for AFT itself. Must not be the management, log archive
    or audit account — AFT deploys pipelines, state machines and a VPC here,
    and sharing the account with anything else makes both harder to reason
    about.
  EOT
  type        = string
  default     = ""
}

variable "vcs_provider" {
  description = "Where AFT reads account requests from: \"github\", \"githubenterprise\", \"gitlab\", \"bitbucket\" or \"codecommit\"."
  type        = string
  default     = "github"

  validation {
    condition = contains(
      ["github", "githubenterprise", "gitlab", "bitbucket", "codecommit"],
      var.vcs_provider
    )
    error_message = "Unsupported VCS provider."
  }
}

variable "account_request_repo" {
  description = "Repo holding account requests, as \"owner/repo\" for GitHub."
  type        = string
  default     = ""
}

variable "account_customizations_repo" {
  description = "Repo holding per-account customisations."
  type        = string
  default     = ""
}

variable "global_customizations_repo" {
  description = "Repo holding customisations applied to every vended account."
  type        = string
  default     = ""
}

variable "account_provisioning_customizations_repo" {
  description = "Repo holding provisioning-time customisations."
  type        = string
  default     = ""
}

variable "aft_feature_enterprise_support" {
  description = <<-EOT
    Enroll vended accounts in Enterprise Support automatically.

    Only set true if the organization actually holds an Enterprise Support
    agreement; otherwise vending fails at this step.
  EOT
  type        = bool
  default     = false
}

variable "aft_vpc_endpoints" {
  description = <<-EOT
    Use VPC endpoints instead of NAT gateways inside AFT's own VPC.

    True trades ~$32/month per NAT gateway for ~$7.20/month per endpoint per
    AZ. Cheaper for a small deployment, more expensive at scale.
  EOT
  type        = bool
  default     = true
}

variable "terraform_version" {
  description = "Terraform version AFT uses inside its pipelines."
  type        = string
  default     = "1.11.4"
}

variable "tags" {
  description = "Tags applied to AFT resources."
  type        = map(string)
  default = {
    Project   = "aws-security-lab"
    ManagedBy = "terraform"
    Stack     = "control-tower-aft"
  }
}
