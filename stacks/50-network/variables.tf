variable "region" {
  description = "Region for the VPC."
  type        = string
  default     = "us-west-2"
}

variable "project" {
  description = "Short project slug used to name resources."
  type        = string
  default     = "aws-security-lab"
}

variable "vpc_cidr" {
  description = <<-EOT
    VPC CIDR. Defaults to 10.20.0.0/16 to stay clear of the 10.42.0.0/16 and
    172.31.0.0/16 ranges already in use in the lab account.
  EOT
  type        = string
  default     = "10.20.0.0/16"

  validation {
    condition     = can(cidrnetmask(var.vpc_cidr))
    error_message = "vpc_cidr must be valid CIDR notation."
  }
}

variable "az_count" {
  description = <<-EOT
    Availability zones to span.

    Two rather than three on purpose: interface VPC endpoints are billed per
    AZ per endpoint, so a third AZ adds 50% to the endpoint bill for no extra
    resilience in a lab.
  EOT
  type        = number
  default     = 2

  validation {
    condition     = var.az_count >= 2 && var.az_count <= 4
    error_message = "az_count must be between 2 and 4."
  }
}

variable "single_nat_gateway" {
  description = <<-EOT
    Share one NAT gateway across all private subnets.

    True for labs: a NAT gateway is roughly $32/month plus data processing, so
    one-per-AZ triples that for redundancy nothing here needs. Set false for a
    production-shaped build where losing an AZ must not sever egress.
  EOT
  type        = bool
  default     = true
}

variable "enable_nat_gateway" {
  description = <<-EOT
    Create NAT at all. With interface endpoints enabled, private workloads can
    reach SSM, KMS and CloudWatch without any egress path, so NAT is optional.
  EOT
  type        = bool
  default     = true
}

variable "enable_interface_endpoints" {
  description = <<-EOT
    Create interface (PrivateLink) endpoints for SSM, KMS and CloudWatch Logs.

    Cost warning: roughly $7.20/month per endpoint per AZ, plus data. The
    default set across 2 AZs lands near $70/month, which dwarfs everything
    else in this lab. Off by default; turn on deliberately, and run
    `terraform destroy` on this stack when you are done.

    Gateway endpoints for S3 and DynamoDB are always created because they are
    free.
  EOT
  type        = bool
  default     = false
}

variable "interface_endpoint_services" {
  description = "Service names for interface endpoints, without the com.amazonaws.<region> prefix."
  type        = list(string)
  default = [
    "ssm",
    "ssmmessages",
    "ec2messages",
    "kms",
    "logs",
    "secretsmanager",
  ]
}

variable "enable_flow_logs" {
  description = "Capture VPC flow logs."
  type        = bool
  default     = true
}

variable "flow_log_destination" {
  description = <<-EOT
    Where flow logs land.

    "s3"         cheapest, best for retention and Athena queries
    "cloudwatch" queryable live with Logs Insights, costs more to ingest
  EOT
  type        = string
  default     = "s3"

  validation {
    condition     = contains(["s3", "cloudwatch"], var.flow_log_destination)
    error_message = "flow_log_destination must be \"s3\" or \"cloudwatch\"."
  }
}

variable "flow_log_retention_days" {
  description = "Retention for flow logs in either destination."
  type        = number
  default     = 14
}

variable "enable_alb" {
  description = <<-EOT
    Create the ALB and its WAF web ACL.

    Cost note: roughly $16/month for the ALB plus $5/month for the web ACL and
    $1/month per managed rule group.
  EOT
  type        = bool
  default     = true
}

variable "certificate_arn" {
  description = <<-EOT
    ACM certificate for the HTTPS listener. Leave empty and the ALB serves a
    plain HTTP listener instead, which is a lab compromise, not a pattern to
    copy — issuing a certificate needs a domain you control.

    With a certificate present, HTTP redirects to HTTPS and TLS 1.2 is the
    floor.
  EOT
  type        = string
  default     = ""
}

variable "alb_allowed_cidrs" {
  description = <<-EOT
    CIDRs permitted to reach the ALB. Defaults to the whole internet because a
    public ALB behind WAF is the thing being demonstrated; narrow it to your
    own address to keep the lab private.
  EOT
  type        = list(string)
  default     = ["0.0.0.0/0"]
}

variable "waf_rate_limit" {
  description = "Requests per 5-minute window from a single IP before WAF blocks it."
  type        = number
  default     = 2000

  validation {
    condition     = var.waf_rate_limit >= 100
    error_message = "WAF rate-based rules require a limit of at least 100."
  }
}

variable "tags" {
  description = "Tags applied to every resource in this stack."
  type        = map(string)
  default = {
    Project   = "aws-security-lab"
    ManagedBy = "terraform"
    Stack     = "50-network"
  }
}
