#######################################################################
# Security groups — lab item 5, half one
#
# Security groups are STATEFUL: allowing inbound 5432 implicitly allows
# the response back out. That is why none of the groups below need a
# matching rule for return traffic. Compare with nacls.tf, where the
# same path needs an explicit ephemeral-port rule in both directions.
#
# They are also referenceable: the app tier allows the ALB's group as a
# source rather than a CIDR, so the rule keeps holding when the ALB's
# addresses change. A CIDR-based rule would not.
#
# Written with the one-rule-per-resource form
# (aws_vpc_security_group_*_rule) rather than inline blocks, so a rule
# change shows up as a single diff rather than a whole-group replacement.
#######################################################################

locals {
  private_cidrs = local.private_subnets
  app_port      = 8080
  db_port       = 5432
}

#######################################################################
# ALB
#######################################################################

resource "aws_security_group" "alb" {
  name        = "${local.name_prefix}-alb"
  description = "Public entry point. Terminates client connections."
  vpc_id      = aws_vpc.this.id

  tags = { Name = "${local.name_prefix}-alb" }

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_vpc_security_group_ingress_rule" "alb_https" {
  for_each = toset(var.alb_allowed_cidrs)

  security_group_id = aws_security_group.alb.id
  description       = "HTTPS from ${each.value}"
  cidr_ipv4         = each.value
  from_port         = 443
  to_port           = 443
  ip_protocol       = "tcp"
}

# Port 80 exists only to carry the redirect to 443 when a certificate is
# configured. Without a certificate it is the only listener, which is a
# lab compromise called out in the README.
resource "aws_vpc_security_group_ingress_rule" "alb_http" {
  for_each = toset(var.alb_allowed_cidrs)

  security_group_id = aws_security_group.alb.id
  description       = "HTTP from ${each.value}, redirected to HTTPS when a cert is set"
  cidr_ipv4         = each.value
  from_port         = 80
  to_port           = 80
  ip_protocol       = "tcp"
}

resource "aws_vpc_security_group_egress_rule" "alb_to_app" {
  security_group_id = aws_security_group.alb.id
  description       = "Forward to the application tier only"

  # Group-to-group reference, not a CIDR.
  referenced_security_group_id = aws_security_group.app.id

  from_port   = local.app_port
  to_port     = local.app_port
  ip_protocol = "tcp"
}

#######################################################################
# Application tier
#######################################################################

resource "aws_security_group" "app" {
  name        = "${local.name_prefix}-app"
  description = "Application workloads. Reachable only from the ALB."
  vpc_id      = aws_vpc.this.id

  tags = { Name = "${local.name_prefix}-app" }

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_vpc_security_group_ingress_rule" "app_from_alb" {
  security_group_id = aws_security_group.app.id
  # No apostrophe: EC2 restricts rule descriptions to
  #   a-zA-Z0-9 . _ - : / ( ) # , @ [ ] + = & ; { } ! $ *
  # and rejects the whole request with InvalidParameterValue otherwise.
  description = "Application port from the ALB security group"

  referenced_security_group_id = aws_security_group.alb.id

  from_port   = local.app_port
  to_port     = local.app_port
  ip_protocol = "tcp"
}

# Needed for SSM Session Manager, KMS, CloudWatch and package installs,
# whether that traffic exits via NAT or via an interface endpoint.
resource "aws_vpc_security_group_egress_rule" "app_https_out" {
  security_group_id = aws_security_group.app.id
  description       = "HTTPS egress for AWS APIs and updates"
  cidr_ipv4         = "0.0.0.0/0"
  from_port         = 443
  to_port           = 443
  ip_protocol       = "tcp"
}

resource "aws_vpc_security_group_egress_rule" "app_to_db" {
  security_group_id = aws_security_group.app.id
  description       = "PostgreSQL to the database tier"

  referenced_security_group_id = aws_security_group.db.id

  from_port   = local.db_port
  to_port     = local.db_port
  ip_protocol = "tcp"
}

#######################################################################
# Database tier
#
# Ingress from the app group only, and NO egress rules at all. A
# database has no reason to originate outbound connections, and removing
# that capability removes a data-exfiltration path.
#######################################################################

resource "aws_security_group" "db" {
  name        = "${local.name_prefix}-db"
  description = "Database tier. Ingress from the app tier only, no egress."
  vpc_id      = aws_vpc.this.id

  tags = { Name = "${local.name_prefix}-db" }

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_vpc_security_group_ingress_rule" "db_from_app" {
  security_group_id = aws_security_group.db.id
  description       = "PostgreSQL from the application tier"

  referenced_security_group_id = aws_security_group.app.id

  from_port   = local.db_port
  to_port     = local.db_port
  ip_protocol = "tcp"
}

#######################################################################
# Interface endpoints
#
# PrivateLink ENIs live in the private subnets and need 443 from inside
# the VPC. Scoped to the VPC CIDR rather than 0.0.0.0/0.
#######################################################################

resource "aws_security_group" "endpoints" {
  count = var.enable_interface_endpoints ? 1 : 0

  name        = "${local.name_prefix}-vpc-endpoints"
  description = "Interface VPC endpoints. HTTPS from within the VPC."
  vpc_id      = aws_vpc.this.id

  tags = { Name = "${local.name_prefix}-vpc-endpoints" }
}

resource "aws_vpc_security_group_ingress_rule" "endpoints_https" {
  count = var.enable_interface_endpoints ? 1 : 0

  security_group_id = aws_security_group.endpoints[0].id
  description       = "HTTPS from inside the VPC"
  cidr_ipv4         = var.vpc_cidr
  from_port         = 443
  to_port           = 443
  ip_protocol       = "tcp"
}
