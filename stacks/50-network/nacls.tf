#######################################################################
# Network ACLs — lab item 5, half two
#
# The contrast with security_groups.tf is the whole point of this file.
#
#   Security group          Network ACL
#   ----------------------  ----------------------------------------
#   stateful                stateless
#   allow rules only        allow AND deny rules
#   evaluated as a set      evaluated in rule-number order, first match wins
#   attaches to an ENI      attaches to a subnet
#   can reference a group   CIDR only
#
# Because NACLs are stateless, every permitted conversation needs TWO
# rules: one for the request and one for the response on the ephemeral
# port range. Forgetting the second is the single most common cause of
# "the security group is right but it still times out".
#
# Linux uses 32768-60999 for ephemeral ports; the 1024-65535 range below
# is the conventional superset that also covers NLB health checks and
# Windows.
#######################################################################

#######################################################################
# Isolated tier NACL — defence in depth for the database subnets
#
# A second, independent control: even if someone widens the database
# security group to 0.0.0.0/0 by mistake, this NACL still only admits
# the private subnet ranges.
#######################################################################

resource "aws_network_acl" "isolated" {
  vpc_id     = aws_vpc.this.id
  subnet_ids = aws_subnet.isolated[*].id

  tags = { Name = "${local.name_prefix}-isolated" }
}

# --- Inbound ---------------------------------------------------------

# Request traffic: PostgreSQL from each private subnet.
resource "aws_network_acl_rule" "isolated_in_db" {
  count = var.az_count

  network_acl_id = aws_network_acl.isolated.id
  rule_number    = 100 + count.index
  egress         = false
  protocol       = "tcp"
  rule_action    = "allow"
  cidr_block     = local.private_subnets[count.index]
  from_port      = local.db_port
  to_port        = local.db_port
}

# Response traffic for connections the database itself opened within the
# VPC — for example to a gateway endpoint. Stateless means this cannot be
# inferred.
resource "aws_network_acl_rule" "isolated_in_ephemeral" {
  network_acl_id = aws_network_acl.isolated.id
  rule_number    = 200
  egress         = false
  protocol       = "tcp"
  rule_action    = "allow"
  cidr_block     = var.vpc_cidr
  from_port      = 1024
  to_port        = 65535
}

# Rule 32767 is an implicit, unremovable DENY ALL at the end of every
# NACL. This explicit rule exists only to make the intent visible in
# the console and in `terraform show`.
resource "aws_network_acl_rule" "isolated_in_deny_all" {
  network_acl_id = aws_network_acl.isolated.id
  rule_number    = 32000
  egress         = false
  protocol       = "-1"
  rule_action    = "deny"
  cidr_block     = "0.0.0.0/0"
}

# --- Outbound --------------------------------------------------------

# The response half of an inbound PostgreSQL connection. Without this,
# queries would arrive and answers would never come back.
resource "aws_network_acl_rule" "isolated_out_ephemeral" {
  count = var.az_count

  network_acl_id = aws_network_acl.isolated.id
  rule_number    = 100 + count.index
  egress         = true
  protocol       = "tcp"
  rule_action    = "allow"
  cidr_block     = local.private_subnets[count.index]
  from_port      = 1024
  to_port        = 65535
}

# Lets the database reach S3 and DynamoDB over the gateway endpoints,
# which is how backups leave an otherwise unroutable subnet.
resource "aws_network_acl_rule" "isolated_out_https_vpc" {
  network_acl_id = aws_network_acl.isolated.id
  rule_number    = 200
  egress         = true
  protocol       = "tcp"
  rule_action    = "allow"
  cidr_block     = var.vpc_cidr
  from_port      = 443
  to_port        = 443
}

resource "aws_network_acl_rule" "isolated_out_deny_all" {
  network_acl_id = aws_network_acl.isolated.id
  rule_number    = 32000
  egress         = true
  protocol       = "-1"
  rule_action    = "deny"
  cidr_block     = "0.0.0.0/0"
}

#######################################################################
# Public tier NACL
#
# Deliberately permissive on the request side — it fronts the internet —
# but it does block one specific thing: inbound SSH and RDP. Nothing in
# the public tier should ever be administered directly, and a NACL deny
# cannot be undone by someone editing a security group.
#######################################################################

resource "aws_network_acl" "public" {
  vpc_id     = aws_vpc.this.id
  subnet_ids = aws_subnet.public[*].id

  tags = { Name = "${local.name_prefix}-public" }
}

# Evaluated first, because first match wins and these are denies.
resource "aws_network_acl_rule" "public_in_deny_ssh" {
  network_acl_id = aws_network_acl.public.id
  rule_number    = 10
  egress         = false
  protocol       = "tcp"
  rule_action    = "deny"
  cidr_block     = "0.0.0.0/0"
  from_port      = 22
  to_port        = 22
}

resource "aws_network_acl_rule" "public_in_deny_rdp" {
  network_acl_id = aws_network_acl.public.id
  rule_number    = 20
  egress         = false
  protocol       = "tcp"
  rule_action    = "deny"
  cidr_block     = "0.0.0.0/0"
  from_port      = 3389
  to_port        = 3389
}

# The public tier fronts the internet; admitting 443 from anywhere is
# the entire purpose of this subnet. WAF, not the NACL, is what filters
# this traffic.
#tfsec:ignore:AVD-AWS-0105
resource "aws_network_acl_rule" "public_in_https" {
  network_acl_id = aws_network_acl.public.id
  rule_number    = 100
  egress         = false
  protocol       = "tcp"
  rule_action    = "allow"
  cidr_block     = "0.0.0.0/0"
  from_port      = 443
  to_port        = 443
}

# Port 80 carries only the redirect to 443 when a certificate is set.
#tfsec:ignore:AVD-AWS-0105
resource "aws_network_acl_rule" "public_in_http" {
  network_acl_id = aws_network_acl.public.id
  rule_number    = 110
  egress         = false
  protocol       = "tcp"
  rule_action    = "allow"
  cidr_block     = "0.0.0.0/0"
  from_port      = 80
  to_port        = 80
}

# Responses to connections the ALB opened outbound. Stateless NACLs
# cannot infer this, and the source of a response is by definition
# whatever host was contacted.
#tfsec:ignore:AVD-AWS-0105
resource "aws_network_acl_rule" "public_in_ephemeral" {
  network_acl_id = aws_network_acl.public.id
  rule_number    = 120
  egress         = false
  protocol       = "tcp"
  rule_action    = "allow"
  cidr_block     = "0.0.0.0/0"
  from_port      = 1024
  to_port        = 65535
}

# Egress from the public tier is unrestricted at the NACL layer; the
# ALB's security group is what actually constrains it to the app tier.
# Narrowing here would break health checks and OCSP stapling.
#tfsec:ignore:AVD-AWS-0102
resource "aws_network_acl_rule" "public_out_all" {
  network_acl_id = aws_network_acl.public.id
  rule_number    = 100
  egress         = true
  protocol       = "-1"
  rule_action    = "allow"
  cidr_block     = "0.0.0.0/0"
}
