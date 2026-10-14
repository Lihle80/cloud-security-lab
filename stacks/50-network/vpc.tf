#######################################################################
# 50-network — VPC and three subnet tiers
#
#   public    ALB only. Routes to an internet gateway.
#   private   application workloads. Egress via NAT, no inbound path.
#   isolated  databases. No route off the VPC at all, not even NAT.
#
# The isolated tier is the point of the exercise: a subnet with no
# default route cannot be reached from the internet and cannot reach it,
# regardless of how wrong a security group gets later.
#######################################################################

data "aws_availability_zones" "available" {
  state = "available"

  filter {
    name   = "opt-in-status"
    values = ["opt-in-not-required"]
  }
}

data "aws_caller_identity" "current" {}
data "aws_partition" "current" {}
data "aws_region" "current" {}

locals {
  account_id = data.aws_caller_identity.current.account_id
  partition  = data.aws_partition.current.partition

  azs = slice(data.aws_availability_zones.available.names, 0, var.az_count)

  # /24 per subnet out of a /16. Offsets leave room to grow each tier.
  public_subnets   = [for i in range(var.az_count) : cidrsubnet(var.vpc_cidr, 8, i)]
  private_subnets  = [for i in range(var.az_count) : cidrsubnet(var.vpc_cidr, 8, i + 10)]
  isolated_subnets = [for i in range(var.az_count) : cidrsubnet(var.vpc_cidr, 8, i + 20)]

  nat_gateway_count = var.enable_nat_gateway ? (var.single_nat_gateway ? 1 : var.az_count) : 0

  name_prefix = var.project
}

resource "aws_vpc" "this" {
  cidr_block = var.vpc_cidr

  enable_dns_support   = true
  enable_dns_hostnames = true

  tags = { Name = "${local.name_prefix}-vpc" }
}

# The default SG allows all traffic between anything attached to it.
# Emptying its rules means accidentally landing in it grants nothing.
resource "aws_default_security_group" "this" {
  vpc_id = aws_vpc.this.id

  # No ingress or egress blocks: both rule sets are removed.

  tags = { Name = "${local.name_prefix}-default-DO-NOT-USE" }
}

#######################################################################
# Internet gateway and public tier
#######################################################################

resource "aws_internet_gateway" "this" {
  vpc_id = aws_vpc.this.id

  tags = { Name = "${local.name_prefix}-igw" }
}

resource "aws_subnet" "public" {
  count = var.az_count

  vpc_id            = aws_vpc.this.id
  cidr_block        = local.public_subnets[count.index]
  availability_zone = local.azs[count.index]

  # Explicitly off. The ALB gets its own public IPs; nothing else should
  # land here, and auto-assignment is how instances leak onto the
  # internet by accident.
  map_public_ip_on_launch = false

  tags = {
    Name = "${local.name_prefix}-public-${local.azs[count.index]}"
    Tier = "public"
  }
}

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.this.id

  tags = { Name = "${local.name_prefix}-public" }
}

resource "aws_route" "public_internet" {
  route_table_id         = aws_route_table.public.id
  destination_cidr_block = "0.0.0.0/0"
  gateway_id             = aws_internet_gateway.this.id
}

resource "aws_route_table_association" "public" {
  count = var.az_count

  subnet_id      = aws_subnet.public[count.index].id
  route_table_id = aws_route_table.public.id
}

#######################################################################
# NAT and private tier
#######################################################################

resource "aws_eip" "nat" {
  count = local.nat_gateway_count

  domain = "vpc"

  tags = { Name = "${local.name_prefix}-nat-${count.index}" }
}

resource "aws_nat_gateway" "this" {
  count = local.nat_gateway_count

  allocation_id = aws_eip.nat[count.index].id
  subnet_id     = aws_subnet.public[count.index].id

  tags = { Name = "${local.name_prefix}-nat-${count.index}" }

  depends_on = [aws_internet_gateway.this]
}

resource "aws_subnet" "private" {
  count = var.az_count

  vpc_id            = aws_vpc.this.id
  cidr_block        = local.private_subnets[count.index]
  availability_zone = local.azs[count.index]

  tags = {
    Name = "${local.name_prefix}-private-${local.azs[count.index]}"
    Tier = "private"
  }
}

# One table per AZ so that with per-AZ NAT, traffic stays in its own AZ
# and avoids cross-AZ data charges.
resource "aws_route_table" "private" {
  count = var.az_count

  vpc_id = aws_vpc.this.id

  tags = { Name = "${local.name_prefix}-private-${local.azs[count.index]}" }
}

resource "aws_route" "private_nat" {
  count = var.enable_nat_gateway ? var.az_count : 0

  route_table_id         = aws_route_table.private[count.index].id
  destination_cidr_block = "0.0.0.0/0"

  # With a single shared NAT every table points at index 0.
  nat_gateway_id = aws_nat_gateway.this[var.single_nat_gateway ? 0 : count.index].id
}

resource "aws_route_table_association" "private" {
  count = var.az_count

  subnet_id      = aws_subnet.private[count.index].id
  route_table_id = aws_route_table.private[count.index].id
}

#######################################################################
# Isolated tier
#
# A route table with no 0.0.0.0/0 entry whatsoever. Only the implicit
# local route exists, so these subnets can talk within the VPC and
# nowhere else. Gateway endpoints still work, which is how a database
# subnet can reach S3 for backups without any egress path.
#######################################################################

resource "aws_subnet" "isolated" {
  count = var.az_count

  vpc_id            = aws_vpc.this.id
  cidr_block        = local.isolated_subnets[count.index]
  availability_zone = local.azs[count.index]

  tags = {
    Name = "${local.name_prefix}-isolated-${local.azs[count.index]}"
    Tier = "isolated"
  }
}

resource "aws_route_table" "isolated" {
  vpc_id = aws_vpc.this.id

  tags = { Name = "${local.name_prefix}-isolated" }
}

resource "aws_route_table_association" "isolated" {
  count = var.az_count

  subnet_id      = aws_subnet.isolated[count.index].id
  route_table_id = aws_route_table.isolated.id
}
