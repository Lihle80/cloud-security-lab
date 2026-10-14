#######################################################################
# Secrets Manager rotation for an RDS password — lab item 7
#
# Uses RDS-managed master passwords (`manage_master_user_password`),
# which is the modern path:
#
#   - RDS generates the password; it is never in Terraform state, never
#     in a variable, never in a tfvars file, never in your shell history
#   - RDS owns the rotation Lambda, so there is no function to write,
#     deploy, patch or hold IAM for
#   - rotation is a single-step swap coordinated with the engine, so
#     there is no window where the stored secret and the real password
#     disagree
#
# The alternative — a customer-managed secret plus the AWS rotation
# function from SAR — is worth knowing but is strictly more machinery
# for the RDS case. docs/SECRETS.md covers when you actually need it
# (non-RDS targets, multi-user rotation, custom credential formats).
#######################################################################

data "aws_caller_identity" "current" {}
data "aws_partition" "current" {}

locals {
  account_id = data.aws_caller_identity.current.account_id
  partition  = data.aws_partition.current.partition
}

#######################################################################
# Network discovery
#
# Finds the isolated subnets and database security group from stack
# 50-network by tag, rather than coupling the two states together.
#######################################################################

data "aws_vpc" "lab" {
  count = var.enable_rds ? 1 : 0

  filter {
    name   = "tag:Name"
    values = [var.vpc_name_tag]
  }
}

data "aws_subnets" "isolated" {
  count = var.enable_rds ? 1 : 0

  filter {
    name   = "vpc-id"
    values = [data.aws_vpc.lab[0].id]
  }

  filter {
    name   = "tag:Tier"
    values = ["isolated"]
  }
}

data "aws_security_groups" "db" {
  count = var.enable_rds ? 1 : 0

  filter {
    name   = "vpc-id"
    values = [data.aws_vpc.lab[0].id]
  }

  filter {
    name   = "tag:Name"
    values = ["${var.project}-db"]
  }
}

data "aws_kms_key" "data" {
  count = var.enable_rds ? 1 : 0

  key_id = "alias/${var.project}-data"
}

#######################################################################
# Database
#######################################################################

resource "aws_db_subnet_group" "this" {
  count = var.enable_rds ? 1 : 0

  name        = "${var.project}-db"
  description = "Isolated subnets with no route to the internet"
  subnet_ids  = data.aws_subnets.isolated[0].ids

  tags = { Name = "${var.project}-db" }
}

resource "aws_db_parameter_group" "this" {
  count = var.enable_rds ? 1 : 0

  name        = "${var.project}-pg16"
  family      = "postgres16"
  description = "Forces TLS and logs connections"

  # Rejects any client that will not use TLS. The equivalent of the
  # bucket policy's DenyInsecureTransport, at the database layer.
  parameter {
    name  = "rds.force_ssl"
    value = "1"
  }

  parameter {
    name  = "log_connections"
    value = "1"
  }

  parameter {
    name  = "log_disconnections"
    value = "1"
  }

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_db_instance" "this" {
  count = var.enable_rds ? 1 : 0

  identifier     = "${var.project}-db"
  engine         = "postgres"
  engine_version = var.db_engine_version
  instance_class = var.db_instance_class

  allocated_storage = var.db_allocated_storage
  storage_type      = "gp3"
  storage_encrypted = true
  kms_key_id        = data.aws_kms_key.data[0].arn

  db_name  = "labdb"
  username = "labadmin"

  #####################################################################
  # The rotation mechanism.
  #
  # `manage_master_user_password` makes RDS create a Secrets Manager
  # secret, own the password, and rotate it on the schedule below.
  # Note the absence of a `password` argument — there is no plaintext
  # credential anywhere in this configuration or in state.
  #####################################################################
  manage_master_user_password   = true
  master_user_secret_kms_key_id = data.aws_kms_key.data[0].arn

  db_subnet_group_name   = aws_db_subnet_group.this[0].name
  vpc_security_group_ids = data.aws_security_groups.db[0].ids
  parameter_group_name   = aws_db_parameter_group.this[0].name

  publicly_accessible = false

  # Lets applications authenticate with short-lived IAM tokens instead
  # of the password at all, which is strictly better where supported.
  iam_database_authentication_enabled = true

  backup_retention_period = 7
  backup_window           = "04:00-05:00"
  maintenance_window      = "sun:05:30-sun:06:30"
  copy_tags_to_snapshot   = true

  auto_minor_version_upgrade = true

  # Surfaces slow queries and errors where CloudWatch alarms can see them.
  enabled_cloudwatch_logs_exports = ["postgresql", "upgrade"]

  # Lab settings. Both should be inverted for anything real.
  deletion_protection = false
  skip_final_snapshot = true

  tags = {
    Name = "${var.project}-db"
    # Picked up by the AWS Backup selection in stack 60-data.
    Backup = "true"
  }
}

#######################################################################
# Rotation schedule
#
# The secret itself is created and owned by RDS; this only sets how
# often it rotates. `rotate_immediately = false` avoids a rotation
# during the apply, which would otherwise race the instance becoming
# available.
#######################################################################

resource "aws_secretsmanager_secret_rotation" "db_master" {
  count = var.enable_rds ? 1 : 0

  secret_id          = aws_db_instance.this[0].master_user_secret[0].secret_arn
  rotate_immediately = false

  rotation_rules {
    automatically_after_days = var.rotation_days
  }
}
