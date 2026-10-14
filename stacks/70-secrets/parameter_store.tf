#######################################################################
# Parameter Store SecureString — lab item 7, the comparison
#
#                        Secrets Manager        Parameter Store
#   ------------------  ---------------------  ----------------------
#   price               ~$0.40/secret/month    free (standard tier)
#                       + $0.05/10k API calls  $0.05/10k advanced
#   max size            64 KB                  4 KB std / 8 KB adv
#   rotation            built in, managed       none — you build it
#   cross-region        native replication      manual
#   resource policy     yes                     no
#   versioning          staged labels           integer versions
#   generates values    yes (GetRandomPassword) no
#   KMS                 always encrypted        only if SecureString
#
# Rule of thumb: credentials that must rotate belong in Secrets Manager.
# Configuration that merely needs to be non-public — endpoints, feature
# flags, non-rotating API keys — belongs in Parameter Store, where it is
# free.
#
# ----------------------------------------------------------------------
# THE STATE PROBLEM, which is the real lesson here
#
# `aws_ssm_parameter.value` is a Terraform-managed attribute, so
# whatever you put there is written to state in plaintext. That makes
# Terraform the wrong place to author a secret value.
#
# Contrast with rds_rotation.tf: RDS generates the master password, so
# no plaintext ever enters state. That asymmetry is why the parameters
# below hold placeholders and ignore subsequent changes — the real value
# is written out-of-band, once, with the CLI:
#
#   aws ssm put-parameter --name /aws-security-lab/app/api-key \
#     --value "$REAL" --type SecureString \
#     --key-id alias/aws-security-lab-data --overwrite
# ----------------------------------------------------------------------
#######################################################################

data "aws_kms_key" "data_for_params" {
  key_id = "alias/${var.project}-data"
}

resource "aws_ssm_parameter" "api_key" {
  name        = "/${var.project}/app/api-key"
  description = "Example rotating-by-hand credential. Real value set out of band."

  # SecureString is what engages KMS. A `String` parameter is stored in
  # plaintext, readable by anyone with ssm:GetParameter.
  type   = "SecureString"
  key_id = data.aws_kms_key.data_for_params.arn

  # Placeholder only — see the note above.
  value = "PLACEHOLDER-SET-OUT-OF-BAND"

  tier = "Standard"

  lifecycle {
    # Without this, every plan would try to reset the real value back to
    # the placeholder.
    ignore_changes = [value]
  }

  tags = { Name = "${var.project}-api-key" }
}

#######################################################################
# A non-secret, for contrast
#
# Plain String: no KMS, free, and appropriate. Encrypting a database
# hostname achieves nothing except making it harder to read.
#######################################################################

resource "aws_ssm_parameter" "db_endpoint" {
  name        = "/${var.project}/app/db-endpoint"
  description = "Database hostname. Not a secret, so not a SecureString."
  type        = "String"

  value = var.enable_rds ? aws_db_instance.this[0].address : "not-provisioned"

  tags = { Name = "${var.project}-db-endpoint" }
}

#######################################################################
# Pointer to the RDS-managed secret
#
# Applications read this to find the secret, then call
# secretsmanager:GetSecretValue. Storing the ARN rather than the
# credential means the rotation in rds_rotation.tf is invisible to the
# application — it always fetches the current value.
#######################################################################

resource "aws_ssm_parameter" "db_secret_arn" {
  count = var.enable_rds ? 1 : 0

  name        = "/${var.project}/app/db-secret-arn"
  description = "ARN of the RDS-managed master user secret"
  type        = "String"
  value       = aws_db_instance.this[0].master_user_secret[0].secret_arn

  tags = { Name = "${var.project}-db-secret-arn" }
}

#######################################################################
# Reader role
#
# Scoped to this parameter path and this key. The kms:ViaService
# condition means the role can decrypt parameters but cannot use the key
# directly for anything else.
#######################################################################

data "aws_iam_policy_document" "param_reader_assume" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["ec2.amazonaws.com", "lambda.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "param_reader" {
  name               = "${var.project}-param-reader"
  description        = "Reads lab parameters and the RDS master secret"
  assume_role_policy = data.aws_iam_policy_document.param_reader_assume.json
}

data "aws_iam_policy_document" "param_reader" {
  statement {
    sid    = "ReadLabParameters"
    effect = "Allow"

    actions = [
      "ssm:GetParameter",
      "ssm:GetParameters",
      "ssm:GetParametersByPath",
    ]

    resources = [
      "arn:${local.partition}:ssm:${var.region}:${local.account_id}:parameter/${var.project}/*",
    ]
  }

  statement {
    sid       = "DecryptSecureStrings"
    effect    = "Allow"
    actions   = ["kms:Decrypt"]
    resources = [data.aws_kms_key.data_for_params.arn]

    condition {
      test     = "StringEquals"
      variable = "kms:ViaService"
      values   = ["ssm.${var.region}.amazonaws.com"]
    }
  }

  dynamic "statement" {
    for_each = var.enable_rds ? [1] : []

    content {
      sid       = "ReadDatabaseSecret"
      effect    = "Allow"
      actions   = ["secretsmanager:GetSecretValue"]
      resources = [aws_db_instance.this[0].master_user_secret[0].secret_arn]
    }
  }
}

resource "aws_iam_role_policy" "param_reader" {
  name   = "read-parameters-and-secrets"
  role   = aws_iam_role.param_reader.id
  policy = data.aws_iam_policy_document.param_reader.json
}
