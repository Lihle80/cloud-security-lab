#######################################################################
# EventBridge -> SNS alerting — lab item 3
#
# Two rules land on one encrypted topic:
#   GuardDuty findings at or above `minimum_alert_severity`
#   Security Hub findings labelled CRITICAL or HIGH, still ACTIVE and NEW
#
# Both use an input transformer so the email is readable rather than a
# wall of raw finding JSON.
#######################################################################

#######################################################################
# KMS key for the topic
#
# An SNS topic encrypted with the AWS-managed key cannot be published to
# by EventBridge, because the managed key's policy cannot be edited to
# trust the service. A customer-managed key is required here, not just
# nice to have.
#######################################################################

resource "aws_kms_key" "alerts" {
  description             = "Encrypts security finding notifications for ${var.project}"
  enable_key_rotation     = true
  deletion_window_in_days = 7
  policy                  = data.aws_iam_policy_document.alerts_key.json
}

resource "aws_kms_alias" "alerts" {
  name          = "alias/${var.project}-alerts"
  target_key_id = aws_kms_key.alerts.key_id
}

data "aws_iam_policy_document" "alerts_key" {
  statement {
    sid       = "EnableIAMPolicies"
    effect    = "Allow"
    actions   = ["kms:*"]
    resources = ["*"]

    principals {
      type        = "AWS"
      identifiers = ["arn:${local.partition}:iam::${local.account_id}:root"]
    }
  }

  statement {
    sid       = "AllowEventBridgeAndSNS"
    effect    = "Allow"
    resources = ["*"]

    actions = [
      "kms:Decrypt",
      "kms:GenerateDataKey*",
    ]

    principals {
      type = "Service"
      identifiers = [
        "events.amazonaws.com",
        "sns.amazonaws.com",
        "cloudwatch.amazonaws.com",
      ]
    }
  }
}

#######################################################################
# Topic
#######################################################################

resource "aws_sns_topic" "alerts" {
  name              = "${var.project}-security-alerts"
  kms_master_key_id = aws_kms_key.alerts.id
}

data "aws_iam_policy_document" "alerts_topic" {
  statement {
    sid       = "AllowEventBridgePublish"
    effect    = "Allow"
    actions   = ["sns:Publish"]
    resources = [aws_sns_topic.alerts.arn]

    principals {
      type        = "Service"
      identifiers = ["events.amazonaws.com"]
    }

    # Confused-deputy guard: only rules in this account may publish.
    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [local.account_id]
    }
  }

  statement {
    sid       = "DenyInsecureTransport"
    effect    = "Deny"
    actions   = ["sns:Publish"]
    resources = [aws_sns_topic.alerts.arn]

    principals {
      type        = "AWS"
      identifiers = ["*"]
    }

    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }
}

resource "aws_sns_topic_policy" "alerts" {
  arn    = aws_sns_topic.alerts.arn
  policy = data.aws_iam_policy_document.alerts_topic.json
}

# Terraform cannot confirm an email subscription for you; AWS mails a
# confirmation link. The resource stays "pending confirmation" until the
# link is clicked, which is expected rather than a failure.
resource "aws_sns_topic_subscription" "alerts_email" {
  count = var.alert_email != "" ? 1 : 0

  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

#######################################################################
# GuardDuty findings
#######################################################################

resource "aws_cloudwatch_event_rule" "guardduty_findings" {
  name        = "${var.project}-guardduty-findings"
  description = "GuardDuty findings at severity >= ${var.minimum_alert_severity}"

  event_pattern = jsonencode({
    source      = ["aws.guardduty"]
    detail-type = ["GuardDuty Finding"]
    detail = {
      severity = [{ numeric = [">=", var.minimum_alert_severity] }]
    }
  })
}

resource "aws_cloudwatch_event_target" "guardduty_to_sns" {
  rule      = aws_cloudwatch_event_rule.guardduty_findings.name
  target_id = "sns"
  arn       = aws_sns_topic.alerts.arn

  input_transformer {
    input_paths = {
      account     = "$.detail.accountId"
      region      = "$.detail.region"
      severity    = "$.detail.severity"
      type        = "$.detail.type"
      title       = "$.detail.title"
      description = "$.detail.description"
      findingId   = "$.detail.id"
      time        = "$.time"
    }

    input_template = <<-EOT
      "GuardDuty finding in account <account> (<region>)"
      ""
      "Severity:    <severity>"
      "Type:        <type>"
      "Title:       <title>"
      "Time:        <time>"
      ""
      "Description: <description>"
      ""
      "Console: https://console.aws.amazon.com/guardduty/home?region=<region>#/findings?macros=current&fId=<findingId>"
    EOT
  }
}

#######################################################################
# Security Hub findings
#######################################################################

resource "aws_cloudwatch_event_rule" "securityhub_findings" {
  count = var.enable_security_hub ? 1 : 0

  name        = "${var.project}-securityhub-critical-high"
  description = "Security Hub CRITICAL and HIGH findings, active and unhandled"

  event_pattern = jsonencode({
    source      = ["aws.securityhub"]
    detail-type = ["Security Hub Findings - Imported"]
    detail = {
      findings = {
        Severity    = { Label = ["CRITICAL", "HIGH"] }
        RecordState = ["ACTIVE"]
        Workflow    = { Status = ["NEW"] }
      }
    }
  })
}

resource "aws_cloudwatch_event_target" "securityhub_to_sns" {
  count = var.enable_security_hub ? 1 : 0

  rule      = aws_cloudwatch_event_rule.securityhub_findings[0].name
  target_id = "sns"
  arn       = aws_sns_topic.alerts.arn

  input_transformer {
    input_paths = {
      account  = "$.detail.findings[0].AwsAccountId"
      region   = "$.detail.findings[0].Region"
      severity = "$.detail.findings[0].Severity.Label"
      title    = "$.detail.findings[0].Title"
      desc     = "$.detail.findings[0].Description"
      resource = "$.detail.findings[0].Resources[0].Id"
      time     = "$.time"
    }

    input_template = <<-EOT
      "Security Hub <severity> finding in account <account> (<region>)"
      ""
      "Title:    <title>"
      "Resource: <resource>"
      "Time:     <time>"
      ""
      "<desc>"
      ""
      "Console: https://console.aws.amazon.com/securityhub/home?region=<region>#/findings"
    EOT
  }
}
