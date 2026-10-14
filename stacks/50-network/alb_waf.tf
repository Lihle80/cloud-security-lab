#######################################################################
# ALB behind WAF — lab item 5
#
# The ALB deliberately has no target group or backend instances. A
# fixed-response listener rule is enough to prove the WAF is inspecting
# and blocking, and it keeps the lab free of EC2 charges. Add a target
# group when you have something to put behind it.
#######################################################################

data "aws_elb_service_account" "current" {}

locals {
  create_alb   = var.enable_alb
  has_cert     = var.certificate_arn != ""
  alb_log_name = "${var.project}-alb-logs-${local.account_id}"
}

#######################################################################
# Access log bucket
#######################################################################

# No versioning and no CMK, both deliberate: ALB access logging does
# not support a customer-managed key at all, and these objects are
# write-once with a 30-day lifecycle, so versioning would only duplicate
# storage. Access logging on a log bucket is also declined — it would
# recurse.
#tfsec:ignore:AVD-AWS-0088
#tfsec:ignore:AVD-AWS-0089
#tfsec:ignore:AVD-AWS-0090
#tfsec:ignore:AVD-AWS-0132
resource "aws_s3_bucket" "alb_logs" {
  count = local.create_alb ? 1 : 0

  bucket        = local.alb_log_name
  force_destroy = true

  tags = { Name = "${local.name_prefix}-alb-logs" }
}

resource "aws_s3_bucket_public_access_block" "alb_logs" {
  count = local.create_alb ? 1 : 0

  bucket                  = aws_s3_bucket.alb_logs[0].id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

#tfsec:ignore:AVD-AWS-0132
resource "aws_s3_bucket_server_side_encryption_configuration" "alb_logs" {
  count = local.create_alb ? 1 : 0

  bucket = aws_s3_bucket.alb_logs[0].id

  rule {
    apply_server_side_encryption_by_default {
      # Must be AES256. ALB access logging does not support a
      # customer-managed KMS key, and delivery fails silently if you set
      # one — the bucket just stays empty.
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "alb_logs" {
  count = local.create_alb ? 1 : 0

  bucket = aws_s3_bucket.alb_logs[0].id

  rule {
    id     = "expire-alb-logs"
    status = "Enabled"

    filter {}

    expiration {
      days = 30
    }

    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
  }
}

data "aws_iam_policy_document" "alb_logs" {
  count = local.create_alb ? 1 : 0

  # In us-west-2 and other long-standing regions, ALB delivers access
  # logs as a regional ELB-owned account rather than a service principal.
  statement {
    sid       = "AllowELBAccountWrite"
    effect    = "Allow"
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.alb_logs[0].arn}/*"]

    principals {
      type        = "AWS"
      identifiers = [data.aws_elb_service_account.current.arn]
    }
  }

  # Regions launched after August 2022 use this principal instead.
  # Harmless to include in older regions.
  statement {
    sid       = "AllowLogDeliveryWrite"
    effect    = "Allow"
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.alb_logs[0].arn}/*"]

    principals {
      type        = "Service"
      identifiers = ["logdelivery.elasticloadbalancing.amazonaws.com"]
    }

    condition {
      test     = "StringEquals"
      variable = "s3:x-amz-acl"
      values   = ["bucket-owner-full-control"]
    }
  }

  statement {
    sid     = "DenyInsecureTransport"
    effect  = "Deny"
    actions = ["s3:*"]

    resources = [
      aws_s3_bucket.alb_logs[0].arn,
      "${aws_s3_bucket.alb_logs[0].arn}/*",
    ]

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

resource "aws_s3_bucket_policy" "alb_logs" {
  count = local.create_alb ? 1 : 0

  bucket = aws_s3_bucket.alb_logs[0].id
  policy = data.aws_iam_policy_document.alb_logs[0].json

  depends_on = [aws_s3_bucket_public_access_block.alb_logs]
}

#######################################################################
# Load balancer
#######################################################################

# Internet-facing is the point: this demonstrates a public ALB behind
# WAF. Narrow `alb_allowed_cidrs` to your own address to keep it private
# while still exercising the same path.
#tfsec:ignore:AVD-AWS-0053
resource "aws_lb" "this" {
  count = local.create_alb ? 1 : 0

  name               = "${var.project}-alb"
  load_balancer_type = "application"
  internal           = false

  subnets         = aws_subnet.public[*].id
  security_groups = [aws_security_group.alb.id]

  # Rejects requests with malformed headers rather than passing them to
  # the backend, which closes a class of request-smuggling tricks.
  drop_invalid_header_fields = true

  # Stops the ALB silently forwarding a desynchronised request.
  desync_mitigation_mode = "strictest"

  enable_http2 = true

  # Lab setting. Turn on for anything real.
  enable_deletion_protection = false

  access_logs {
    bucket  = aws_s3_bucket.alb_logs[0].id
    prefix  = "alb"
    enabled = true
  }

  tags = { Name = "${local.name_prefix}-alb" }

  depends_on = [aws_s3_bucket_policy.alb_logs]
}

#######################################################################
# Listeners
#
# With a certificate: 80 redirects to 443, and 443 serves the response
# under TLS 1.2 or better.
#
# Without one: a single HTTP listener on 80. That is a lab compromise
# because issuing an ACM certificate requires a domain you control, and
# it is flagged by both checkov and tfsec on purpose — the finding is
# accurate.
#######################################################################

resource "aws_lb_listener" "https" {
  count = local.create_alb && local.has_cert ? 1 : 0

  load_balancer_arn = aws_lb.this[0].arn
  port              = 443
  protocol          = "HTTPS"

  # Forward secrecy, TLS 1.2 floor, no RSA key exchange.
  ssl_policy      = "ELBSecurityPolicy-TLS13-1-2-2021-06"
  certificate_arn = var.certificate_arn

  default_action {
    type = "fixed-response"

    fixed_response {
      content_type = "text/plain"
      message_body = "aws-security-lab: request reached the ALB through WAF"
      status_code  = "200"
    }
  }
}

resource "aws_lb_listener" "http_redirect" {
  count = local.create_alb && local.has_cert ? 1 : 0

  load_balancer_arn = aws_lb.this[0].arn
  port              = 80
  protocol          = "HTTP"

  default_action {
    type = "redirect"

    redirect {
      port        = "443"
      protocol    = "HTTPS"
      status_code = "HTTP_301"
    }
  }
}

# This finding is CORRECT and accepted only because the lab has no
# domain to issue a certificate for. Set `certificate_arn` and this
# resource disappears, replaced by the HTTPS listener and a 301 above.
# checkov:skip=CKV_AWS_2:No ACM certificate available in the lab; see comment above.
# checkov:skip=CKV_AWS_103:TLS policy cannot be set on an HTTP listener.
#tfsec:ignore:AVD-AWS-0054
resource "aws_lb_listener" "http_only" {
  count = local.create_alb && !local.has_cert ? 1 : 0

  load_balancer_arn = aws_lb.this[0].arn
  port              = 80
  protocol          = "HTTP"

  default_action {
    type = "fixed-response"

    fixed_response {
      content_type = "text/plain"
      message_body = "aws-security-lab: request reached the ALB through WAF"
      status_code  = "200"
    }
  }
}

#######################################################################
# WAF web ACL — lab item 5
#
# Rule evaluation is by priority, lowest first. The IP reputation list
# and rate limit come before the signature-based groups so that obvious
# junk is dropped before paying to inspect it.
#
# `override_action = none` means the managed group's own actions apply.
# Switch a group to `count` while tuning, to measure what it WOULD block
# before it starts blocking real traffic.
#######################################################################

resource "aws_wafv2_web_acl" "this" {
  count = local.create_alb ? 1 : 0

  name        = "${var.project}-web-acl"
  description = "Managed rule groups plus a rate limit, fronting the lab ALB"
  scope       = "REGIONAL"

  default_action {
    allow {}
  }

  # --- Priority 1: known-bad source addresses ------------------------
  rule {
    name     = "AWSManagedRulesAmazonIpReputationList"
    priority = 1

    override_action {
      none {}
    }

    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesAmazonIpReputationList"
        vendor_name = "AWS"
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "ip-reputation"
      sampled_requests_enabled   = true
    }
  }

  # --- Priority 2: volumetric abuse ----------------------------------
  rule {
    name     = "RateLimitPerIP"
    priority = 2

    action {
      block {}
    }

    statement {
      rate_based_statement {
        limit              = var.waf_rate_limit
        aggregate_key_type = "IP"
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "rate-limit"
      sampled_requests_enabled   = true
    }
  }

  # --- Priority 3: OWASP-style common attacks ------------------------
  rule {
    name     = "AWSManagedRulesCommonRuleSet"
    priority = 3

    override_action {
      none {}
    }

    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesCommonRuleSet"
        vendor_name = "AWS"

        # This rule blocks bodies over 8KB, which breaks file uploads
        # and large JSON payloads. Counted rather than blocked so it
        # still shows in metrics without breaking a real application.
        rule_action_override {
          name = "SizeRestrictions_BODY"

          action_to_use {
            count {}
          }
        }
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "common-rule-set"
      sampled_requests_enabled   = true
    }
  }

  # --- Priority 4: inputs with no legitimate use ---------------------
  rule {
    name     = "AWSManagedRulesKnownBadInputsRuleSet"
    priority = 4

    override_action {
      none {}
    }

    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesKnownBadInputsRuleSet"
        vendor_name = "AWS"
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "known-bad-inputs"
      sampled_requests_enabled   = true
    }
  }

  # --- Priority 5: SQL injection -------------------------------------
  rule {
    name     = "AWSManagedRulesSQLiRuleSet"
    priority = 5

    override_action {
      none {}
    }

    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesSQLiRuleSet"
        vendor_name = "AWS"
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "sqli"
      sampled_requests_enabled   = true
    }
  }

  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = "${var.project}-web-acl"
    sampled_requests_enabled   = true
  }

  tags = { Name = "${local.name_prefix}-web-acl" }
}

resource "aws_wafv2_web_acl_association" "alb" {
  count = local.create_alb ? 1 : 0

  resource_arn = aws_lb.this[0].arn
  web_acl_arn  = aws_wafv2_web_acl.this[0].arn
}

#######################################################################
# WAF logging
#
# The log group name MUST begin with "aws-waf-logs-"; WAF rejects any
# other destination name.
#######################################################################

# WAF logs contain request metadata, with Authorization and Cookie
# headers redacted below. Left on the default CloudWatch key rather than
# a CMK, because the alerts CMK lives in stack 30-detection and
# cross-stack key references would couple the two states together.
#tfsec:ignore:AVD-AWS-0017
resource "aws_cloudwatch_log_group" "waf" {
  count = local.create_alb ? 1 : 0

  name              = "aws-waf-logs-${var.project}"
  retention_in_days = 14
}

resource "aws_wafv2_web_acl_logging_configuration" "this" {
  count = local.create_alb ? 1 : 0

  resource_arn            = aws_wafv2_web_acl.this[0].arn
  log_destination_configs = [aws_cloudwatch_log_group.waf[0].arn]

  # Authorization headers and cookies would otherwise be written to logs
  # in cleartext.
  redacted_fields {
    single_header {
      name = "authorization"
    }
  }

  redacted_fields {
    single_header {
      name = "cookie"
    }
  }
}
