output "vpc_id" {
  description = "VPC ID."
  value       = aws_vpc.this.id
}

output "vpc_cidr" {
  description = "VPC CIDR block."
  value       = aws_vpc.this.cidr_block
}

output "public_subnet_ids" {
  description = "Public subnets, hosting the ALB only."
  value       = aws_subnet.public[*].id
}

output "private_subnet_ids" {
  description = "Private subnets for application workloads."
  value       = aws_subnet.private[*].id
}

output "isolated_subnet_ids" {
  description = "Isolated subnets with no route off the VPC. Use these for databases."
  value       = aws_subnet.isolated[*].id
}

output "security_group_ids" {
  description = "Tiered security groups, for the data and secrets stacks to consume."
  value = {
    alb       = aws_security_group.alb.id
    app       = aws_security_group.app.id
    db        = aws_security_group.db.id
    endpoints = try(aws_security_group.endpoints[0].id, null)
  }
}

output "nat_gateway_ids" {
  description = "NAT gateways created, if any."
  value       = aws_nat_gateway.this[*].id
}

output "gateway_endpoint_ids" {
  description = "Free gateway endpoints."
  value = {
    s3       = aws_vpc_endpoint.s3.id
    dynamodb = aws_vpc_endpoint.dynamodb.id
  }
}

output "interface_endpoint_ids" {
  description = "Interface endpoints, empty unless enabled."
  value       = { for k, v in aws_vpc_endpoint.interface : k => v.id }
}

output "flow_log_destination" {
  description = "Where flow logs are being written."
  value = local.flow_logs_to_s3 ? "s3://${aws_s3_bucket.flow_logs[0].id}" : (
    local.flow_logs_to_cloudwatch ? aws_cloudwatch_log_group.flow_logs[0].name : "disabled"
  )
}

output "alb_dns_name" {
  description = "ALB hostname. Curl this to exercise the WAF."
  value       = try(aws_lb.this[0].dns_name, null)
}

output "alb_arn" {
  description = "ALB ARN."
  value       = try(aws_lb.this[0].arn, null)
}

output "web_acl_arn" {
  description = "WAF web ACL associated with the ALB."
  value       = try(aws_wafv2_web_acl.this[0].arn, null)
}
