output "alb_dns_name" {
  description = "DNS name of the load balancer. Point your domain at it."
  value       = aws_lb.this.dns_name
}

output "admin_url" {
  description = "Admin UI and API."
  value       = "${var.certificate_arn == "" ? "http" : "https"}://${aws_lb.this.dns_name}"
}

output "checkpoint_url" {
  description = "OpenAI-compatible checkpoint base URL."
  value       = "${var.certificate_arn == "" ? "http" : "https"}://${aws_lb.this.dns_name}/v1"
}

output "admin_token_secret_arn" {
  description = "Secrets Manager ARN of the admin token."
  value       = aws_secretsmanager_secret.admin_token.arn
}

output "gateway_key_secret_arn" {
  description = "Secrets Manager ARN of the internal gateway key."
  value       = aws_secretsmanager_secret.gateway_key.arn
}

output "database_url_secret_arn" {
  description = "Secrets Manager ARN of the database URL."
  value       = aws_secretsmanager_secret.database_url.arn
}

output "provider_secret_arns" {
  description = "Secrets Manager ARNs of the provider credentials, by variable name. Set their values after apply."
  value       = { for k, s in aws_secretsmanager_secret.provider : k => s.arn }
}

output "estate_parameter_name" {
  description = "SSM parameter holding the estate CDL."
  value       = aws_ssm_parameter.estate.name
}

output "db_endpoint" {
  description = "RDS endpoint (host:port)."
  value       = aws_db_instance.this.endpoint
}

output "ecs_cluster_name" {
  value = aws_ecs_cluster.this.name
}

output "ecs_service_name" {
  value = aws_ecs_service.this.name
}

output "log_group_name" {
  value = aws_cloudwatch_log_group.this.name
}

output "task_role_arn" {
  description = "IAM role the containers run as."
  value       = aws_iam_role.task.arn
}
