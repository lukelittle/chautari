provider "aws" {
  region = var.region

  default_tags {
    tags = merge({
      "chautari:stack" = var.name
      "managed-by"     = "terraform"
    }, var.tags)
  }
}

data "aws_caller_identity" "current" {}
data "aws_partition" "current" {}

locals {
  # ALB and target group names are limited to 32 characters.
  short_name = replace(substr(var.name, 0, 26), "/-+$/", "")

  gateway_config = var.dataplane == "litellm" ? "/gateway/litellm.yaml" : "/gateway/gateway.yaml"
  gateway_command = var.dataplane == "litellm" ? [
    "--config", "/gateway/litellm.yaml", "--port", "3000",
  ] : ["-f", "/gateway/gateway.yaml"]

  estate_cdl = file(var.estate_cdl_path)
}

resource "aws_ecs_cluster" "this" {
  name = var.name

  setting {
    name  = "containerInsights"
    value = "enabled"
  }
}

resource "aws_ecs_cluster_capacity_providers" "this" {
  cluster_name       = aws_ecs_cluster.this.name
  capacity_providers = ["FARGATE"]

  default_capacity_provider_strategy {
    capacity_provider = "FARGATE"
    weight            = 1
  }
}

resource "aws_cloudwatch_log_group" "this" {
  name              = "/ecs/${var.name}"
  retention_in_days = var.log_retention_days
}
