# One task = render-gateway (init) + chautari (control plane, :8080) + the
# data plane sidecar (:3000 LLM/MCP, :3100 A2A, task-local only). They share
# an ephemeral volume at /gateway: chautari writes the live data plane config,
# the gateway reads it and hot-reloads.

locals {
  log_options = {
    "awslogs-group"         = aws_cloudwatch_log_group.this.name
    "awslogs-region"        = var.region
    "awslogs-stream-prefix" = "chautari"
  }

  estate_secret = { name = "CHAUTARI_ESTATE_CDL", valueFrom = aws_ssm_parameter.estate.arn }

  # A digest of the estate in the task definition makes a CDL change roll the
  # service (SSM values are read only when a task starts).
  estate_digest = { name = "CHAUTARI_ESTATE_SHA256", value = sha256(local.estate_cdl) }

  chautari_environment = concat([
    { name = "CHAUTARI_DATAPLANE", value = var.dataplane },
    { name = "CHAUTARI_GATEWAY_URL", value = "http://127.0.0.1:3000" },
    { name = "CHAUTARI_GATEWAY_CONFIG", value = local.gateway_config },
    { name = "OTEL_SERVICE_NAME", value = "chautari" },
    { name = "AWS_REGION", value = var.region },
    local.estate_digest,
    ],
    var.enable_a2a ? [{ name = "CHAUTARI_GATEWAY_A2A_URL", value = "http://127.0.0.1:3100" }] : [],
    var.otel_endpoint == "" ? [] : [{ name = "OTEL_EXPORTER_OTLP_ENDPOINT", value = var.otel_endpoint }],
  )

  containers = [
    {
      # Renders the data plane config from the CDL alone (no database) so the
      # gateway has a config at start.
      name                   = "render-gateway"
      image                  = var.image
      essential              = false
      # Runs as root only to hand the task's shared volume (created root-owned
      # by Fargate) to the control plane's non-root user.
      command                = ["chautari", "render-gateway", "--out", local.gateway_config, "--owner", "65532:65532"]
      user                   = "0"
      readonlyRootFilesystem = true
      environment = [
        { name = "CHAUTARI_DATAPLANE", value = var.dataplane },
        local.estate_digest,
      ]
      secrets     = [local.estate_secret]
      mountPoints = [{ sourceVolume = "gateway", containerPath = "/gateway", readOnly = false }]
      logConfiguration = {
        logDriver = "awslogs"
        options   = local.log_options
      }
    },
    {
      name                   = "chautari"
      image                  = var.image
      essential              = true
      command                = ["chautari", "serve"]
      readonlyRootFilesystem = true
      portMappings           = [{ containerPort = 8080, protocol = "tcp", name = "http" }]
      environment            = local.chautari_environment
      secrets = concat([
        local.estate_secret,
        { name = "CHAUTARI_DATABASE_URL", valueFrom = aws_secretsmanager_secret.database_url.arn },
        { name = "CHAUTARI_GATEWAY_KEY", valueFrom = aws_secretsmanager_secret.gateway_key.arn },
        { name = "CHAUTARI_DIGEST_KEY", valueFrom = aws_secretsmanager_secret.digest_key.arn },
        ], var.per_person_admin_tokens ? [
        { name = "CHAUTARI_ADMIN_TOKENS", valueFrom = aws_secretsmanager_secret.admin_tokens[0].arn },
        ] : [
        { name = "CHAUTARI_ADMIN_TOKEN", valueFrom = aws_secretsmanager_secret.admin_token.arn },
      ])
      mountPoints = [
        { sourceVolume = "gateway", containerPath = "/gateway", readOnly = false },
        { sourceVolume = "tmp", containerPath = "/tmp", readOnly = false },
      ]
      dependsOn = [{ containerName = "render-gateway", condition = "SUCCESS" }]
      healthCheck = {
        command     = ["CMD", "chautari", "healthcheck"]
        interval    = 10
        timeout     = 5
        retries     = 3
        startPeriod = 30
      }
      logConfiguration = {
        logDriver = "awslogs"
        options   = local.log_options
      }
    },
    {
      # The data plane. No port mappings are published to the load balancer
      # and the task security group never opens 3000/3100.
      name                   = "gateway"
      image                  = var.gateway_image
      essential              = true
      command                = local.gateway_command
      readonlyRootFilesystem = var.dataplane != "litellm"
      environment            = [{ name = "AWS_REGION", value = var.region }]
      secrets = concat(
        [{ name = "CHAUTARI_GATEWAY_KEY", valueFrom = aws_secretsmanager_secret.gateway_key.arn }],
        [for k, s in aws_secretsmanager_secret.provider : { name = k, valueFrom = s.arn }],
      )
      mountPoints = [
        { sourceVolume = "gateway", containerPath = "/gateway", readOnly = true },
        { sourceVolume = "gateway-tmp", containerPath = "/tmp", readOnly = false },
      ]
      dependsOn = [{ containerName = "chautari", condition = "HEALTHY" }]
      logConfiguration = {
        logDriver = "awslogs"
        options   = local.log_options
      }
    },
  ]
}

resource "aws_ecs_task_definition" "this" {
  family                   = var.name
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = var.cpu
  memory                   = var.memory
  execution_role_arn       = aws_iam_role.execution.arn
  task_role_arn            = aws_iam_role.task.arn
  container_definitions    = jsonencode(local.containers)

  runtime_platform {
    operating_system_family = "LINUX"
    cpu_architecture        = var.cpu_architecture
  }

  # Fargate ephemeral storage, shared by the containers that mount it.
  volume {
    name = "gateway"
  }

  volume {
    name = "tmp"
  }

  volume {
    name = "gateway-tmp"
  }

  # Make sure the secrets have a value before any task tries to read them.
  depends_on = [
    aws_secretsmanager_secret_version.admin_token,
    aws_secretsmanager_secret_version.gateway_key,
    aws_secretsmanager_secret_version.database_url,
    aws_secretsmanager_secret_version.provider,
  ]
}

resource "aws_ecs_service" "this" {
  name                              = var.name
  cluster                           = aws_ecs_cluster.this.id
  task_definition                   = aws_ecs_task_definition.this.arn
  desired_count                     = var.desired_count
  launch_type                       = "FARGATE"
  platform_version                  = "LATEST"
  health_check_grace_period_seconds = 60
  propagate_tags                    = "SERVICE"
  enable_ecs_managed_tags           = true

  deployment_minimum_healthy_percent = 100
  deployment_maximum_percent         = 200

  deployment_circuit_breaker {
    enable   = true
    rollback = true
  }

  network_configuration {
    subnets          = var.private_subnet_ids
    security_groups  = [aws_security_group.tasks.id]
    assign_public_ip = var.assign_public_ip
  }

  load_balancer {
    target_group_arn = aws_lb_target_group.this.arn
    container_name   = "chautari"
    container_port   = 8080
  }

  depends_on = [
    aws_lb_listener.http,
    aws_lb_listener.https,
    aws_iam_role_policy.execution,
  ]
}
