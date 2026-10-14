# ── Generated credentials ───────────────────────────────────────────────────

resource "random_password" "admin_token" {
  length  = 48
  special = false
}

resource "random_password" "gateway_key" {
  length  = 48
  special = false
}

resource "aws_secretsmanager_secret" "admin_token" {
  name                    = "${var.name}/admin-token"
  description             = "Chautari admin API bearer token (CHAUTARI_ADMIN_TOKEN)."
  recovery_window_in_days = var.secret_recovery_window_days
}

resource "aws_secretsmanager_secret_version" "admin_token" {
  secret_id     = aws_secretsmanager_secret.admin_token.id
  secret_string = random_password.admin_token.result
}

resource "random_password" "digest_key" {
  length  = 48
  special = false
}

resource "aws_secretsmanager_secret" "digest_key" {
  name                    = "${var.name}/digest-key"
  description             = "Key for prompt HMACs in the audit log (CHAUTARI_DIGEST_KEY). Rotating it breaks digest comparisons with older records."
  recovery_window_in_days = var.secret_recovery_window_days
}

resource "aws_secretsmanager_secret_version" "digest_key" {
  secret_id     = aws_secretsmanager_secret.digest_key.id
  secret_string = random_password.digest_key.result
}

# Per-person admin tokens (name=token,name=token). Terraform creates the
# secret with a placeholder and never reads it back: set the real value out
# of band so no administrator's token lands in Terraform state.
resource "aws_secretsmanager_secret" "admin_tokens" {
  count                   = var.per_person_admin_tokens ? 1 : 0
  name                    = "${var.name}/admin-tokens"
  description             = "Per-person admin tokens (CHAUTARI_ADMIN_TOKENS): name=token[,name=token]. Set out of band."
  recovery_window_in_days = var.secret_recovery_window_days
}

resource "aws_secretsmanager_secret_version" "admin_tokens" {
  count         = var.per_person_admin_tokens ? 1 : 0
  secret_id     = aws_secretsmanager_secret.admin_tokens[0].id
  secret_string = "replace-me=replace-me-with-a-long-random-token"
  lifecycle {
    ignore_changes = [secret_string]
  }
}

resource "aws_secretsmanager_secret" "gateway_key" {
  name                    = "${var.name}/gateway-key"
  description             = "Internal key the checkpoint presents to the data plane (CHAUTARI_GATEWAY_KEY)."
  recovery_window_in_days = var.secret_recovery_window_days
}

resource "aws_secretsmanager_secret_version" "gateway_key" {
  secret_id     = aws_secretsmanager_secret.gateway_key.id
  secret_string = random_password.gateway_key.result
}

resource "aws_secretsmanager_secret" "database_url" {
  name                    = "${var.name}/database-url"
  description             = "Postgres connection URL for the control plane (CHAUTARI_DATABASE_URL)."
  recovery_window_in_days = var.secret_recovery_window_days
}

resource "aws_secretsmanager_secret_version" "database_url" {
  secret_id = aws_secretsmanager_secret.database_url.id
  secret_string = format(
    "postgres://%s:%s@%s/%s?sslmode=require",
    aws_db_instance.this.username,
    random_password.db.result,
    aws_db_instance.this.endpoint,
    aws_db_instance.this.db_name,
  )
}

# ── Provider credentials (data plane only) ──────────────────────────────────
# Created with a placeholder so the tasks can start. Put the real value in
# out of band; Terraform will not overwrite it:
#   aws secretsmanager put-secret-value --secret-id <arn> --secret-string <key>

resource "aws_secretsmanager_secret" "provider" {
  for_each = toset(var.provider_key_names)

  name                    = "${var.name}/provider/${each.key}"
  description             = "Provider credential ${each.key}, read only by the data plane."
  recovery_window_in_days = var.secret_recovery_window_days
}

resource "aws_secretsmanager_secret_version" "provider" {
  for_each = aws_secretsmanager_secret.provider

  secret_id     = each.value.id
  secret_string = "REPLACE_ME"

  lifecycle {
    ignore_changes = [secret_string]
  }
}

# ── Estate ──────────────────────────────────────────────────────────────────
# The reviewed CDL, injected into the containers as CHAUTARI_ESTATE_CDL.
# Advanced tier allows up to 8 KB.

resource "aws_ssm_parameter" "estate" {
  name        = "/${var.name}/estate.cdl"
  description = "Chautari estate CDL for ${var.name}."
  type        = "String"
  tier        = "Advanced"
  value       = local.estate_cdl
}
