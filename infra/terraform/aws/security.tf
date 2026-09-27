resource "aws_kms_key" "platform" {
  description             = "samiir-fatma data encryption (RDS, Redis, S3, secrets, backups)"
  enable_key_rotation     = true
  deletion_window_in_days = 30
}

resource "aws_kms_alias" "platform" {
  name          = "alias/samiir-fatma-${var.environment}"
  target_key_id = aws_kms_key.platform.key_id
}

# Secrets are created empty; values are written by the key-management pipeline, never by TF.
locals {
  app_secrets = ["field-encryption-keyring", "blind-index-key", "slot-token-key", "csrf-key",
    "quarantine-key", "pseudonym-key", "meta-app-secret", "meta-verify-token",
  "samiir-openai-api-key", "fatma-openai-api-key", "oidc-client-secret"]
}

resource "aws_secretsmanager_secret" "app" {
  for_each   = toset(local.app_secrets)
  name       = "platform/secrets/${each.key}"
  kms_key_id = aws_kms_key.platform.arn
}

resource "aws_security_group" "db" {
  name   = "samiir-fatma-db"
  vpc_id = aws_vpc.main.id
  ingress {
    description = "PostgreSQL from application subnets only"
    from_port   = 5432
    to_port     = 5432
    protocol    = "tcp"
    cidr_blocks = aws_subnet.app[*].cidr_block
  }
}

resource "aws_security_group" "redis" {
  name   = "samiir-fatma-redis"
  vpc_id = aws_vpc.main.id
  ingress {
    from_port   = 6379
    to_port     = 6379
    protocol    = "tcp"
    cidr_blocks = aws_subnet.app[*].cidr_block
  }
}
