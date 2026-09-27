resource "aws_db_subnet_group" "main" {
  name       = "samiir-fatma"
  subnet_ids = aws_subnet.data[*].id
}

resource "aws_db_parameter_group" "pg" {
  name   = "samiir-fatma-pg17"
  family = "postgres17"
  parameter {
    name  = "rds.force_ssl"
    value = "1"
  }
  parameter {
    name  = "log_min_duration_statement"
    value = "1000"
  }
  parameter {
    name         = "shared_preload_libraries"
    value        = "pg_stat_statements"
    apply_method = "pending-reboot"
  }
}

# Managed PostgreSQL 17 with pgvector (CREATE EXTENSION vector in migration 0001).
resource "aws_db_instance" "main" {
  identifier                          = "samiir-fatma-${var.environment}"
  engine                              = "postgres"
  engine_version                      = "17"
  instance_class                      = var.db_instance_class
  allocated_storage                   = 100
  max_allocated_storage               = 1000
  storage_encrypted                   = true
  kms_key_id                          = aws_kms_key.platform.arn
  db_subnet_group_name                = aws_db_subnet_group.main.name
  vpc_security_group_ids              = [aws_security_group.db.id]
  parameter_group_name                = aws_db_parameter_group.pg.name
  multi_az                            = true
  publicly_accessible                 = false
  iam_database_authentication_enabled = true
  username                            = "postgres"
  manage_master_user_password         = true
  master_user_secret_kms_key_id       = aws_kms_key.platform.arn
  backup_retention_period             = 35
  deletion_protection                 = true
  copy_tags_to_snapshot               = true
  performance_insights_enabled        = true
  performance_insights_kms_key_id     = aws_kms_key.platform.arn
  enabled_cloudwatch_logs_exports     = ["postgresql"]
  auto_minor_version_upgrade          = true
  skip_final_snapshot                 = false
  final_snapshot_identifier           = "samiir-fatma-${var.environment}-final"
}

resource "aws_elasticache_subnet_group" "main" {
  name       = "samiir-fatma"
  subnet_ids = aws_subnet.data[*].id
}

resource "aws_elasticache_replication_group" "redis" {
  replication_group_id       = "samiir-fatma-${var.environment}"
  description                = "sessions, rate limits, replay caches, realtime"
  engine                     = "redis"
  engine_version             = "7.1"
  node_type                  = var.redis_node_type
  num_cache_clusters         = 2
  automatic_failover_enabled = true
  multi_az_enabled           = true
  at_rest_encryption_enabled = true
  transit_encryption_enabled = true
  kms_key_id                 = aws_kms_key.platform.arn
  subnet_group_name          = aws_elasticache_subnet_group.main.name
  security_group_ids         = [aws_security_group.redis.id]
  # Per-service Redis ACL users (key-prefix scoped) are managed via aws_elasticache_user.
}

# Object storage: raw (redacted) security events and quarantined samples.
resource "aws_s3_bucket" "raw_events" {
  bucket = "samiir-fatma-${var.environment}-raw-events"
}

resource "aws_s3_bucket" "quarantine" {
  bucket              = "samiir-fatma-${var.environment}-quarantine"
  object_lock_enabled = true
}
resource "aws_s3_bucket" "logs" {
  bucket = "samiir-fatma-${var.environment}-logs"
}

# Written out per bucket (not for_each) so policy scanners can link each control to its bucket.
resource "aws_s3_bucket_public_access_block" "raw_events" {
  bucket                  = aws_s3_bucket.raw_events.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "raw_events" {
  bucket = aws_s3_bucket.raw_events.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.platform.arn
    }
    bucket_key_enabled = true
  }
}

moved {
  from = aws_s3_bucket_public_access_block.all["raw"]
  to   = aws_s3_bucket_public_access_block.raw_events
}

moved {
  from = aws_s3_bucket_server_side_encryption_configuration.all["raw"]
  to   = aws_s3_bucket_server_side_encryption_configuration.raw_events
}

resource "aws_s3_bucket_public_access_block" "quarantine" {
  bucket                  = aws_s3_bucket.quarantine.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "quarantine" {
  bucket = aws_s3_bucket.quarantine.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.platform.arn
    }
    bucket_key_enabled = true
  }
}

moved {
  from = aws_s3_bucket_public_access_block.all["q"]
  to   = aws_s3_bucket_public_access_block.quarantine
}

moved {
  from = aws_s3_bucket_server_side_encryption_configuration.all["q"]
  to   = aws_s3_bucket_server_side_encryption_configuration.quarantine
}

resource "aws_s3_bucket_public_access_block" "logs" {
  bucket                  = aws_s3_bucket.logs.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "logs" {
  bucket = aws_s3_bucket.logs.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.platform.arn
    }
    bucket_key_enabled = true
  }
}

moved {
  from = aws_s3_bucket_public_access_block.all["l"]
  to   = aws_s3_bucket_public_access_block.logs
}

moved {
  from = aws_s3_bucket_server_side_encryption_configuration.all["l"]
  to   = aws_s3_bucket_server_side_encryption_configuration.logs
}

resource "aws_s3_bucket_lifecycle_configuration" "raw" {
  bucket = aws_s3_bucket.raw_events.id
  rule {
    id     = "retention"
    status = "Enabled"
    filter {}
    expiration { days = 400 }
  }
}
