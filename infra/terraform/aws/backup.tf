# Encrypted backups with cross-region copies. Restore drills are run by
# .github/workflows/restore-drill.yml (weekly) against an isolated account.
resource "aws_backup_vault" "main" {
  name        = "samiir-fatma-${var.environment}"
  kms_key_arn = aws_kms_key.platform.arn
}

resource "aws_backup_vault_lock_configuration" "main" {
  backup_vault_name  = aws_backup_vault.main.name
  min_retention_days = 35
}

resource "aws_backup_plan" "main" {
  name = "samiir-fatma-${var.environment}"
  rule {
    rule_name         = "daily"
    target_vault_name = aws_backup_vault.main.name
    schedule          = "cron(0 3 * * ? *)"
    lifecycle { delete_after = 35 }
    copy_action {
      destination_vault_arn = "arn:aws:backup:${var.backup_region}:${data.aws_caller_identity.me.account_id}:backup-vault:samiir-fatma-${var.environment}-dr"
      lifecycle { delete_after = 90 }
    }
  }
}

resource "aws_backup_selection" "main" {
  name         = "platform-data"
  plan_id      = aws_backup_plan.main.id
  iam_role_arn = aws_iam_role.backup.arn
  resources    = [aws_db_instance.main.arn, aws_s3_bucket.quarantine.arn]
}

data "aws_caller_identity" "me" {}

resource "aws_iam_role" "backup" {
  name = "samiir-fatma-backup"
  assume_role_policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{ Effect = "Allow", Principal = { Service = "backup.amazonaws.com" }, Action = "sts:AssumeRole" }]
  })
}

resource "aws_iam_role_policy_attachment" "backup" {
  role       = aws_iam_role.backup.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSBackupServiceRolePolicyForBackup"
}
