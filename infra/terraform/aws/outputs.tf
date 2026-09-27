output "db_endpoint" {
  value = aws_db_instance.main.address
}

output "redis_endpoint" {
  value = aws_elasticache_replication_group.redis.primary_endpoint_address
}

output "eks_cluster" {
  value = aws_eks_cluster.main.name
}

output "kms_key_arn" {
  value = aws_kms_key.platform.arn
}
