# Terraform boundary

Production modules should provision separate SAMIIR and FATMA subnets/service accounts, private data services, KMS keys, secret-manager ACLs, WAF, workload identity, immutable audit storage, and an isolated scanner node pool. Provider-specific values are intentionally supplied by environment configuration rather than committed credentials.
