# AWS baseline (Terraform)

Private-by-default production foundation for the platform:

| Area | Resources |
|---|---|
| Network | VPC with public (LB only), app (EKS nodes, NAT egress) and data (no internet route) subnets, VPC flow logs |
| Compute | EKS (KMS-encrypted secrets, private endpoint, audit logs), Bottlerocket node groups: `apps`, tainted `scanners` and `sandbox` pools |
| Data | RDS PostgreSQL 17 (Multi-AZ, KMS, forced TLS, IAM auth, 35-day PITR), ElastiCache Redis (TLS + at-rest encryption) |
| Secrets | KMS CMK with rotation; Secrets Manager entries created empty and populated by the key pipeline |
| Storage | S3 raw-event and quarantine (object-lock) buckets, all public access blocked, SSE-KMS |
| Backup/DR | AWS Backup daily plan, vault lock, cross-region copy to `backup_region` |

```bash
terraform init -backend-config=env/prod.backend.hcl
terraform plan -var environment=prod -var 'admin_cidrs=["203.0.113.0/24"]'
```

Cluster add-ons (installed with Helm after `apply`): Istio (STRICT mTLS), ingress-nginx,
External Secrets Operator, cert-manager, Kyverno/sigstore policy-controller (only signed images),
OpenTelemetry collector, Temporal (or Temporal Cloud), gVisor runtime class on the sandbox pool.
