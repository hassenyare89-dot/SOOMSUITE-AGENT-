# Deployment

## 1. Local: Docker Compose

```bash
python3 scripts/bootstrap_dev.py         # .env with random secrets; .secrets/service-keys/*.pem + trust.json
docker compose up -d --build
docker compose ps                        # 16 healthy services + web
docker compose --profile scanners up -d  # Temporal UI :8233, ClamAV, scanner-worker, malware-worker
```

| URL | What |
|---|---|
| http://localhost:3000 | Console + widget (`/widget/<key>`) |
| http://localhost:8000 | Public gateway |
| http://localhost:8001 | Admin gateway |
| http://localhost:8025 | Mailpit (captured emails) |

All ports bind to `127.0.0.1`. Containers run as uid 10001 with read-only root filesystems,
`no-new-privileges`, and all capabilities dropped. Each service mounts **only its own** private
key plus the public trust bundle.

Corporate proxies and private package indexes: images accept optional BuildKit secrets
(`pip_conf`, `npmrc`, `extra_ca`) and `APT_UPGRADE=false` so no credential enters a layer.

## 2. Production: Kubernetes (Helm)

Chart: `infra/kubernetes/helm/samiir-fatma`

```bash
helm upgrade --install platform infra/kubernetes/helm/samiir-fatma -n platform \
  --set global.imageRegistry=ghcr.io/<org>/samiir-fatma --set global.imageTag=<git-sha> \
  --set global.domain=<your-domain> --atomic --wait
```

What the chart creates:
- One Deployment + ServiceAccount per service (the SA is its mesh identity), with PodSecurity
  `restricted`, read-only root filesystems and resource limits.
- `ExternalSecret`s per service from the `platform-secrets` store (Vault or AWS Secrets Manager).
  No secret values live in values files.
- Default-deny `NetworkPolicy` plus per-service ingress generated from `callers` (mirrors
  `ACCEPTED_CALLERS`). Istio `PeerAuthentication STRICT` and `AuthorizationPolicy`.
- Separate worker node pools (taints) for scanner and malware workers, with egress-restricted
  namespaces.
- A pre-install/pre-upgrade migration Job: the only place the schema-owner credential exists.
- Ingress for the two gateways and the web app only.

Images should be referenced by digest and verified with cosign (e.g. a Kyverno `verifyImages`
policy) using the keyless identity of `.github/workflows/security.yml`.

## 3. Cloud baseline: Terraform (AWS)

`infra/terraform/aws` provisions a VPC with private subnets, EKS (private endpoint, KMS-encrypted
secrets, separate node groups), RDS PostgreSQL 16 (Multi-AZ, KMS, IAM auth, forced SSL,
pgvector), ElastiCache Redis (TLS + AUTH), S3 buckets for raw events and quarantine (KMS, object
lock for evidence), Secrets Manager, and AWS Backup with a cross-region copy. See its README.
State goes in an encrypted S3 backend with locking.

## 4. Secrets

| Secret | Holder | Notes |
|---|---|---|
| Service Ed25519 private keys | each service only | Rotate by adding a new kid to the trust bundle, rolling, then removing the old |
| DB role passwords / IAM auth | each service | Production: IAM or Vault dynamic credentials |
| `FIELD_ENCRYPTION_KEYRING`, `BLIND_INDEX_KEY` | data services | Keyring `v1.kid.b64,...`: add a new first entry to rotate. Old keys stay for decryption |
| Meta access token + app secret | whatsapp service | Never in model context |
| Cloudflare / AWS WAF | fatma-soc (via `secret_ref`) | Least-privilege scoped tokens |
| OpenAI API key | samiir-agent, fatma-soc | Separate keys/projects per agent recommended |
| OIDC client secret, session key | admin gateway | |
| Ingest webhook secrets | security-ingest | Per integration, referenced by `secret_ref` (`env://`, `file://`, `vault://`, `aws-sm://`) |

## 5. CI/CD (GitHub Actions)

| Workflow | Runs | Gates |
|---|---|---|
| `ci.yml` | PR, main | ruff, mypy, pytest (pgvector service), web typecheck/build, helm lint + kube-linter, terraform fmt/validate |
| `security.yml` | PR, main, weekly | gitleaks, CodeQL, bandit, semgrep, pip-audit, npm audit, trivy (config + each image), SBOM (SPDX), cosign keyless signing + provenance on main |
| `migrations.yml` | PR touching schema; manual deploy | upgrade → downgrade → upgrade, drift test; environment-protected helm deploy via OIDC role |
| `restore-drill.yml` | weekly | Restore latest snapshot into an isolated account; verify Alembic head + audit hash chains; tear down |

Protect `main`, require these checks, and configure GitHub Environments `staging`/`production`
with required reviewers.

## 6. Operations
- Health: `/healthz` (liveness), `/readyz` (DB/Redis) on every service.
- Migrations: forward-only in production. Every migration ships a downgrade that CI tests.
- Backups: RDS automated backups + AWS Backup cross-region copy. The restore drill runs weekly.
- Scaling: gateways and SAMIIR scale horizontally. The fatma-soc sweeper and the notification
  worker use `FOR UPDATE SKIP LOCKED`, so replicas are safe.
