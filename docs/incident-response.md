# Incident response: the platform itself

This plan covers incidents *affecting this platform* (as opposed to customer incidents handled
with FATMA; see `soc-runbook.md`). It follows NIST SP 800-61: prepare, detect/analyse, contain,
eradicate, recover, lessons learned.

## Roles
- **Incident commander (IC):** owns decisions and the timeline.
- **Tech lead:** investigation and containment.
- **Comms:** customers, legal and regulators. Breach-notification clocks (e.g. GDPR 72 h) start
  at awareness.
- **Scribe:** keeps the timeline in the ticket. Every action gets a UTC timestamp.

## Severity
| Sev | Examples |
|---|---|
| SEV1 | Cross-tenant data exposure; key/credential compromise; audit chain broken; unapproved defensive action or scan executed |
| SEV2 | Single-tenant PII exposure; agent guardrail bypass reaching a customer; service identity misuse |
| SEV3 | Contained vulnerability with no evidence of exploitation; prompt-injection attempts that were blocked but noisy |

## Detection sources
Audit chain `/verify` failures; `FORBIDDEN`/`NOT_FOUND` spikes per principal; service token
replay or `aud` rejections; RLS errors; guardrail replacement rate; unexpected egress in
network-policy logs; CloudTrail/GuardDuty; dependency and image scan alerts.

## Playbooks

### A. Suspected agent compromise (prompt injection, jailbreak)
1. Pull `agent_runs` and `tool_calls` for the conversation (admin → SAMIIR → agent runs).
2. Confirm which tools ran and that each was policy-authorized. Unauthorized attempts appear as
   denied tool calls.
3. Contain: set the tenant's agent to deterministic runtime or disable the widget key, then
   block the source at the edge.
4. Eradicate: add the payload to `tests/security/test_prompt_injection.py` and fix the guardrail
   or schema. Model instructions alone are never the fix.

### B. Credential or key compromise
| Secret | Action |
|---|---|
| Service Ed25519 key | Generate a new key (`bootstrap_dev.py --rotate-keys` or the secret-manager equivalent), publish the new trust bundle, roll the service, then remove the old kid. Tokens live 60 s. |
| Field encryption key | Prepend a new key to the keyring, roll, run the re-encryption job, then retire the old key after verification |
| Meta / Cloudflare / OpenAI / calendar token | Revoke at the provider, issue a new scoped token, update the secret store, and review provider audit logs for the exposure window |
| OIDC client secret / session key | Rotate. Changing the session key invalidates all admin sessions |
| DB credential | Rotate the role password or IAM binding. Review `pg_stat_activity` and logs |

### C. Cross-tenant exposure
1. SEV1. Freeze deploys.
2. Identify the path: RLS bypass (check the `app.tenant_id` setting), a lookup function, or a
   caching bug.
3. Hotfix with a regression test in `tests/integration`.
4. Enumerate affected records from audit logs and notify the affected tenants.

### D. Audit chain verification failure
1. Snapshot the database immediately. Do not "repair" rows.
2. Compare against the SIEM copy (forwarded entries include `entry_hash`) to find the first
   divergent `seq`.
3. Treat as tampering until proven otherwise. Review superuser and owner access.

### E. Unapproved scan or defensive action
1. Revert the action (`/actions/{id}/revert`) or cancel the workflow.
2. Check the approval record: payload hash, signer, consume timestamp.
3. Notify the affected asset owner. Scanning without authorization can have legal consequences.

## Evidence handling
Preserve: DB snapshot, audit export, raw event objects (object-lock bucket), container images
by digest, Kubernetes events, and cloud audit logs. Record SHA-256 hashes of every artifact in
the ticket. Chain of custody belongs with the IC.

## Recovery and post-incident
- Restore from backup follows the restore drill procedure (`restore-drill.yml`).
- Verify the audit chain and run the full test suite before reopening traffic.
- Hold a blameless review within 5 business days. Each action item needs an owner and a test or
  control that would have caught the problem.
