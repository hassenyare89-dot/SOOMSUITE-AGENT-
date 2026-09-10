# Threat model

## Assets and adversaries

Protected assets include tenant data, customer PII, SOC telemetry, integration tokens, scanner authorization, model context, audit evidence, and production infrastructure. Adversaries include anonymous abusers, compromised tenant users, malicious insiders, supply-chain actors, hostile uploaded files, and prompt injection embedded in customer content/logs.

## Primary abuse cases and controls

| Threat | Boundary control | Validation |
|---|---|---|
| SAMIIR-to-FATMA escalation | distinct registries, roles, identities, networks, queues | adversarial tool-escalation tests |
| Cross-tenant IDOR | tenant JWT binding, repository predicates, PostgreSQL RLS, opaque 404 | tenant isolation tests |
| Webhook spoof/replay | Meta HMAC over raw bytes, dedupe IDs, timestamp/cache controls | signature and replay tests |
| Scanner misuse/SSRF | ownership proof, allowlist, ticket, approval hash, DNS/IP revalidation, safe profile | policy and SSRF tests |
| Prompt injection | untrusted-data envelopes, fixed typed tools, deterministic policy, output validation | prompt-injection suite |
| False breach declaration | correlation thresholds and analyst confirmation | risk tests |
| Approval substitution | canonical SHA-256 payload binding, expiry, single execution | parameter mutation tests |
| Malware/archive bombs | MIME/magic checks, streaming size/depth limits, quarantine, no execution, isolated ClamAV/YARA | malicious upload corpus |
| Secret disclosure | secret manager references, redaction, restricted traces, key rotation | secret scanning |
| Audit tampering | append-only store, per-entry hash chain, SIEM export, restricted writer | chain verification |

## Residual risks

LLM output remains probabilistic, scanners may affect fragile targets, upstream identity or cloud compromise can defeat local controls, and traffic analysis can expose metadata. Human approval, canary deployment, rate/concurrency limits, kill switches, vendor risk review, and incident exercises reduce but do not eliminate these risks.
