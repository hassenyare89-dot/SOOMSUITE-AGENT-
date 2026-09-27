# SOC runbook (FATMA operators)

Audience: `security_analyst` and `security_engineer` roles. FATMA is an assistant. Every decision
that changes a system or a claim is made by a person and recorded.

## 1. Risk model

| Score | Class | Expected response |
|---|---|---|
| 0–24 | NORMAL | None. Visible in events. |
| 25–49 | SUSPICIOUS | Review within 1 business day |
| 50–74 | HIGH_RISK | Acknowledge within 1 h, investigate |
| 75–100 | CRITICAL | Acknowledge within 15 min, page on-call |

The score combines signal severity × confidence, asset criticality (1–5), volume, success
indicators and the blocked ratio (blocked traffic lowers urgency). On an open incident, risk
never decreases automatically.

Detectors: brute force, credential stuffing, request flood, distributed sources, endpoint
concentration, geo shift, auth flood, bot spike, repeat offender, plus per-event signatures
(WAF blocks, malware hits, scanner findings, token reuse, impossible travel). Per-tenant
thresholds live in tenant settings under `detection`.

## 2. Incident lifecycle

```
NEW → ACKNOWLEDGED → INVESTIGATING → CONTAINED → REMEDIATED → CLOSED
  └──────────────┴──────────────┴──→ FALSE_POSITIVE        (reopen → INVESTIGATING)
```

Claim status is separate: **SUSPECTED** (default, always for FATMA) → **CONFIRMED** (human only).

### Triage checklist
1. Open the incident and read the signals, evidence events and FATMA analysis.
   FATMA's analysis is a hypothesis.
2. Check whether the source is a known scanner, partner or monitoring service. If so, mark it
   `FALSE_POSITIVE` with a note and tune thresholds if the pattern recurs.
3. Check success indicators: `login_success` after failures, 2xx on sensitive endpoints after
   blocks, malware verdicts, or data volume anomalies.
4. Acknowledge, assign an owner and move to `INVESTIGATING`.
5. Ask FATMA (`/ask`) for correlations, timelines and hypotheses. Every answer cites event ids.

### Confirming an incident
`POST /incidents/{id}/confirm` requires the `incident.confirm` permission and MFA, and:
- every item of the category's **confirmation checklist** attested,
- `evidence_refs` (event ids, ticket, forensic artifact references),
- a justification of at least 30 characters.

The database rejects confirmations whose actor is not a user.

## 3. Defensive actions

| Action | Risk | Approval |
|---|---|---|
| `challenge_ip`, `temp_block_ip` (≤ /24, public IPs), `rate_limit_path`, `revoke_app_session` | Low | 1 approver, or tenant pre-approval policy |
| `block_country`, `disable_account`, `rotate_credentials`, `change_firewall_rule`, `change_dns`, `shutdown_service`, network isolation, data deletion | High | 2 distinct approvers, always human |

Flow: FATMA recommends → an analyst requests approval → the approver reviews the **exact
payload** and echoes its hash → an engineer executes (the approval is consumed) → the action is
`ACTIVE` until TTL → the sweeper reverts it and marks it `EXPIRED`. Manual `revert` is always
available.

**Tenant pre-approval** (`fatma_mode = preapproved_low_risk`) auto-approves only low-risk,
single-IP actions with TTL ≤ 1 h and confidence ≥ 0.9. It is off by default.

If no provider is configured, execution produces a *manual runbook* task. Apply the change by
hand and record the reference in a note.

## 4. Scanning

Before requesting a scan:
1. Register the asset and verify ownership (DNS TXT `_samiir-fatma-verify.<host>` = `sf-verify=<token>`,
   or the HTTPS file `/.well-known/samiir-fatma-verify.txt`).
2. Record the customer authorization reference and expiry.
3. Allowlist the asset.
4. Request the scan with a change/authorization ticket reference and a profile:
   - `safe-passive`: tech, misconfig, exposure, TLS, headers. Low rate.
   - `safe-standard`: adds CVE/config/panel/takeover checks. Still non-intrusive.
5. A second engineer approves the payload hash. The workflow then starts.

Never scan third-party infrastructure (CDNs, SaaS) without that provider's written permission.
Findings flow back as `scanner` events and are deduplicated by template and location.

## 5. Malware samples
Upload via `/malware/submit`. Samples are stored encrypted, scanned by ClamAV + YARA, and never
executed. Results produce `malware` events. Destroy samples after the case closes; destruction
is audited.

## 6. Daily hygiene
- Review unacknowledged HIGH_RISK/CRITICAL incidents and pending approvals.
- Review `ACTIVE` actions nearing expiry. Extend them only through a new approval.
- Check `/v1/admin/audit/verify` returns `valid: true`.
- Review integrations with no events in 24 h (a broken pipe looks like peace).
