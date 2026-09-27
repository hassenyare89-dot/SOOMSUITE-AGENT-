"""Containment and remediation guidance per incident category, plus candidate defensive
actions. Recommendations are advice for humans; actions still require approval."""

from __future__ import annotations

from dataclasses import dataclass, field

from platform_core.schemas.enums import DefenseActionType


@dataclass(frozen=True)
class Playbook:
    containment: list[str]
    remediation: list[str]
    actions: list[DefenseActionType] = field(default_factory=list)


PLAYBOOKS: dict[str, Playbook] = {
    "sql_injection": Playbook(
        ["Confirm the WAF managed SQLi rules are in block mode for the targeted host.",
         "Temporarily block or challenge the attacking source addresses."],
        ["Review the targeted endpoint for unparameterized queries.",
         "Check database logs for unexpected queries or data access in the time window.",
         "Rotate database credentials if any successful injection is suspected."],
        [DefenseActionType.TEMP_BLOCK_IP, DefenseActionType.CHALLENGE_IP]),
    "xss": Playbook(
        ["Ensure WAF XSS rules are enforced for the affected paths."],
        ["Verify output encoding on the reflected parameters.",
         "Confirm a strict Content-Security-Policy is deployed."],
        [DefenseActionType.CHALLENGE_IP]),
    "path_traversal": Playbook(
        ["Block the source if requests target sensitive files."],
        ["Validate and canonicalize file paths server-side.",
         "Check whether any sensitive file was returned (2xx responses)."],
        [DefenseActionType.TEMP_BLOCK_IP]),
    "web_attack": Playbook(
        ["Challenge or temporarily block the source."],
        ["Patch the targeted component; review application logs for exploitation."],
        [DefenseActionType.TEMP_BLOCK_IP, DefenseActionType.CHALLENGE_IP]),
    "credential_attack": Playbook(
        ["Apply a short rate limit on the login endpoint.",
         "Challenge sources with high failure rates."],
        ["Verify MFA enforcement for targeted accounts.",
         "Check for successful logins from attacking sources; reset affected credentials.",
         "Review breached-password screening."],
        [DefenseActionType.RATE_LIMIT_PATH, DefenseActionType.CHALLENGE_IP,
         DefenseActionType.REVOKE_APP_SESSION]),
    "auth_anomaly": Playbook(
        ["Revoke suspicious sessions after verification."],
        ["Contact the account owner; review recent account activity."],
        [DefenseActionType.REVOKE_APP_SESSION, DefenseActionType.DISABLE_ACCOUNT]),
    "ddos": Playbook(
        ["Enable the CDN's DDoS / 'under attack' protections for the zone.",
         "Rate-limit the targeted endpoint; challenge abusive sources."],
        ["Review origin capacity and caching for the targeted path.",
         "Coordinate with the CDN provider if the attack persists."],
        [DefenseActionType.RATE_LIMIT_PATH, DefenseActionType.CHALLENGE_IP,
         DefenseActionType.BLOCK_COUNTRY]),
    "rate_anomaly": Playbook(
        ["Investigate traffic source; consider a short rate limit."],
        ["Confirm whether the spike correlates with marketing or releases."],
        [DefenseActionType.RATE_LIMIT_PATH]),
    "bot": Playbook(
        ["Challenge automated sources on the affected paths."],
        ["Enable bot management rules; protect forms with proof-of-work or CAPTCHA."],
        [DefenseActionType.CHALLENGE_IP]),
    "malware": Playbook(
        ["Keep the sample quarantined; isolate the affected host or remove the file after "
         "forensic capture."],
        ["Identify the infection vector; scan related systems; restore from a clean backup.",
         "Rotate credentials that may have been exposed on the affected system."],
        [DefenseActionType.ISOLATE_NETWORK_SEGMENT]),
    "vulnerability": Playbook(
        ["Apply virtual patching via WAF rules where available."],
        ["Patch or upgrade the affected software; re-scan to verify."]),
    "misconfiguration": Playbook(
        [], ["Correct the configuration (headers, TLS settings) and re-scan to verify."]),
    "exposure": Playbook(
        ["Restrict access to the exposed resource."],
        ["Remove sensitive files from the web root; review deployment pipeline."]),
}


def playbook_for(category: str) -> Playbook:
    return PLAYBOOKS.get(category, Playbook(["Triage the evidence and monitor."],
                                            ["Document findings and close if benign."]))
