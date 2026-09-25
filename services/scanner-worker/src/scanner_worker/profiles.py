"""Scan profiles. Both profiles are non-destructive by construction.

Excluded in every profile: denial-of-service, fuzzing, brute force / credential stuffing /
default-login / token spraying, intrusive templates, remote-code-execution and injection
exploitation templates, out-of-band interaction (interactsh), persistence, anything that
writes to the target. ZAP runs spider + passive scan only (never the active scanner).
"""

from __future__ import annotations

from dataclasses import dataclass

DEFAULT_EXCLUDED_TAGS = (
    "dos", "fuzz", "fuzzing", "intrusive", "bruteforce", "brute-force", "default-login",
    "credential-stuffing", "token-spray", "spray", "rce", "sqli", "xss", "lfi", "rfi", "ssrf",
    "oast", "dast", "file-upload", "deserialization", "headless", "code", "malware",
)


@dataclass(frozen=True)
class Profile:
    name: str
    nuclei_tags: tuple[str, ...]
    nuclei_rate_limit: int
    nuclei_concurrency: int
    zap_spider_minutes: int
    zap_passive_minutes: int


PROFILES: dict[str, Profile] = {
    "safe-passive": Profile("safe-passive", ("tech", "misconfig", "exposure", "ssl", "headers"),
                            nuclei_rate_limit=5, nuclei_concurrency=3, zap_spider_minutes=3,
                            zap_passive_minutes=5),
    "safe-standard": Profile("safe-standard",
                             ("tech", "misconfig", "exposure", "ssl", "headers", "cve", "config",
                              "panel", "takeover"),
                             nuclei_rate_limit=10, nuclei_concurrency=5, zap_spider_minutes=8,
                             zap_passive_minutes=10),
}


def nuclei_args(profile: Profile, target: str, output: str) -> list[str]:
    return [
        "nuclei", "-u", target, "-tags", ",".join(profile.nuclei_tags),
        "-etags", ",".join(DEFAULT_EXCLUDED_TAGS), "-exclude-type", "headless,code,file",
        "-rl", str(profile.nuclei_rate_limit), "-c", str(profile.nuclei_concurrency),
        "-timeout", "10", "-retries", "1", "-ni", "-disable-update-check", "-no-color",
        "-silent", "-jsonl", "-o", output
    ]


def zap_plan(profile: Profile, target: str, report_dir: str) -> dict:
    return {
        "env": {"contexts": [{"name": "target", "urls": [target],
                              "includePaths": [f"{target.rstrip('/')}.*"]}],
                "parameters": {"failOnError": False, "progressToStdout": False}},
        "jobs": [
            {"type": "spider", "parameters": {"context": "target",
                                              "maxDuration": profile.zap_spider_minutes,
                                              "maxChildren": 50}},
            {"type": "passiveScan-wait", "parameters": {"maxDuration": profile.zap_passive_minutes}},
            {"type": "report", "parameters": {"template": "traditional-json",
                                              "reportDir": report_dir,
                                              "reportFile": "zap-report.json"}},
        ],
    }
