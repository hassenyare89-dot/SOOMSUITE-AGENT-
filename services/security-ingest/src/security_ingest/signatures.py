"""Lightweight attack-signature classifier for request paths/queries (app & proxy logs).

WAF/CDN sources usually label attacks themselves; this classifier covers raw access logs.
Patterns operate on URL-decoded, lower-cased input and are bounded to avoid ReDoS."""

from __future__ import annotations

import re
from urllib.parse import unquote_plus

from platform_core.schemas.security import EventCategory

_MAX = 4096
SIGNATURES: list[tuple[EventCategory, str, re.Pattern[str], int, float]] = [
    (EventCategory.SQL_INJECTION, "sqli.union_select",
     re.compile(r"\bunion\b[\s/*+]{1,20}(all[\s/*+]{1,20})?select\b"), 8, 0.85),
    (EventCategory.SQL_INJECTION, "sqli.boolean",
     re.compile(r"['\"`]\s{0,5}(or|and)\s{1,5}['\"`]?\d{1,5}['\"`]?\s{0,5}=\s{0,5}['\"`]?\d{1,5}"), 7, 0.75),
    (EventCategory.SQL_INJECTION, "sqli.time_based",
     re.compile(r"\b(sleep|pg_sleep|benchmark|waitfor\s{1,5}delay)\s{0,5}\("), 8, 0.8),
    (EventCategory.SQL_INJECTION, "sqli.comment_terminator",
     re.compile(r"['\"]\s{0,5}(;|--|#|/\*)"), 5, 0.5),
    (EventCategory.XSS, "xss.script_tag", re.compile(r"<\s{0,5}script\b"), 7, 0.85),
    (EventCategory.XSS, "xss.event_handler",
     re.compile(r"<[^>]{0,200}\bon(error|load|mouseover|focus|click)\s{0,5}="), 7, 0.8),
    (EventCategory.XSS, "xss.js_uri", re.compile(r"javascript\s{0,5}:"), 6, 0.7),
    (EventCategory.PATH_TRAVERSAL, "traversal.dotdot",
     re.compile(r"(\.\.[/\\]){2,}|%2e%2e[/\\%]"), 7, 0.8),
    (EventCategory.PATH_TRAVERSAL, "traversal.sensitive_file",
     re.compile(r"(/etc/passwd|/etc/shadow|win\.ini|boot\.ini|/proc/self/environ)"), 9, 0.9),
    (EventCategory.WEB_ATTACK, "rce.command_injection",
     re.compile(r"(;|\||`|\$\()\s{0,5}(cat|curl|wget|bash|sh|nc|powershell)\b"), 9, 0.8),
    (EventCategory.WEB_ATTACK, "ssrf.metadata_endpoint",
     re.compile(r"169\.254\.169\.254|metadata\.google\.internal"), 8, 0.8),
    (EventCategory.WEB_ATTACK, "log4shell", re.compile(r"\$\{\s{0,5}jndi\s{0,5}:"), 10, 0.9),
    (EventCategory.EXPOSURE, "probe.sensitive_paths",
     re.compile(r"/(\.env|\.git/|wp-config\.php|phpmyadmin|\.aws/credentials|server-status)"), 5, 0.6),
]

SCANNER_UA = re.compile(r"(sqlmap|nikto|nmap|masscan|zgrab|nuclei|acunetix|wpscan|dirbuster|"
                        r"gobuster|feroxbuster|hydra)", re.I)


def classify_request(path: str | None, query: str | None = None,
                     user_agent: str | None = None) -> list[tuple[EventCategory, str, int, float]]:
    raw = f"{path or ''}?{query or ''}"[:_MAX]
    decoded = unquote_plus(unquote_plus(raw)).lower()
    hits = [(cat, name, sev, conf) for cat, name, pat, sev, conf in SIGNATURES
            if pat.search(decoded)]
    if user_agent and SCANNER_UA.search(user_agent[:512]):
        hits.append((EventCategory.BOT, "bot.scanner_user_agent", 4, 0.7))
    return hits
