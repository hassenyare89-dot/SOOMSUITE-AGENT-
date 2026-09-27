"""Detection & correlation engine.

Input: newly stored, normalized security events for one tenant.
Output: signals grouped into incidents keyed by a correlation key, with deterministic risk.

Detectors
* per-event: attack categories from WAF/signature labels, success indicators (2xx responses
  to attack requests), scanner user agents
* windowed (SQL aggregates over ``security_events``):
  - credential attacks: brute force per source, credential stuffing (many users per source),
    distributed attacks on one account
  - Layer-7 floods / DDoS indicators: request-rate spike vs. baseline, distributed sources,
    endpoint concentration, geolocation shift, authentication floods
  - repeat offenders: sources blocked across several categories
  - bot spikes
"""

from __future__ import annotations

import hashlib
import ipaddress
import uuid
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from fatma_soc.risk import Signal

ATTACK_CATEGORIES = {"sql_injection", "xss", "path_traversal", "web_attack"}
FAMILY = {"sql_injection": "web_attack", "xss": "web_attack", "path_traversal": "web_attack",
          "web_attack": "web_attack", "waf_block": "web_attack", "credential_attack": "credential",
          "auth_anomaly": "credential", "ddos": "ddos", "rate_anomaly": "ddos", "bot": "bot",
          "malware": "malware", "vulnerability": "vulnerability",
          "misconfiguration": "vulnerability", "exposure": "vulnerability",
          "data_exfiltration": "exfiltration"}

# Thresholds (per tenant overrides via tenants.settings["detection"]).
DEFAULT_THRESHOLDS = {
    "bruteforce_failures_10m": 10,
    "stuffing_distinct_users_10m": 5,
    "distributed_account_sources_30m": 5,
    "flood_min_rpm": 300,
    "flood_ratio": 5.0,
    "distributed_sources_5m": 200,
    "endpoint_concentration": 0.6,
    "geo_shift": 0.5,
    "auth_flood_rpm": 100,
    "bot_spike_5m": 50,
    "repeat_offender_categories_1h": 2,
}


@dataclass
class Candidate:
    correlation_key: str
    category: str
    title: str
    asset_id: uuid.UUID | None
    signals: list[Signal] = field(default_factory=list)
    event_ids: list[uuid.UUID] = field(default_factory=list)
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    succeeded: bool = False
    blocked: int = 0
    sources: set[str] = field(default_factory=set)

    def add_event(self, ev: Any) -> None:
        self.event_ids.append(ev.event_id)
        ts = ev.timestamp
        self.first_seen = ts if self.first_seen is None or ts < self.first_seen else self.first_seen
        self.last_seen = ts if self.last_seen is None or ts > self.last_seen else self.last_seen
        if ev.src_ip:
            self.sources.add(str(ev.src_ip))
        if (ev.action_taken or "") in ("block", "drop", "challenge", "managed_challenge"):
            self.blocked += 1


def _net(ip: str | None) -> str:
    if not ip:
        return "unknown"
    addr = ipaddress.ip_address(str(ip))
    return str(ipaddress.ip_network(f"{addr}/{24 if addr.version == 4 else 64}", strict=False))


def correlation_key(tenant_id: uuid.UUID, *parts: Any) -> str:
    return hashlib.sha256("|".join([str(tenant_id), *map(str, parts)]).encode()).hexdigest()


def per_event_candidates(tenant_id: uuid.UUID, events: list[Any]) -> dict[str, Candidate]:
    cands: dict[str, Candidate] = {}
    for ev in events:
        cat = ev.category
        if cat == "info":
            continue
        family = FAMILY.get(cat, cat)
        day = ev.timestamp.astimezone(UTC).date().isoformat()
        if family == "web_attack":
            key = correlation_key(tenant_id, ev.asset_id, family, _net(ev.src_ip), day)
            title = f"Web attack activity from {_net(ev.src_ip)}"
        elif family == "malware":
            sha = (ev.metadata_redacted or {}).get("sha256", "unknown")
            key = correlation_key(tenant_id, family, sha)
            title = "Malware detected in submitted file"
        elif family == "vulnerability":
            key = correlation_key(tenant_id, ev.asset_id, family, ev.rule_id or ev.event_type)
            title = f"Security weakness: {ev.signature or ev.event_type}"[:200]
        elif family == "credential":
            key = correlation_key(tenant_id, ev.asset_id, family, _net(ev.src_ip), day)
            title = f"Suspicious authentication activity from {_net(ev.src_ip)}"
        elif family in ("ddos", "bot"):
            hour = ev.timestamp.astimezone(UTC).strftime("%Y-%m-%dT%H")
            key = correlation_key(tenant_id, ev.asset_id, family, hour)
            title = "Traffic flood / DDoS indicators" if family == "ddos" else "Bot activity spike"
        else:
            key = correlation_key(tenant_id, ev.asset_id, family, day)
            title = f"{cat.replace('_', ' ').title()} activity"
        cand = cands.setdefault(key, Candidate(key, cat if family != "web_attack" else cat, title,
                                               ev.asset_id))
        cand.add_event(ev)
        cand.signals.append(Signal(f"event:{ev.event_type}", cat, int(ev.severity),
                                   float(ev.confidence),
                                   {"rule_id": ev.rule_id, "path": (ev.request_path or "")[:120]}))
        if cat in ATTACK_CATEGORIES and ev.status_code and 200 <= ev.status_code < 300 \
                and (ev.action_taken or "allow") not in ("block", "drop"):
            cand.succeeded = True
            cand.signals.append(Signal("success_indicator:2xx_on_attack", cat, 8, 0.6,
                                       {"status": ev.status_code}))
        # Upgrade category to the most severe one seen in the group.
        if int(ev.severity) >= max(s.severity for s in cand.signals):
            cand.category = cat
    return cands


async def windowed_signals(s: AsyncSession, tenant_id: uuid.UUID, asset_ids: set,
                           thresholds: dict[str, float]) -> list[Candidate]:
    """Aggregate detectors. Queries run under RLS for the tenant."""
    out: list[Candidate] = []
    now = datetime.now(UTC)
    # --- credential attacks -------------------------------------------------------------
    rows = (await s.execute(text("""
        SELECT host(src_ip) AS ip, asset_id, count(*) AS failures,
               count(DISTINCT user_id) AS users,
               min("timestamp") AS first_seen, max("timestamp") AS last_seen
        FROM security_events
        WHERE category IN ('credential_attack','auth_anomaly') AND src_ip IS NOT NULL
          AND "timestamp" > now() - interval '10 minutes'
        GROUP BY src_ip, asset_id
        HAVING count(*) >= :n OR count(DISTINCT user_id) >= :u
    """), {"n": thresholds["bruteforce_failures_10m"],
           "u": thresholds["stuffing_distinct_users_10m"]})).all()
    for r in rows:
        stuffing = r.users >= thresholds["stuffing_distinct_users_10m"]
        c = Candidate(correlation_key(tenant_id, r.asset_id, "credential", _net(r.ip),
                                      now.date().isoformat()), "credential_attack",
                      f"{'Credential stuffing' if stuffing else 'Brute-force'} from {r.ip}",
                      r.asset_id,
                      first_seen=r.first_seen, last_seen=r.last_seen)
        c.sources.add(r.ip)
        c.signals.append(Signal("credential_stuffing" if stuffing else "brute_force",
                                "credential_attack", 7 if stuffing else 6, 0.8,
                                {"failures_10m": r.failures, "distinct_users": r.users}))
        out.append(c)
    rows = (await s.execute(text("""
        SELECT user_id, count(DISTINCT src_ip) AS sources, count(*) AS failures,
               min("timestamp") AS first_seen, max("timestamp") AS last_seen
        FROM security_events
        WHERE category = 'credential_attack' AND user_id IS NOT NULL
          AND "timestamp" > now() - interval '30 minutes'
        GROUP BY user_id HAVING count(DISTINCT src_ip) >= :n
    """), {"n": thresholds["distributed_account_sources_30m"]})).all()
    for r in rows:
        c = Candidate(correlation_key(tenant_id, None, "credential-account", r.user_id,
                                      now.date().isoformat()), "credential_attack",
                      "Distributed attack on a single account", None,
                      first_seen=r.first_seen, last_seen=r.last_seen)
        c.signals.append(Signal("distributed_account_attack", "credential_attack", 7, 0.75,
                                {"sources_30m": r.sources, "failures": r.failures,
                                 "account": r.user_id}))
        out.append(c)

    # --- traffic floods / DDoS indicators, per asset -----------------------------------
    for asset_id in asset_ids:
        stats = (await s.execute(text("""
            SELECT
              count(*) FILTER (WHERE "timestamp" > now() - interval '1 minute') AS rpm_now,
              count(*) FILTER (WHERE "timestamp" <= now() - interval '1 minute'
                               AND "timestamp" > now() - interval '61 minutes') / 60.0 AS rpm_base,
              count(DISTINCT src_ip) FILTER (WHERE "timestamp" > now() - interval '5 minutes')
                AS sources_5m,
              count(*) FILTER (WHERE category IN ('credential_attack','auth_anomaly')
                               AND "timestamp" > now() - interval '1 minute') AS auth_rpm,
              count(*) FILTER (WHERE category = 'bot' AND "timestamp" > now() - interval '5 minutes')
                AS bots_5m,
              count(*) FILTER (WHERE category IN ('ddos','rate_anomaly')
                               AND "timestamp" > now() - interval '5 minutes') AS edge_ddos_5m
            FROM security_events
            WHERE asset_id = :a AND "timestamp" > now() - interval '61 minutes'
        """), {"a": asset_id})).one()
        hour = now.strftime("%Y-%m-%dT%H")
        key = correlation_key(tenant_id, asset_id, "ddos", hour)
        c = Candidate(key, "ddos", "Traffic flood / DDoS indicators", asset_id, first_seen=now,
                      last_seen=now)
        base = float(stats.rpm_base or 0)
        ratio = stats.rpm_now / max(base, 1.0)
        if stats.rpm_now >= thresholds["flood_min_rpm"] and ratio >= thresholds["flood_ratio"]:
            c.signals.append(Signal("abnormal_request_rate", "ddos", 7, 0.75,
                                    {"rpm_now": stats.rpm_now, "rpm_baseline": round(base, 1),
                                     "ratio": round(ratio, 1)}))
        if stats.sources_5m >= thresholds["distributed_sources_5m"]:
            c.signals.append(Signal("distributed_sources", "ddos", 6, 0.7,
                                    {"distinct_sources_5m": stats.sources_5m}))
        if stats.auth_rpm >= thresholds["auth_flood_rpm"]:
            c.signals.append(Signal("authentication_flood", "ddos", 7, 0.75,
                                    {"auth_events_1m": stats.auth_rpm}))
        if stats.edge_ddos_5m > 0:
            c.signals.append(Signal("edge_ddos_mitigation", "ddos", 6, 0.8,
                                    {"edge_events_5m": stats.edge_ddos_5m}))
        if c.signals:
            top = (await s.execute(text("""
                SELECT request_path, count(*) AS n FROM security_events
                WHERE asset_id = :a AND "timestamp" > now() - interval '5 minutes'
                GROUP BY request_path ORDER BY n DESC LIMIT 1"""), {"a": asset_id})).first()
            total5 = await s.scalar(text("""SELECT count(*) FROM security_events WHERE asset_id = :a
                AND "timestamp" > now() - interval '5 minutes'"""), {"a": asset_id})
            if top and total5 and top.n / total5 >= thresholds["endpoint_concentration"]:
                c.signals.append(Signal("endpoint_targeted_flood", "ddos", 6, 0.7,
                                        {"path": (top.request_path or "/")[:120],
                                         "share": round(top.n / total5, 2)}))
            geo = (await s.execute(text("""
                WITH recent AS (SELECT country, count(*) n FROM security_events
                    WHERE asset_id = :a AND country IS NOT NULL
                      AND "timestamp" > now() - interval '10 minutes' GROUP BY country),
                     base AS (SELECT country, count(*) n FROM security_events
                    WHERE asset_id = :a AND country IS NOT NULL
                      AND "timestamp" BETWEEN now() - interval '24 hours'
                                          AND now() - interval '10 minutes' GROUP BY country)
                SELECT r.country, r.n::float / (SELECT sum(n) FROM recent) AS share_now,
                       coalesce(b.n::float / nullif((SELECT sum(n) FROM base), 0), 0) AS share_base
                FROM recent r LEFT JOIN base b USING (country)
                ORDER BY share_now DESC LIMIT 1"""), {"a": asset_id})).first()
            if geo and geo.share_now - geo.share_base >= thresholds["geo_shift"]:
                c.signals.append(Signal("geolocation_shift", "ddos", 5, 0.6,
                                        {"country": geo.country,
                                         "share_now": round(geo.share_now, 2),
                                         "share_baseline": round(geo.share_base, 2)}))
            out.append(c)
        if stats.bots_5m >= thresholds["bot_spike_5m"]:
            b = Candidate(correlation_key(tenant_id, asset_id, "bot", hour), "bot",
                          "Bot activity spike", asset_id, first_seen=now, last_seen=now)
            b.signals.append(Signal("bot_spike", "bot", 5, 0.7, {"bot_events_5m": stats.bots_5m}))
            out.append(b)

    # --- repeat offenders ------------------------------------------------------------
    rows = (await s.execute(text("""
        SELECT host(src_ip) AS ip, asset_id, count(DISTINCT category) AS cats, count(*) AS n,
               min("timestamp") AS first_seen, max("timestamp") AS last_seen
        FROM security_events
        WHERE src_ip IS NOT NULL AND category NOT IN ('info')
          AND "timestamp" > now() - interval '1 hour'
        GROUP BY src_ip, asset_id HAVING count(DISTINCT category) >= :c
    """), {"c": thresholds["repeat_offender_categories_1h"]})).all()
    for r in rows:
        c = Candidate(correlation_key(tenant_id, r.asset_id, "web_attack", _net(r.ip),
                                      now.date().isoformat()), "web_attack",
                      f"Repeated abuse from {r.ip}", r.asset_id, first_seen=r.first_seen,
                      last_seen=r.last_seen)
        c.sources.add(r.ip)
        c.signals.append(Signal("repeat_offender", "web_attack", 6, 0.8,
                                {"categories_1h": r.cats, "events_1h": r.n}))
        out.append(c)
    return out


def merge(cands: dict[str, Candidate], extra: list[Candidate]) -> dict[str, Candidate]:
    for c in extra:
        if c.correlation_key in cands:
            existing = cands[c.correlation_key]
            names = {s.name for s in existing.signals}
            existing.signals.extend(s for s in c.signals if s.name not in names)
            existing.sources |= c.sources
        else:
            cands[c.correlation_key] = c
    return cands


def summarize_signals(signals: list[Signal]) -> list[dict]:
    """Collapse per-event signals: keep one entry per signal name with counts."""
    grouped: dict[str, dict] = defaultdict(lambda: {"count": 0})
    for s in signals:
        g = grouped[s.name]
        g.update({"name": s.name, "category": s.category,
                  "severity": max(g.get("severity", 0), s.severity),
                  "confidence": max(g.get("confidence", 0.0), round(s.confidence, 3)),
                  "evidence": s.evidence})
        g["count"] += 1
    return sorted(grouped.values(), key=lambda g: (-g["severity"], -g["count"]))[:25]
