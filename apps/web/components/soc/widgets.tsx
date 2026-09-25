"use client";

import Link from "next/link";
import { ColumnChart, SeverityBars, StackedColumns, type StackRow } from "@/components/charts/charts";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { StatTile } from "@/components/page";
import { fmtDate, fmtDuration } from "@/lib/utils";

export type Overview = {
  fatma_mode: string;
  active_incidents: Record<string, number>;
  critical_findings: number;
  vulnerabilities_by_severity: Record<string, number>;
  waf_blocked_24h: number;
  ddos_indicators_24h: { hour: string; count: number }[];
  event_timeline_24h: { hour: string; category: string; count: number }[];
  malware_detections_30d: number;
  suspicious_ips: { ip: string; events: number; max_severity: number; categories: string[] }[];
  recent_scans: { id: string; status: string; profile: string; target: string; created_at: string; findings: number }[];
  assets_at_risk: { id: string; name: string; risk_score: number; open_incidents: number }[];
  risk_score: number;
  pending_recommendations: number;
  mean_time_to_acknowledge_seconds: number | null;
  mean_time_to_remediate_seconds: number | null;
  unresolved_incidents: number;
  confirmed_incidents: number;
};

const hourLabel = (iso: string) => new Date(iso).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });

export function timelineRows(o: Overview): { rows: StackRow[]; series: string[] } {
  const totals = new Map<string, number>();
  const byHour = new Map<string, Record<string, number>>();
  for (const p of o.event_timeline_24h) {
    totals.set(p.category, (totals.get(p.category) ?? 0) + p.count);
    const row = byHour.get(p.hour) ?? {};
    row[p.category] = (row[p.category] ?? 0) + p.count;
    byHour.set(p.hour, row);
  }
  // Fixed, entity-stable order: categories sorted by name (not rank) so filtering never
  // repaints survivors; the chart folds everything past four into "Other".
  const series = [...totals.keys()].sort();
  return { rows: [...byHour.entries()].map(([h, values]) => ({ label: hourLabel(h), values })), series };
}

export function SocWidgets({ o }: { o: Overview }) {
  const active = Object.values(o.active_incidents).reduce((a, b) => a + b, 0);
  const { rows, series } = timelineRows(o);
  return (
    <div className="space-y-4">
      <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
        <StatTile label="Active incidents" value={active}
                  hint={`${o.active_incidents.CRITICAL ?? 0} critical · ${o.active_incidents["HIGH RISK"] ?? 0} high risk`} />
        <StatTile label="Risk score" value={`${o.risk_score}/100`} hint="Highest open incident" />
        <StatTile label="Critical findings" value={o.critical_findings} />
        <StatTile label="WAF blocked (24h)" value={o.waf_blocked_24h} />
        <StatTile label="Malware detections (30d)" value={o.malware_detections_30d} />
        <StatTile label="Unresolved incidents" value={o.unresolved_incidents}
                  hint={`${o.confirmed_incidents} human-confirmed`} />
        <StatTile label="Time to acknowledge" value={fmtDuration(o.mean_time_to_acknowledge_seconds)} hint="Mean" />
        <StatTile label="Time to remediate" value={fmtDuration(o.mean_time_to_remediate_seconds)} hint="Mean" />
      </div>
      <div className="grid gap-4 lg:grid-cols-3">
        <Card className="lg:col-span-2">
          <CardHeader><CardTitle>Security events by category (24h)</CardTitle>
            <CardDescription>Excludes informational events</CardDescription></CardHeader>
          <CardContent><StackedColumns rows={rows} series={series} /></CardContent>
        </Card>
        <Card>
          <CardHeader><CardTitle>Vulnerabilities by severity</CardTitle>
            <CardDescription>Open findings, excluding false positives</CardDescription></CardHeader>
          <CardContent><SeverityBars counts={o.vulnerabilities_by_severity} /></CardContent>
        </Card>
      </div>
      <div className="grid gap-4 lg:grid-cols-3">
        <Card>
          <CardHeader><CardTitle>DDoS / flood indicators (24h)</CardTitle></CardHeader>
          <CardContent>
            <ColumnChart unit="indicator events"
                         data={o.ddos_indicators_24h.map((d) => ({ label: hourLabel(d.hour), value: d.count }))} />
          </CardContent>
        </Card>
        <Card>
          <CardHeader><CardTitle>Suspicious IPs (24h)</CardTitle></CardHeader>
          <CardContent>
            <ul className="space-y-1 text-sm">
              {o.suspicious_ips.length === 0 ? <li className="text-subtle">None</li> : null}
              {o.suspicious_ips.map((ip) => (
                <li key={ip.ip} className="flex justify-between gap-2">
                  <span className="font-mono text-xs">{ip.ip}</span>
                  <span className="truncate text-xs text-muted">{ip.categories.join(", ")}</span>
                  <span className="tabular text-xs">{ip.events}</span>
                </li>
              ))}
            </ul>
          </CardContent>
        </Card>
        <Card>
          <CardHeader><CardTitle>Assets at risk</CardTitle></CardHeader>
          <CardContent>
            <ul className="space-y-1 text-sm">
              {o.assets_at_risk.length === 0 ? <li className="text-subtle">None</li> : null}
              {o.assets_at_risk.map((a) => (
                <li key={a.id} className="flex justify-between">
                  <span>{a.name}</span><span className="tabular text-xs text-muted">{a.risk_score}/100 · {a.open_incidents} open</span>
                </li>
              ))}
            </ul>
            <p className="mt-4 text-xs font-medium text-muted">Recent scans</p>
            <ul className="mt-1 space-y-1 text-xs">
              {o.recent_scans.map((s) => (
                <li key={s.id} className="flex justify-between">
                  <Link href="/fatma/scans" className="underline">{s.target}</Link>
                  <span className="text-muted">{s.status} · {fmtDate(s.created_at)}</span>
                </li>
              ))}
            </ul>
          </CardContent>
        </Card>
      </div>
      <p className="text-xs text-muted">
        FATMA mode: <strong>{o.fatma_mode.replaceAll("_", " ")}</strong> · {o.pending_recommendations} pending
        recommendation(s). Incidents remain SUSPECTED until a security engineer confirms them with
        recorded evidence.
      </p>
    </div>
  );
}
