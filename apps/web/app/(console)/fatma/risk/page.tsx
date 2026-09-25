"use client";

import { PageHeader, StatTile } from "@/components/page";
import { SeverityBars } from "@/components/charts/charts";
import { RiskBadge } from "@/components/status";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Table, TBody, TD, TH, THead, TR } from "@/components/ui/table";
import { type Overview } from "@/components/soc/widgets";
import { useApi } from "@/lib/api";

type AssetRisk = { id: string; name: string; canonical_target: string; criticality: number;
  risk_score: number; open_findings: number; verification_status: string };

const level = (s: number) => (s >= 75 ? "CRITICAL" : s >= 50 ? "HIGH RISK" : s >= 25 ? "SUSPICIOUS" : "NORMAL");

export default function Risk() {
  const assets = useApi<AssetRisk[]>("/v1/admin/fatma/assets");
  const o = useApi<Overview>("/v1/admin/fatma/soc/overview");
  return (
    <div>
      <PageHeader title="Risk dashboard" description="Deterministic risk scores (0–100) per asset from open incidents and findings." />
      <div className="mb-6 grid grid-cols-2 gap-4 lg:grid-cols-4">
        <StatTile label="Tenant risk score" value={o.data ? `${o.data.risk_score}/100` : "—"} />
        <StatTile label="Critical incidents" value={o.data?.active_incidents.CRITICAL ?? 0} />
        <StatTile label="High-risk incidents" value={o.data?.active_incidents["HIGH RISK"] ?? 0} />
        <StatTile label="Critical findings" value={o.data?.critical_findings ?? 0} />
      </div>
      <div className="grid gap-4 lg:grid-cols-3">
        <Card className="lg:col-span-2"><CardHeader><CardTitle>Assets by risk</CardTitle></CardHeader>
          <CardContent>
            <Table><THead><tr><TH>Asset</TH><TH>Criticality</TH><TH>Risk</TH><TH>Open findings</TH><TH>Ownership</TH></tr></THead>
              <TBody>{assets.data?.map((a) => (
                <TR key={a.id}><TD>{a.name}<p className="font-mono text-xs text-muted">{a.canonical_target}</p></TD>
                  <TD className="tabular">{a.criticality}</TD>
                  <TD><span className="inline-flex items-center gap-2"><RiskBadge level={level(a.risk_score)} /><span className="tabular text-xs">{a.risk_score}</span></span></TD>
                  <TD className="tabular">{a.open_findings}</TD><TD>{a.verification_status}</TD></TR>
              ))}</TBody></Table>
          </CardContent></Card>
        <Card><CardHeader><CardTitle>Findings by severity</CardTitle></CardHeader>
          <CardContent>{o.data ? <SeverityBars counts={o.data.vulnerabilities_by_severity} /> : null}</CardContent></Card>
      </div>
    </div>
  );
}
