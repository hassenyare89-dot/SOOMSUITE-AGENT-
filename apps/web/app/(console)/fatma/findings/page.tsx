"use client";

import * as React from "react";
import { Can } from "@/components/session";
import { ErrorNote, PageHeader } from "@/components/page";
import { ResourceTable } from "@/components/resource-table";
import { RiskBadge } from "@/components/status";
import { Select } from "@/components/ui/input";
import { api } from "@/lib/api";
import { fmtDate } from "@/lib/utils";

type Finding = { id: string; title: string; severity: string; scanner: string; rule_id: string;
  url: string | null; cwe: string | null; false_positive_status: string; remediation_status: string;
  last_seen: string; remediation: string | null };

export default function Findings() {
  const [sev, setSev] = React.useState("");
  const [tick, setTick] = React.useState(0);
  const [err, setErr] = React.useState<string | null>(null);
  async function patch(id: string, body: Record<string, string>) {
    setErr(null);
    try { await api(`/v1/admin/fatma/findings/${id}`, { method: "PATCH", json: body }); setTick((t) => t + 1); }
    catch (e) { setErr(e instanceof Error ? e.message : "Failed"); }
  }
  return (
    <div>
      <PageHeader title="Vulnerability findings" description="Normalized findings from ZAP and Nuclei (safe profiles) and external scanners."
        actions={<Select value={sev} onChange={(e) => setSev(e.target.value)} aria-label="Severity">
          <option value="">All severities</option>{["critical", "high", "medium", "low", "info"].map((s) => <option key={s}>{s}</option>)}</Select>} />
      <ErrorNote error={err} />
      <ResourceTable<Finding> path={`/v1/admin/fatma/findings${sev ? `?severity=${sev}` : ""}`} rowKey={(r) => r.id} reloadSignal={tick} columns={[
        { key: "sev", header: "Severity", render: (r) => <RiskBadge level={r.severity} /> },
        { key: "title", header: "Finding", render: (r) => <><p>{r.title}</p><p className="font-mono text-xs text-muted">{r.scanner}:{r.rule_id} {r.cwe ?? ""}</p></> },
        { key: "url", header: "Location", render: (r) => <span className="block max-w-64 truncate font-mono text-xs">{r.url ?? "—"}</span> },
        { key: "fp", header: "Review", render: (r) => <Can perm="finding:review"><Select className="h-8 text-xs" value={r.false_positive_status} onChange={(e) => void patch(r.id, { false_positive_status: e.target.value })}>
          {["UNREVIEWED", "CONFIRMED_TRUE", "FALSE_POSITIVE", "ACCEPTED_RISK"].map((s) => <option key={s}>{s}</option>)}</Select></Can> },
        { key: "rem", header: "Remediation", render: (r) => <Can perm="finding:review"><Select className="h-8 text-xs" value={r.remediation_status} onChange={(e) => void patch(r.id, { remediation_status: e.target.value })}>
          {["OPEN", "IN_PROGRESS", "REMEDIATED", "VERIFIED", "WONT_FIX"].map((s) => <option key={s}>{s}</option>)}</Select></Can> },
        { key: "seen", header: "Last seen", render: (r) => fmtDate(r.last_seen) },
      ]} />
    </div>
  );
}
