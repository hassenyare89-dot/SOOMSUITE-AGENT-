"use client";

import Link from "next/link";
import * as React from "react";
import { PageHeader } from "@/components/page";
import { ResourceTable } from "@/components/resource-table";
import { ClaimBadge, RiskBadge, StatusBadge } from "@/components/status";
import { Button } from "@/components/ui/button";
import { useRealtime } from "@/lib/api";
import { fmtDate } from "@/lib/utils";

type Inc = { id: string; title: string; category: string; risk_level: string; risk_score: number;
  claim_status: string; status: string; event_count: number; last_seen: string };

export default function Incidents() {
  const [open, setOpen] = React.useState(true);
  const [tick, setTick] = React.useState(0);
  useRealtime("fatma", ["incident.updated"], () => setTick((t) => t + 1));
  return (
    <div>
      <PageHeader title="Incidents" description="Correlated incidents with deterministic risk scoring. FATMA never marks a breach as confirmed."
        actions={<Button variant="outline" onClick={() => setOpen(!open)}>{open ? "Show all" : "Open only"}</Button>} />
      <ResourceTable<Inc> path={`/v1/admin/fatma/incidents?open_only=${open}`} rowKey={(r) => r.id} reloadSignal={tick} columns={[
        { key: "title", header: "Incident", render: (r) => <Link className="underline" href={`/fatma/incidents/${r.id}`}>{r.title}</Link> },
        { key: "risk", header: "Risk", render: (r) => <span className="inline-flex items-center gap-2"><RiskBadge level={r.risk_level} /><span className="tabular text-xs text-muted">{r.risk_score}</span></span> },
        { key: "claim", header: "Claim", render: (r) => <ClaimBadge claim={r.claim_status} /> },
        { key: "status", header: "Status", render: (r) => <StatusBadge value={r.status} /> },
        { key: "events", header: "Events", render: (r) => <span className="tabular">{r.event_count}</span> },
        { key: "last", header: "Last seen", render: (r) => fmtDate(r.last_seen) },
      ]} />
    </div>
  );
}
