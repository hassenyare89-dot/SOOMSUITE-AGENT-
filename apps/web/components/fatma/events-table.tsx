"use client";

import * as React from "react";
import { ResourceTable } from "@/components/resource-table";
import { RiskBadge } from "@/components/status";
import { useRealtime } from "@/lib/api";
import { fmtDate } from "@/lib/utils";

type Ev = { event_id: string; source: string; category: string; event_type: string; severity: number;
  confidence: number; timestamp: string; src_ip: string | null; request_path: string | null;
  country: string | null; action_taken: string | null; risk: string | null; rule_id: string | null };

export function EventsTable({ query = "" }: { query?: string }) {
  const [tick, setTick] = React.useState(0);
  useRealtime("fatma", ["incident.updated"], () => setTick((t) => t + 1));
  return (
    <ResourceTable<Ev> path={`/v1/admin/fatma/events${query}`} rowKey={(r) => r.event_id} reloadSignal={tick}
      columns={[
        { key: "time", header: "Time", render: (r) => fmtDate(r.timestamp) },
        { key: "src", header: "Source", render: (r) => r.source },
        { key: "cat", header: "Category", render: (r) => r.category },
        { key: "type", header: "Type", render: (r) => <span className="font-mono text-xs">{r.event_type}</span> },
        { key: "sev", header: "Sev", render: (r) => <span className="tabular">{r.severity}</span> },
        { key: "ip", header: "Source IP", render: (r) => <span className="font-mono text-xs">{r.src_ip ?? "—"}</span> },
        { key: "cc", header: "Country", render: (r) => r.country ?? "—" },
        // Attacker-controlled path: rendered as text, truncated, never interpreted.
        { key: "path", header: "Path", render: (r) => <span className="block max-w-72 truncate font-mono text-xs" title={r.request_path ?? ""}>{r.request_path ?? "—"}</span> },
        { key: "act", header: "Action", render: (r) => r.action_taken ?? "—" },
        { key: "risk", header: "Risk", render: (r) => <RiskBadge level={r.risk} /> },
      ]} />
  );
}
