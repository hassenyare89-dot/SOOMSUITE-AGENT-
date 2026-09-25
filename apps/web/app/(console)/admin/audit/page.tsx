"use client";

import * as React from "react";
import { PageHeader } from "@/components/page";
import { ResourceTable } from "@/components/resource-table";
import { RiskBadge, StatusBadge } from "@/components/status";
import { Button } from "@/components/ui/button";
import { Input, Select } from "@/components/ui/input";
import { api } from "@/lib/api";
import { fmtDate } from "@/lib/utils";

type Log = { id: string; seq: number; actor_type: string; actor_id: string; agent_name: string | null;
  service: string; tool_name: string | null; action: string; target_type: string | null; target_id: string | null;
  result: string; risk_level: string | null; approval_id: string | null; source_ip: string | null;
  metadata_redacted: Record<string, unknown>; entry_hash: string; created_at: string };

export default function Audit() {
  const [action, setAction] = React.useState("");
  const [agent, setAgent] = React.useState("");
  const [verify, setVerify] = React.useState<string | null>(null);
  const qs = new URLSearchParams();
  if (action) qs.set("action", action);
  if (agent) qs.set("agent_name", agent);
  return (
    <div>
      <PageHeader title="Audit log" description="Append-only, per-tenant hash chain. Secrets and PII are redacted before storage."
        actions={<>
          <Input value={action} onChange={(e) => setAction(e.target.value)} placeholder="Action prefix" aria-label="Action" />
          <Select value={agent} onChange={(e) => setAgent(e.target.value)} aria-label="Agent"><option value="">All actors</option><option>SAMIIR</option><option>FATMA</option></Select>
          <Button variant="outline" onClick={async () => {
            const r = await api<{ valid: boolean; entries: number; broken_at_seq?: number }>("/v1/admin/audit/verify");
            setVerify(r.valid ? `Chain valid (${r.entries} entries)` : `Chain BROKEN at seq ${r.broken_at_seq}`);
          }}>Verify chain</Button></>} />
      {verify ? <p className="mb-3 text-sm">{verify}</p> : null}
      <ResourceTable<Log> path={`/v1/admin/audit/logs${qs.size ? `?${qs}` : ""}`} rowKey={(r) => r.id} columns={[
        { key: "seq", header: "#", render: (r) => <span className="tabular">{r.seq}</span> },
        { key: "time", header: "Time", render: (r) => fmtDate(r.created_at) },
        { key: "actor", header: "Actor", render: (r) => <span className="text-xs">{r.agent_name ?? r.actor_type}:{r.actor_id.slice(0, 12)}</span> },
        { key: "svc", header: "Service", render: (r) => r.service },
        { key: "action", header: "Action", render: (r) => <span className="font-mono text-xs">{r.action}{r.tool_name ? ` (${r.tool_name})` : ""}</span> },
        { key: "target", header: "Target", render: (r) => <span className="text-xs">{r.target_type ?? "—"} {r.target_id?.slice(0, 8)}</span> },
        { key: "result", header: "Result", render: (r) => <StatusBadge value={r.result} /> },
        { key: "risk", header: "Risk", render: (r) => <RiskBadge level={r.risk_level} /> },
        { key: "meta", header: "Details", render: (r) => <span className="block max-w-72 truncate font-mono text-xs" title={JSON.stringify(r.metadata_redacted)}>{JSON.stringify(r.metadata_redacted)}</span> },
      ]} />
    </div>
  );
}
