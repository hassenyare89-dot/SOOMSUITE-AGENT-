"use client";

import Link from "next/link";
import * as React from "react";
import { PageHeader } from "@/components/page";
import { ResourceTable } from "@/components/resource-table";
import { StatusBadge } from "@/components/status";
import { Select } from "@/components/ui/input";
import { useRealtime } from "@/lib/api";
import { fmtDate } from "@/lib/utils";

type Conv = { id: string; channel: string; status: string; contact_id: string | null;
  escalation_reason: string | null; last_message_at: string | null; created_at: string };

export default function Conversations() {
  const [status, setStatus] = React.useState("");
  const [tick, setTick] = React.useState(0);
  useRealtime("samiir", ["message.inbound", "conversation.escalated"], () => setTick((t) => t + 1));
  return (
    <div>
      <PageHeader title="Conversations" description="Website chat and WhatsApp conversations handled by SAMIIR."
        actions={<Select value={status} onChange={(e) => setStatus(e.target.value)} aria-label="Status filter">
          <option value="">All statuses</option><option>OPEN</option><option>ESCALATED</option>
          <option>HUMAN_HANDLING</option><option>CLOSED</option></Select>} />
      <ResourceTable<Conv> path={`/v1/admin/samiir/conversations${status ? `?status=${status}` : ""}`}
        rowKey={(r) => r.id} reloadSignal={tick} columns={[
          { key: "id", header: "Conversation", render: (r) => <Link className="underline" href={`/samiir/conversations/${r.id}`}>{r.id.slice(0, 8)}</Link> },
          { key: "channel", header: "Channel", render: (r) => r.channel },
          { key: "status", header: "Status", render: (r) => <StatusBadge value={r.status} /> },
          { key: "esc", header: "Escalation", render: (r) => r.escalation_reason ?? "—" },
          { key: "last", header: "Last message", render: (r) => fmtDate(r.last_message_at) },
        ]} />
    </div>
  );
}
