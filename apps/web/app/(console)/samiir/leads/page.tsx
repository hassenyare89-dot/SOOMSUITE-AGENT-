"use client";

import { PageHeader } from "@/components/page";
import { ResourceTable } from "@/components/resource-table";
import { StatusBadge } from "@/components/status";
import { fmtDate } from "@/lib/utils";

type Opp = { id: string; title: string; stage: string; source: string | null;
  service_interest: string | null; last_interaction_at: string | null; created_at: string };

export default function Leads() {
  return (
    <div>
      <PageHeader title="Leads" description="New and qualified leads captured by SAMIIR and staff." />
      <ResourceTable<Opp> path="/v1/admin/crm/opportunities?leads_only=true" rowKey={(r) => r.id} columns={[
        { key: "title", header: "Lead", render: (r) => r.title },
        { key: "stage", header: "Stage", render: (r) => <StatusBadge value={r.stage} /> },
        { key: "interest", header: "Service interest", render: (r) => r.service_interest ?? "—" },
        { key: "source", header: "Source", render: (r) => r.source ?? "—" },
        { key: "last", header: "Last interaction", render: (r) => fmtDate(r.last_interaction_at) },
        { key: "created", header: "Created", render: (r) => fmtDate(r.created_at) },
      ]} />
    </div>
  );
}
