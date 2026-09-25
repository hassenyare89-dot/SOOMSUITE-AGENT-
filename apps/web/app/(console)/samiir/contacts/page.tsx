"use client";

import * as React from "react";
import { PageHeader } from "@/components/page";
import { ResourceTable } from "@/components/resource-table";
import { Input } from "@/components/ui/input";
import { fmtDate } from "@/lib/utils";

type Contact = { id: string; full_name: string | null; email: string | null; phone: string | null;
  preferred_channel: string | null; source: string | null; consent: Record<string, unknown>;
  last_interaction_at: string | null };

export default function Contacts() {
  const [q, setQ] = React.useState("");
  const [query, setQuery] = React.useState("");
  return (
    <div>
      <PageHeader title="Contacts" description="PII is encrypted at rest; search by exact email or phone uses keyed blind indexes."
        actions={<form onSubmit={(e) => { e.preventDefault(); setQuery(q); }}>
          <Input value={q} onChange={(e) => setQ(e.target.value)} placeholder="Name, email or phone" aria-label="Search" />
        </form>} />
      <ResourceTable<Contact> path={`/v1/admin/crm/contacts${query ? `?q=${encodeURIComponent(query)}` : ""}`}
        rowKey={(r) => r.id} columns={[
          { key: "name", header: "Name", render: (r) => r.full_name ?? "—" },
          { key: "email", header: "Email", render: (r) => r.email ?? "—" },
          { key: "phone", header: "Phone", render: (r) => r.phone ?? "—" },
          { key: "channel", header: "Preferred", render: (r) => r.preferred_channel ?? "—" },
          { key: "consent", header: "Consent", render: (r) => Object.entries(r.consent).filter(([k, v]) => v === true && k !== "history").map(([k]) => k).join(", ") || "—" },
          { key: "source", header: "Source", render: (r) => r.source ?? "—" },
          { key: "last", header: "Last interaction", render: (r) => fmtDate(r.last_interaction_at) },
        ]} />
    </div>
  );
}
