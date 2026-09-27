"use client";

import * as React from "react";
import { Can } from "@/components/session";
import { ErrorNote, PageHeader } from "@/components/page";
import { ResourceTable } from "@/components/resource-table";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { api } from "@/lib/api";
import { fmtDate } from "@/lib/utils";

type Company = { id: string; name: string; domain: string | null; industry: string | null;
  size_band: string | null; created_at: string };

export default function Companies() {
  const [name, setName] = React.useState("");
  const [tick, setTick] = React.useState(0);
  const [err, setErr] = React.useState<string | null>(null);
  return (
    <div>
      <PageHeader title="Companies" actions={<Can perm="crm:write">
        <form className="flex gap-2" onSubmit={async (e) => {
          e.preventDefault(); setErr(null);
          try { await api("/v1/admin/crm/companies", { method: "POST", json: { name } }); setName(""); setTick(tick + 1); }
          catch (x) { setErr(x instanceof Error ? x.message : "Failed"); }
        }}>
          <Input value={name} onChange={(e) => setName(e.target.value)} placeholder="Company name" aria-label="Company name" />
          <Button disabled={name.length < 1}>Add</Button>
        </form></Can>} />
      <ErrorNote error={err} />
      <ResourceTable<Company> path="/v1/admin/crm/companies" rowKey={(r) => r.id} reloadSignal={tick} columns={[
        { key: "name", header: "Name", render: (r) => r.name },
        { key: "domain", header: "Domain", render: (r) => r.domain ?? "—" },
        { key: "industry", header: "Industry", render: (r) => r.industry ?? "—" },
        { key: "size", header: "Size", render: (r) => r.size_band ?? "—" },
        { key: "created", header: "Created", render: (r) => fmtDate(r.created_at) },
      ]} />
    </div>
  );
}
