"use client";

import * as React from "react";
import { ErrorNote, PageHeader } from "@/components/page";
import { StatusBadge } from "@/components/status";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input, Label, Select, Textarea } from "@/components/ui/input";
import { Table, TBody, TD, TH, THead, TR } from "@/components/ui/table";
import { api, useApi } from "@/lib/api";

const KINDS = ["calendar.google", "calendar.microsoft365", "whatsapp.cloud", "defense.cloudflare",
  "defense.aws_waf", "ingest.cloudflare", "ingest.aws_waf", "ingest.siem", "ingest.app_log",
  "ingest.proxy", "ingest.auth", "ingest.scanner", "ingest.malware", "email.smtp"];
type I = { id: string; kind: string; name: string; external_key: string | null; secret_ref: string | null; config: Record<string, unknown>; status: string };

export default function Integrations() {
  const { data, error, reload } = useApi<I[]>("/v1/admin/identity/integrations");
  const [err, setErr] = React.useState<string | null>(null);
  const [f, setF] = React.useState({ kind: "whatsapp.cloud", name: "", external_key: "", secret_ref: "", config: "{}" });
  return (
    <div>
      <PageHeader title="Integrations" description="Credentials are never entered here. Store them in the secret manager and reference them (vault://, aws-sm://, file://)." />
      <ErrorNote error={error ?? err} />
      <Card className="mb-6"><CardHeader><CardTitle>Add integration</CardTitle>
        <CardDescription>Ingest integrations get a generated key id; webhook URL: /v1/ingest/&lt;source&gt;/&lt;key id&gt;</CardDescription></CardHeader>
        <CardContent className="grid gap-3 md:grid-cols-2">
          <div><Label>Kind</Label><Select value={f.kind} onChange={(e) => setF({ ...f, kind: e.target.value })}>{KINDS.map((k) => <option key={k}>{k}</option>)}</Select></div>
          <div><Label>Name</Label><Input value={f.name} onChange={(e) => setF({ ...f, name: e.target.value })} /></div>
          <div><Label>External key (e.g. WhatsApp phone_number_id)</Label><Input value={f.external_key} onChange={(e) => setF({ ...f, external_key: e.target.value })} /></div>
          <div><Label>Secret reference</Label><Input value={f.secret_ref} placeholder="vault://kv/tenants/acme/whatsapp#token" onChange={(e) => setF({ ...f, secret_ref: e.target.value })} /></div>
          <div className="md:col-span-2"><Label>Non-secret config (JSON)</Label><Textarea className="font-mono text-xs" value={f.config} onChange={(e) => setF({ ...f, config: e.target.value })} /></div>
          <div><Button onClick={async () => { setErr(null); try {
            await api("/v1/admin/identity/integrations", { method: "POST", json: { kind: f.kind, name: f.name,
              external_key: f.external_key || null, secret_ref: f.secret_ref || null, config: JSON.parse(f.config || "{}") } });
            await reload(); } catch (e) { setErr(e instanceof Error ? e.message : "Failed"); } }}>Add</Button></div>
        </CardContent></Card>
      <Table><THead><tr><TH>Kind</TH><TH>Name</TH><TH>Key</TH><TH>Secret reference</TH><TH>Status</TH><TH></TH></tr></THead>
        <TBody>{data?.map((i) => (
          <TR key={i.id}><TD className="font-mono text-xs">{i.kind}</TD><TD>{i.name}</TD><TD className="font-mono text-xs">{i.external_key ?? "—"}</TD>
            <TD className="font-mono text-xs">{i.secret_ref ?? "—"}</TD><TD><StatusBadge value={i.status} /></TD>
            <TD>{i.status === "active" ? <Button size="sm" variant="outline" onClick={async () => { await api(`/v1/admin/identity/integrations/${i.id}/disable`, { method: "POST" }); await reload(); }}>Disable</Button> : null}</TD></TR>
        ))}</TBody></Table>
    </div>
  );
}
