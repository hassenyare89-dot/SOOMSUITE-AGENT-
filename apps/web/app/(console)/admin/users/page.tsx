"use client";

import * as React from "react";
import { ErrorNote, PageHeader } from "@/components/page";
import { StatusBadge } from "@/components/status";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input, Label } from "@/components/ui/input";
import { Table, TBody, TD, TH, THead, TR } from "@/components/ui/table";
import { api, useApi } from "@/lib/api";

const ROLES = ["sales_agent", "support_agent", "security_analyst", "security_engineer", "tenant_admin"];
type U = { id: string; display_name: string; email: string | null; status: string; roles: string[]; external_subject: string };

export default function Users() {
  const { data, error, reload } = useApi<U[]>("/v1/admin/identity/users");
  const [err, setErr] = React.useState<string | null>(null);
  const [form, setForm] = React.useState({ name: "", email: "", subject: "", roles: [] as string[] });
  async function act(fn: () => Promise<unknown>) {
    setErr(null);
    try { await fn(); await reload(); } catch (e) { setErr(e instanceof Error ? e.message : "Failed"); }
  }
  const toggle = (list: string[], r: string) => (list.includes(r) ? list.filter((x) => x !== r) : [...list, r]);
  return (
    <div>
      <PageHeader title="Users" description="Users authenticate via SSO; MFA/passkeys are enforced for privileged permissions." />
      <ErrorNote error={error ?? err} />
      <Card className="mb-6"><CardHeader><CardTitle>Invite user</CardTitle></CardHeader>
        <CardContent className="grid gap-3 md:grid-cols-3">
          <div><Label>Display name</Label><Input value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} /></div>
          <div><Label>Email</Label><Input value={form.email} onChange={(e) => setForm({ ...form, email: e.target.value })} /></div>
          <div><Label>IdP subject</Label><Input value={form.subject} onChange={(e) => setForm({ ...form, subject: e.target.value })} /></div>
          <div className="flex flex-wrap gap-3 text-sm md:col-span-3">{ROLES.map((r) => (
            <label key={r} className="flex items-center gap-1"><input type="checkbox" checked={form.roles.includes(r)} onChange={() => setForm({ ...form, roles: toggle(form.roles, r) })} />{r}</label>))}</div>
          <div><Button onClick={() => act(() => api("/v1/admin/identity/users", { method: "POST", json: { display_name: form.name, email: form.email, external_subject: form.subject, roles: form.roles } }))}>Invite</Button></div>
        </CardContent></Card>
      <Table><THead><tr><TH>Name</TH><TH>Email</TH><TH>Roles</TH><TH>Status</TH><TH></TH></tr></THead>
        <TBody>{data?.map((u) => (
          <TR key={u.id}><TD>{u.display_name}<p className="font-mono text-xs text-muted">{u.external_subject}</p></TD><TD>{u.email}</TD>
            <TD><div className="flex flex-wrap gap-2 text-xs">{ROLES.map((r) => (
              <label key={r} className="flex items-center gap-1"><input type="checkbox" checked={u.roles.includes(r)}
                onChange={() => act(() => api(`/v1/admin/identity/users/${u.id}/roles`, { method: "PUT", json: { roles: toggle(u.roles, r) } }))} />{r}</label>))}</div></TD>
            <TD><StatusBadge value={u.status} /></TD>
            <TD>{u.status === "active" ? <Button size="sm" variant="outline" onClick={() => act(() => api(`/v1/admin/identity/users/${u.id}/disable`, { method: "POST" }))}>Disable</Button> : null}</TD></TR>
        ))}</TBody></Table>
    </div>
  );
}
