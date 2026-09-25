"use client";

import * as React from "react";
import { ErrorNote, PageHeader } from "@/components/page";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input, Label, Select, Textarea } from "@/components/ui/input";
import { api, useApi } from "@/lib/api";

type Tenant = { id: string; name: string; slug: string; timezone: string; users: number;
  settings: { fatma_mode?: string; preapproved_actions?: string[]; appointment_rules?: unknown } };
type Widget = { id: string; name: string; public_key: string; allowed_origins: string[]; active: boolean };
const LOW = ["defense.challenge_ip", "defense.temp_block_ip", "defense.rate_limit_path", "defense.revoke_app_session"];

export default function TenantPage() {
  const t = useApi<Tenant>("/v1/admin/identity/tenant");
  const w = useApi<Widget[]>("/v1/admin/identity/widgets");
  const [err, setErr] = React.useState<string | null>(null);
  const [rules, setRules] = React.useState("");
  const [widget, setWidget] = React.useState({ name: "", origins: "" });
  React.useEffect(() => { if (t.data) setRules(JSON.stringify(t.data.settings.appointment_rules ?? {}, null, 2)); }, [t.data]);
  async function save(body: unknown) {
    setErr(null);
    try { await api("/v1/admin/identity/tenant", { method: "PATCH", json: body }); await t.reload(); }
    catch (e) { setErr(e instanceof Error ? e.message : "Failed"); }
  }
  const s = t.data?.settings;
  return (
    <div className="space-y-6">
      <PageHeader title="Tenant" description={t.data ? `${t.data.name} (${t.data.slug}) · ${t.data.users} users · ${t.data.timezone}` : undefined} />
      <ErrorNote error={t.error ?? err} />
      <Card><CardHeader><CardTitle>FATMA defensive mode</CardTitle>
        <CardDescription>Recommend-only is the default. Pre-approval covers only time-boxed, single-target low-risk actions with high-confidence evidence. High-risk actions always need a human.</CardDescription></CardHeader>
        <CardContent className="space-y-3">
          <Select value={s?.fatma_mode ?? "recommend_only"} onChange={(e) => void save({ fatma_mode: e.target.value })} aria-label="FATMA mode">
            <option value="recommend_only">Recommend only</option><option value="preapproved_low_risk">Pre-approved low-risk actions</option></Select>
          <div className="flex flex-wrap gap-3 text-sm">{LOW.map((a) => (
            <label key={a} className="flex items-center gap-1"><input type="checkbox" checked={s?.preapproved_actions?.includes(a) ?? false}
              onChange={(e) => void save({ preapproved_actions: e.target.checked ? [...(s?.preapproved_actions ?? []), a] : (s?.preapproved_actions ?? []).filter((x) => x !== a) })} />{a}</label>))}</div>
        </CardContent></Card>
      <Card><CardHeader><CardTitle>Appointment rules</CardTitle><CardDescription>business_timezone, working_hours, min_notice_minutes, max_days_ahead, slot_step_minutes, holidays</CardDescription></CardHeader>
        <CardContent className="space-y-2"><Textarea className="font-mono text-xs" value={rules} onChange={(e) => setRules(e.target.value)} />
          <Button onClick={() => { try { void save({ appointment_rules: JSON.parse(rules) }); } catch { setErr("Invalid JSON"); } }}>Save rules</Button></CardContent></Card>
      <Card><CardHeader><CardTitle>Chat widget embeds</CardTitle><CardDescription>The widget can only be framed by these exact origins (CSP frame-ancestors).</CardDescription></CardHeader>
        <CardContent className="space-y-3">
          <ul className="space-y-2 text-sm">{w.data?.map((x) => (
            <li key={x.id}><p className="font-medium">{x.name}</p><p className="text-xs text-muted">{x.allowed_origins.join(", ")}</p>
              <pre className="mt-1 overflow-x-auto rounded bg-background p-2 text-xs">{`<script src="${typeof window !== "undefined" ? window.location.origin : ""}/widget/loader.js" data-key="${x.public_key}" async></script>`}</pre></li>))}</ul>
          <div className="grid gap-2 md:grid-cols-3">
            <div><Label>Name</Label><Input value={widget.name} onChange={(e) => setWidget({ ...widget, name: e.target.value })} /></div>
            <div className="md:col-span-2"><Label>Allowed origins (comma separated)</Label><Input value={widget.origins} placeholder="https://www.example.com" onChange={(e) => setWidget({ ...widget, origins: e.target.value })} /></div>
          </div>
          <Button onClick={async () => { setErr(null); try {
            await api("/v1/admin/identity/widgets", { method: "POST", json: { name: widget.name, allowed_origins: widget.origins.split(",").map((o) => o.trim()).filter(Boolean) } });
            await w.reload(); } catch (e) { setErr(e instanceof Error ? e.message : "Failed"); } }}>Create widget</Button>
        </CardContent></Card>
    </div>
  );
}
