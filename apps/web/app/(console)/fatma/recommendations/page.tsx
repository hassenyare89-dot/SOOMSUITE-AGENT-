"use client";

import * as React from "react";
import { Can } from "@/components/session";
import { ErrorNote, PageHeader } from "@/components/page";
import { ResourceTable } from "@/components/resource-table";
import { RiskBadge, StatusBadge } from "@/components/status";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input, Label, Select, Textarea } from "@/components/ui/input";
import { api, useRealtime } from "@/lib/api";
import { fmtDate } from "@/lib/utils";

type Action = { id: string; action_type: string; target: string; status: string; risk_level: string;
  mode: string; rationale: string; ttl_seconds: number | null; expires_at: string | null;
  provider: string; approval_id: string | null; created_by: string; created_at: string };

const TYPES = ["challenge_ip", "temp_block_ip", "rate_limit_path", "revoke_app_session",
  "block_country", "disable_account", "rotate_credentials", "change_firewall_rule",
  "shutdown_service", "change_dns", "modify_infrastructure", "delete_data", "isolate_network_segment"];

export default function Recommendations() {
  const [tick, setTick] = React.useState(0);
  const [err, setErr] = React.useState<string | null>(null);
  const [form, setForm] = React.useState({ action_type: "challenge_ip", target: "", ttl: "900", rationale: "" });
  useRealtime("fatma", ["action.updated", "approval.decided"], () => setTick((t) => t + 1));
  async function act(fn: () => Promise<unknown>) {
    setErr(null);
    try { await fn(); setTick((t) => t + 1); } catch (e) { setErr(e instanceof Error ? e.message : "Failed"); }
  }
  return (
    <div>
      <PageHeader title="Security recommendations"
        description="FATMA only recommends. Execution requires an approval bound to the exact action payload (and a different approver for anything not pre-approved)." />
      <ErrorNote error={err} />
      <Can perm="defense:request">
        <Card className="mb-6">
          <CardHeader><CardTitle>Propose an action</CardTitle></CardHeader>
          <CardContent className="grid gap-3 md:grid-cols-4">
            <div><Label>Action</Label><Select value={form.action_type} onChange={(e) => setForm({ ...form, action_type: e.target.value })}>
              {TYPES.map((t) => <option key={t}>{t}</option>)}</Select></div>
            <div><Label>Target</Label><Input value={form.target} placeholder="IP, /path, country code…" onChange={(e) => setForm({ ...form, target: e.target.value })} /></div>
            <div><Label>TTL (seconds)</Label><Input value={form.ttl} inputMode="numeric" onChange={(e) => setForm({ ...form, ttl: e.target.value })} /></div>
            <div className="md:col-span-4"><Label>Rationale</Label><Textarea value={form.rationale} onChange={(e) => setForm({ ...form, rationale: e.target.value })} /></div>
            <div><Button onClick={() => act(() => api("/v1/admin/fatma/actions", { method: "POST", json: {
              action_type: form.action_type, target: form.target, ttl_seconds: Number(form.ttl) || null, rationale: form.rationale } }))}>Record recommendation</Button></div>
          </CardContent>
        </Card>
      </Can>
      <ResourceTable<Action> path="/v1/admin/fatma/actions" rowKey={(r) => r.id} reloadSignal={tick} columns={[
        { key: "a", header: "Action", render: (r) => <span className="font-mono text-xs">{r.action_type}</span> },
        { key: "t", header: "Target", render: (r) => <span className="font-mono text-xs">{r.target}</span> },
        { key: "r", header: "Risk", render: (r) => <RiskBadge level={r.risk_level} /> },
        { key: "s", header: "Status", render: (r) => <StatusBadge value={r.status} /> },
        { key: "m", header: "Mode", render: (r) => r.mode.replaceAll("_", " ") },
        { key: "why", header: "Rationale", render: (r) => <span className="block max-w-80 text-xs">{r.rationale}</span> },
        { key: "exp", header: "Expires", render: (r) => fmtDate(r.expires_at) },
        { key: "by", header: "Proposed by", render: (r) => r.created_by.startsWith("agent:") ? r.created_by : "staff" },
        { key: "x", header: "", render: (r) => (
          <div className="flex gap-1">
            {r.status === "RECOMMENDED" ? <Can perm="defense:request">
              <Button size="sm" onClick={() => act(() => api(`/v1/admin/fatma/actions/${r.id}/request-approval`, { method: "POST" }))}>Request approval</Button>
              <Button size="sm" variant="outline" onClick={() => act(() => api(`/v1/admin/fatma/actions/${r.id}/dismiss`, { method: "POST" }))}>Dismiss</Button>
            </Can> : null}
            {r.status === "PENDING_APPROVAL" ? <Can perm="defense:execute">
              <Button size="sm" variant="destructive" onClick={() => act(() => api(`/v1/admin/fatma/actions/${r.id}/execute`, { method: "POST" }))}>Execute (if approved)</Button>
            </Can> : null}
            {r.status === "ACTIVE" ? <Can perm="defense:execute">
              <Button size="sm" variant="outline" onClick={() => act(() => api(`/v1/admin/fatma/actions/${r.id}/revert`, { method: "POST" }))}>Revert</Button>
            </Can> : null}
          </div>) },
      ]} />
    </div>
  );
}
