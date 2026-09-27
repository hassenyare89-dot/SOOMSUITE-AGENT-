"use client";

import * as React from "react";
import { Can } from "@/components/session";
import { ErrorNote, PageHeader } from "@/components/page";
import { ResourceTable } from "@/components/resource-table";
import { StatusBadge } from "@/components/status";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input, Label, Select } from "@/components/ui/input";
import { api, useApi, useRealtime } from "@/lib/api";
import { fmtDate, newIdempotencyKey } from "@/lib/utils";

type Asset = { id: string; name: string; canonical_target: string };
type Scan = { id: string; target_url: string; profile: string; scanners: string[]; status: string;
  approval_id: string | null; authorization_ticket: string; findings_count: number; created_at: string;
  error: string | null };

export default function Scans() {
  const assets = useApi<Asset[]>("/v1/admin/scanner/assets");
  const [tick, setTick] = React.useState(0);
  const [err, setErr] = React.useState<string | null>(null);
  const [gate, setGate] = React.useState<Record<string, boolean> | null>(null);
  const [form, setForm] = React.useState({ asset_id: "", profile: "safe-passive", ticket: "", nuclei: true, zap: true });
  useRealtime("fatma", ["scan.updated", "approval.decided"], () => setTick((t) => t + 1));
  const body = () => ({ asset_id: form.asset_id, profile: form.profile, authorization_ticket: form.ticket,
    scanners: [form.nuclei && "nuclei", form.zap && "zap"].filter(Boolean), idempotency_key: newIdempotencyKey() });
  async function act(fn: () => Promise<unknown>) {
    setErr(null);
    try { await fn(); setTick((t) => t + 1); } catch (e) { setErr(e instanceof Error ? e.message : "Failed"); }
  }
  return (
    <div>
      <PageHeader title="Scan history" description="Scans run only via approved Temporal workflows in isolated workers — never from the API." />
      <ErrorNote error={err} />
      <Can perm="scan:request">
        <Card className="mb-6">
          <CardHeader><CardTitle>Request an authorized scan</CardTitle>
            <CardDescription>Requires: security engineer · customer authorization · verified ownership · allowlisted target · ticket · human approval · safe profile.</CardDescription></CardHeader>
          <CardContent className="grid gap-3 md:grid-cols-4">
            <div><Label>Asset</Label><Select value={form.asset_id} onChange={(e) => setForm({ ...form, asset_id: e.target.value })}>
              <option value="">Select…</option>{assets.data?.map((a) => <option key={a.id} value={a.id}>{a.name} ({a.canonical_target})</option>)}</Select></div>
            <div><Label>Profile</Label><Select value={form.profile} onChange={(e) => setForm({ ...form, profile: e.target.value })}>
              <option value="safe-passive">safe-passive</option><option value="safe-standard">safe-standard</option></Select></div>
            <div><Label>Authorization ticket</Label><Input value={form.ticket} placeholder="SEC-1234" onChange={(e) => setForm({ ...form, ticket: e.target.value })} /></div>
            <div className="flex items-end gap-3 text-sm">
              <label className="flex items-center gap-1"><input type="checkbox" checked={form.nuclei} onChange={(e) => setForm({ ...form, nuclei: e.target.checked })} />Nuclei</label>
              <label className="flex items-center gap-1"><input type="checkbox" checked={form.zap} onChange={(e) => setForm({ ...form, zap: e.target.checked })} />ZAP</label>
            </div>
            <div className="flex gap-2 md:col-span-4">
              <Button variant="outline" disabled={!form.asset_id} onClick={() => act(async () => {
                const r = await api<{ checks: Record<string, boolean> }>("/v1/admin/scanner/scans/gate-check", { method: "POST", json: body() });
                setGate(r.checks);
              })}>Check pre-conditions</Button>
              <Button disabled={!form.asset_id || !form.ticket} onClick={() => act(() => api("/v1/admin/scanner/scans", { method: "POST", json: body() }))}>Request scan (creates approval)</Button>
            </div>
            {gate ? <ul className="text-xs md:col-span-4">{Object.entries(gate).map(([k, v]) => <li key={k}>{v ? "✓" : "✗"} {k.replaceAll("_", " ")}</li>)}</ul> : null}
          </CardContent>
        </Card>
      </Can>
      <ResourceTable<Scan> path="/v1/admin/scanner/scans" rowKey={(r) => r.id} reloadSignal={tick} columns={[
        { key: "t", header: "Target", render: (r) => <span className="font-mono text-xs">{r.target_url}</span> },
        { key: "p", header: "Profile", render: (r) => `${r.profile} · ${r.scanners.join("+")}` },
        { key: "tk", header: "Ticket", render: (r) => r.authorization_ticket },
        { key: "s", header: "Status", render: (r) => <><StatusBadge value={r.status} />{r.error ? <p className="text-xs text-critical">{r.error}</p> : null}</> },
        { key: "f", header: "Findings", render: (r) => <span className="tabular">{r.findings_count}</span> },
        { key: "c", header: "Requested", render: (r) => fmtDate(r.created_at) },
        { key: "x", header: "", render: (r) => <Can perm="scan:request"><div className="flex gap-1">
          {r.status === "PENDING_APPROVAL" ? <Button size="sm" onClick={() => act(() => api(`/v1/admin/scanner/scans/${r.id}/start`, { method: "POST" }))}>Start (after approval)</Button> : null}
          {["PENDING_APPROVAL", "QUEUED", "RUNNING"].includes(r.status) ? <Button size="sm" variant="outline" onClick={() => act(() => api(`/v1/admin/scanner/scans/${r.id}/cancel`, { method: "POST" }))}>Cancel</Button> : null}
          {["FAILED", "TIMED_OUT", "CANCELLED"].includes(r.status) ? <Button size="sm" variant="outline" onClick={() => act(() => api(`/v1/admin/scanner/scans/${r.id}/retry`, { method: "POST", json: { idempotency_key: newIdempotencyKey() } }))}>Retry</Button> : null}
        </div></Can> },
      ]} />
    </div>
  );
}
