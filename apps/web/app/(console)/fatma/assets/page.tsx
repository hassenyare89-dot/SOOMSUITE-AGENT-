"use client";

import * as React from "react";
import { Can } from "@/components/session";
import { ErrorNote, PageHeader } from "@/components/page";
import { StatusBadge } from "@/components/status";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input, Label } from "@/components/ui/input";
import { Table, TBody, TD, TH, THead, TR } from "@/components/ui/table";
import { api, useApi } from "@/lib/api";
import { fmtDate } from "@/lib/utils";

type Asset = { id: string; name: string; canonical_target: string; criticality: number;
  verification_status: string; verified_until: string | null; allowlisted: boolean;
  customer_authorization_ref: string | null; customer_authorization_expires_at: string | null };

export default function Assets() {
  const { data, error, reload } = useApi<Asset[]>("/v1/admin/scanner/assets");
  const [err, setErr] = React.useState<string | null>(null);
  const [challenge, setChallenge] = React.useState<{ asset: string; id: string; instructions: Record<string, string> } | null>(null);
  const [form, setForm] = React.useState({ name: "", target: "", criticality: "3" });
  async function act(fn: () => Promise<unknown>) {
    setErr(null);
    try { await fn(); await reload(); } catch (e) { setErr(e instanceof Error ? e.message : "Failed"); }
  }
  return (
    <div>
      <PageHeader title="Assets" description="FATMA only operates on verified, authorized assets. Scanning additionally requires allowlisting." />
      <ErrorNote error={error ?? err} />
      <Can perm="asset:manage">
        <Card className="mb-6"><CardHeader><CardTitle>Register asset</CardTitle></CardHeader>
          <CardContent className="grid gap-3 md:grid-cols-4">
            <div><Label>Name</Label><Input value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} /></div>
            <div><Label>Hostname</Label><Input value={form.target} placeholder="www.example.com" onChange={(e) => setForm({ ...form, target: e.target.value })} /></div>
            <div><Label>Criticality (1-5)</Label><Input value={form.criticality} onChange={(e) => setForm({ ...form, criticality: e.target.value })} /></div>
            <div className="flex items-end"><Button onClick={() => act(() => api("/v1/admin/scanner/assets", { method: "POST", json: { name: form.name, canonical_target: form.target.toLowerCase(), criticality: Number(form.criticality) } }))}>Register</Button></div>
          </CardContent></Card>
      </Can>
      {challenge ? (
        <Card className="mb-6"><CardHeader><CardTitle>Ownership challenge</CardTitle></CardHeader>
          <CardContent className="space-y-1 text-sm">
            {Object.entries(challenge.instructions).map(([k, v]) => <p key={k}><span className="text-muted">{k}:</span> <span className="font-mono break-all">{v}</span></p>)}
            <p className="text-xs text-muted">This value is shown once. Publish it, then check verification.</p>
            <Button size="sm" onClick={() => act(async () => {
              const r = await api<{ verified: boolean }>(`/v1/admin/scanner/assets/${challenge.asset}/verifications/${challenge.id}/check`, { method: "POST" });
              if (!r.verified) throw new Error("Challenge not found yet");
              setChallenge(null);
            })}>Check verification</Button>
          </CardContent></Card>
      ) : null}
      <Table>
        <THead><tr><TH>Asset</TH><TH>Target</TH><TH>Criticality</TH><TH>Ownership</TH><TH>Customer authorization</TH><TH>Allowlisted</TH><TH></TH></tr></THead>
        <TBody>
          {data?.map((a) => (
            <TR key={a.id}>
              <TD>{a.name}</TD>
              <TD className="font-mono text-xs">{a.canonical_target}</TD>
              <TD className="tabular">{a.criticality}</TD>
              <TD><StatusBadge value={a.verification_status} /><p className="text-xs text-muted">until {fmtDate(a.verified_until)}</p></TD>
              <TD className="text-xs">{a.customer_authorization_ref ?? "—"}<p className="text-muted">until {fmtDate(a.customer_authorization_expires_at)}</p></TD>
              <TD>{a.allowlisted ? "Yes" : "No"}</TD>
              <TD>
                <Can perm="asset:manage">
                  <div className="flex flex-wrap gap-1">
                    <Button size="sm" variant="outline" onClick={() => act(async () => {
                      const r = await api<{ verification_id: string; instructions: Record<string, string> }>(`/v1/admin/scanner/assets/${a.id}/verifications`, { method: "POST", json: { method: "dns_txt" } });
                      setChallenge({ asset: a.id, id: r.verification_id, instructions: r.instructions });
                    })}>Verify (DNS)</Button>
                    <Button size="sm" variant="outline" onClick={() => act(async () => {
                      const r = await api<{ verification_id: string; instructions: Record<string, string> }>(`/v1/admin/scanner/assets/${a.id}/verifications`, { method: "POST", json: { method: "http_file" } });
                      setChallenge({ asset: a.id, id: r.verification_id, instructions: r.instructions });
                    })}>Verify (HTTP)</Button>
                    <Button size="sm" variant="outline" onClick={() => act(() => api(`/v1/admin/scanner/assets/${a.id}`, { method: "PATCH", json: {
                      customer_authorization_ref: prompt("Customer authorization reference (e.g. signed SoW id)") ?? "",
                      customer_authorization_expires_at: new Date(Date.now() + 90 * 864e5).toISOString() } }))}>Record authorization</Button>
                    <Button size="sm" variant={a.allowlisted ? "outline" : "default"} onClick={() => act(() => api(`/v1/admin/scanner/assets/${a.id}/allowlist`, { method: "POST", json: { allowlisted: !a.allowlisted } }))}>
                      {a.allowlisted ? "Remove from allowlist" : "Allowlist"}
                    </Button>
                  </div>
                </Can>
              </TD>
            </TR>
          ))}
        </TBody>
      </Table>
    </div>
  );
}
