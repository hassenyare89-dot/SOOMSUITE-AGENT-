"use client";

import * as React from "react";
import { useSession } from "@/components/session";
import { ErrorNote, PageHeader } from "@/components/page";
import { RiskBadge, StatusBadge } from "@/components/status";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input, Select } from "@/components/ui/input";
import { Table, TBody, TD, TH, THead, TR } from "@/components/ui/table";
import { api, type Page, useApi, useRealtime } from "@/lib/api";
import { fmtDate } from "@/lib/utils";

type Approval = { id: string; action_type: string; action_payload: Record<string, unknown>; payload_hash: string;
  requested_by: string; requested_at: string; reason: string; risk_level: string; expires_at: string;
  status: string; approved_by: string | null; decision_comment: string | null };
type Policy = { action_type: string; risk: string; approver_permission: string; ttl_seconds: number; preapprovable: boolean };

export default function Approvals() {
  const { me } = useSession();
  const [status, setStatus] = React.useState("PENDING");
  const list = useApi<Page<Approval>>(`/v1/admin/approvals?status=${status}`);
  const policies = useApi<Policy[]>("/v1/admin/approvals/policies");
  const [err, setErr] = React.useState<string | null>(null);
  const [comment, setComment] = React.useState("");
  useRealtime("fatma", ["approval.decided"], () => void list.reload());
  async function decide(a: Approval, decision: "approve" | "reject") {
    setErr(null);
    try {
      // The approver echoes the hash of the exact payload they reviewed; any change → rejected.
      await api(`/v1/admin/approvals/${a.id}/decide`, { method: "POST", json: { decision, payload_hash: a.payload_hash, comment: comment || null } });
      await list.reload();
    } catch (e) { setErr(e instanceof Error ? e.message : "Failed"); }
  }
  return (
    <div className="space-y-6">
      <PageHeader title="Approvals" description="High-risk actions are cryptographically bound to their exact payload (SHA-256). The requester can never approve their own request."
        actions={<Select value={status} onChange={(e) => setStatus(e.target.value)} aria-label="Status">
          {["PENDING", "APPROVED", "EXECUTED", "REJECTED", "EXPIRED"].map((s) => <option key={s}>{s}</option>)}</Select>} />
      <ErrorNote error={list.error ?? err} />
      {list.data?.items.map((a) => (
        <Card key={a.id}>
          <CardHeader><CardTitle className="flex items-center gap-2">{a.action_type} <RiskBadge level={a.risk_level} /> <StatusBadge value={a.status} /></CardTitle>
            <CardDescription>Requested {fmtDate(a.requested_at)} by {a.requested_by.slice(0, 12)} · expires {fmtDate(a.expires_at)}</CardDescription></CardHeader>
          <CardContent className="space-y-2 text-sm">
            <p>{a.reason}</p>
            <pre className="overflow-x-auto rounded bg-background p-3 text-xs">{JSON.stringify(a.action_payload, null, 2)}</pre>
            <p className="font-mono text-xs text-muted">payload sha256: {a.payload_hash}</p>
            {a.status === "PENDING" ? (
              a.requested_by === me?.user_id ? <p className="text-xs text-muted">You requested this action; another approver must decide.</p> : (
                <div className="flex flex-wrap gap-2">
                  <Input className="max-w-sm" value={comment} onChange={(e) => setComment(e.target.value)} placeholder="Comment (optional)" aria-label="Comment" />
                  <Button onClick={() => void decide(a, "approve")}>Approve this exact payload</Button>
                  <Button variant="outline" onClick={() => void decide(a, "reject")}>Reject</Button>
                </div>)
            ) : <p className="text-xs text-muted">Decided by {a.approved_by ?? "—"} {a.decision_comment ? `· ${a.decision_comment}` : ""}</p>}
          </CardContent>
        </Card>
      ))}
      {list.data && list.data.items.length === 0 ? <p className="text-sm text-subtle">No {status.toLowerCase()} approvals.</p> : null}
      <Card><CardHeader><CardTitle>Approval policies</CardTitle><CardDescription>Code-reviewed; high-risk actions are never pre-approvable.</CardDescription></CardHeader>
        <CardContent><Table><THead><tr><TH>Action</TH><TH>Risk</TH><TH>Approver permission</TH><TH>Validity</TH><TH>Pre-approvable</TH></tr></THead>
          <TBody>{policies.data?.map((p) => <TR key={p.action_type}><TD className="font-mono text-xs">{p.action_type}</TD><TD><RiskBadge level={p.risk} /></TD>
            <TD className="text-xs">{p.approver_permission}</TD><TD className="tabular">{Math.round(p.ttl_seconds / 60)} min</TD><TD>{p.preapprovable ? "Yes (tenant opt-in)" : "Never"}</TD></TR>)}</TBody></Table></CardContent></Card>
    </div>
  );
}
