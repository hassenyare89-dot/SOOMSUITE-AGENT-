"use client";

import { useParams } from "next/navigation";
import * as React from "react";
import { Can } from "@/components/session";
import { ErrorNote, PageHeader } from "@/components/page";
import { ClaimBadge, RiskBadge, StatusBadge } from "@/components/status";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input, Label, Textarea } from "@/components/ui/input";
import { api, useApi, useRealtime } from "@/lib/api";
import { fmtDate } from "@/lib/utils";

type Detail = {
  incident: { id: string; title: string; summary: string; category: string; risk_level: string;
    risk_score: number; claim_status: string; status: string; event_count: number;
    signals: { name: string; category: string; severity: number; confidence: number; count: number }[];
    recommendations: { type: string; text: string }[];
    analysis: { sources?: string[]; confirmation_checklist?: string[]; fatma?: {
      summary: string; attack_hypotheses: string[]; evidence_gaps: string[];
      recommended_next_steps: string[]; confidence: number }; engine?: string };
    first_seen: string; last_seen: string; confirmed_at: string | null };
  timeline: { id: string; type: string; actor_type: string; actor_id: string; body: Record<string, unknown>; created_at: string }[];
  events: { event_id: string; timestamp: string; category: string; event_type: string; src_ip: string | null; request_path: string | null; status_code: number | null; action_taken: string | null }[];
  actions: { id: string; action_type: string; target: string; status: string; risk_level: string }[];
};

const NEXT: Record<string, string[]> = {
  NEW: ["ACKNOWLEDGED", "FALSE_POSITIVE"], ACKNOWLEDGED: ["INVESTIGATING", "FALSE_POSITIVE"],
  INVESTIGATING: ["CONTAINED", "REMEDIATED", "FALSE_POSITIVE"], CONTAINED: ["REMEDIATED", "INVESTIGATING"],
  REMEDIATED: ["CLOSED", "INVESTIGATING"], CLOSED: ["INVESTIGATING"], FALSE_POSITIVE: ["INVESTIGATING"],
};

export default function IncidentDetail() {
  const { id } = useParams<{ id: string }>();
  const { data, error, reload } = useApi<Detail>(`/v1/admin/fatma/incidents/${id}`);
  const [err, setErr] = React.useState<string | null>(null);
  const [note, setNote] = React.useState("");
  const [confirmForm, setConfirmForm] = React.useState({ justification: "", refs: "", checked: [] as string[] });
  const [busy, setBusy] = React.useState(false);
  useRealtime("fatma", ["incident.updated", "action.updated"], () => void reload());
  async function act(fn: () => Promise<unknown>) {
    setErr(null); setBusy(true);
    try { await fn(); await reload(); } catch (e) { setErr(e instanceof Error ? e.message : "Failed"); }
    finally { setBusy(false); }
  }
  const inc = data?.incident;
  if (!inc) return <div><ErrorNote error={error} /><p className="text-sm text-muted">Loading…</p></div>;
  const checklist = inc.analysis.confirmation_checklist ?? [];
  const fatma = inc.analysis.fatma;
  return (
    <div className="space-y-4">
      <PageHeader title={inc.title} description={`${inc.category.replaceAll("_", " ")} · first seen ${fmtDate(inc.first_seen)} · last seen ${fmtDate(inc.last_seen)}`}
        actions={<><RiskBadge level={inc.risk_level} /><ClaimBadge claim={inc.claim_status} /><StatusBadge value={inc.status} /></>} />
      <ErrorNote error={err} />
      <Card><CardContent className="pt-4 text-sm">{inc.summary}</CardContent></Card>
      <Can perm="incident:triage">
        <div className="flex flex-wrap gap-2">
          {(NEXT[inc.status] ?? []).map((s) => (
            <Button key={s} size="sm" variant="outline" disabled={busy}
                    onClick={() => act(() => api(`/v1/admin/fatma/incidents/${id}/status`, { method: "POST", json: { status: s } }))}>
              Mark {s.replaceAll("_", " ").toLowerCase()}
            </Button>
          ))}
          <Can perm="fatma:ask">
            <Button size="sm" disabled={busy} onClick={() => act(() => api(`/v1/admin/fatma/incidents/${id}/analyze`, { method: "POST" }))}>
              Ask FATMA to analyse
            </Button>
          </Can>
        </div>
      </Can>
      <div className="grid gap-4 lg:grid-cols-2">
        <Card>
          <CardHeader><CardTitle>Signals</CardTitle><CardDescription>Risk score {inc.risk_score}/100 (deterministic)</CardDescription></CardHeader>
          <CardContent>
            <ul className="space-y-1 text-sm">
              {inc.signals.map((s) => (
                <li key={s.name} className="flex justify-between gap-2">
                  <span className="font-mono text-xs">{s.name}</span>
                  <span className="text-xs text-muted">sev {s.severity} · conf {s.confidence} · ×{s.count}</span>
                </li>
              ))}
            </ul>
            <p className="mt-3 text-xs text-muted">Sources: {inc.analysis.sources?.join(", ") || "—"}</p>
          </CardContent>
        </Card>
        <Card>
          <CardHeader><CardTitle>FATMA analysis</CardTitle>
            <CardDescription>{fatma ? `engine: ${inc.analysis.engine} · confidence ${fatma.confidence}` : "Not analysed yet"}</CardDescription></CardHeader>
          <CardContent className="space-y-2 text-sm">
            {fatma ? <>
              <p>{fatma.summary}</p>
              <p className="text-xs font-medium text-muted">Hypotheses</p>
              <ul className="list-disc pl-5 text-xs">{fatma.attack_hypotheses.map((h) => <li key={h}>{h}</li>)}</ul>
              <p className="text-xs font-medium text-muted">Evidence gaps</p>
              <ul className="list-disc pl-5 text-xs">{fatma.evidence_gaps.map((h) => <li key={h}>{h}</li>)}</ul>
            </> : null}
            <p className="text-xs font-medium text-muted">Recommended steps</p>
            <ul className="list-disc pl-5 text-xs">{(fatma?.recommended_next_steps ?? inc.recommendations.map((r) => r.text)).map((h) => <li key={h}>{h}</li>)}</ul>
          </CardContent>
        </Card>
      </div>
      {data.actions.length ? (
        <Card><CardHeader><CardTitle>Defensive actions</CardTitle><CardDescription>Manage in Recommendations</CardDescription></CardHeader>
          <CardContent><ul className="text-sm">{data.actions.map((a) => (
            <li key={a.id}>{a.action_type} → <span className="font-mono">{a.target}</span> · <RiskBadge level={a.risk_level} /> · {a.status}</li>
          ))}</ul></CardContent></Card>
      ) : null}
      <div className="grid gap-4 lg:grid-cols-2">
        <Card>
          <CardHeader><CardTitle>Timeline</CardTitle></CardHeader>
          <CardContent>
            <ul className="space-y-2 text-xs">
              {data.timeline.map((t) => (
                <li key={t.id}><span className="text-muted">{fmtDate(t.created_at)} · {t.actor_type}:{t.actor_id.slice(0, 8)} · {t.type}</span>
                  <p className="break-words">{JSON.stringify(t.body)}</p></li>
              ))}
            </ul>
            <Can perm="incident:triage">
              <div className="mt-3 flex gap-2">
                <Input value={note} onChange={(e) => setNote(e.target.value)} placeholder="Add a note" aria-label="Note" />
                <Button size="sm" disabled={!note} onClick={() => act(async () => {
                  await api(`/v1/admin/fatma/incidents/${id}/notes`, { method: "POST", json: { note } }); setNote("");
                })}>Add</Button>
              </div>
            </Can>
          </CardContent>
        </Card>
        <Card>
          <CardHeader><CardTitle>Linked events ({inc.event_count})</CardTitle></CardHeader>
          <CardContent>
            <ul className="space-y-1 text-xs">
              {data.events.slice(0, 30).map((e) => (
                <li key={e.event_id} className="truncate font-mono">{fmtDate(e.timestamp)} {e.src_ip} {e.event_type} {e.status_code ?? ""} {e.action_taken ?? ""} {e.request_path}</li>
              ))}
            </ul>
          </CardContent>
        </Card>
      </div>
      {inc.claim_status !== "CONFIRMED INCIDENT" ? (
        <Can perm="incident:confirm">
          <Card>
            <CardHeader><CardTitle>Confirm incident</CardTitle>
              <CardDescription>Only a security engineer can confirm, with evidence and a completed checklist. This is recorded in the audit log.</CardDescription></CardHeader>
            <CardContent className="space-y-3">
              {checklist.map((c) => (
                <label key={c} className="flex items-start gap-2 text-sm">
                  <input type="checkbox" checked={confirmForm.checked.includes(c)} onChange={(e) =>
                    setConfirmForm({ ...confirmForm, checked: e.target.checked ? [...confirmForm.checked, c] : confirmForm.checked.filter((x) => x !== c) })} />
                  {c}
                </label>
              ))}
              <div><Label>Evidence references (comma separated ticket/case IDs)</Label>
                <Input value={confirmForm.refs} onChange={(e) => setConfirmForm({ ...confirmForm, refs: e.target.value })} /></div>
              <div><Label>Justification</Label>
                <Textarea value={confirmForm.justification} onChange={(e) => setConfirmForm({ ...confirmForm, justification: e.target.value })} /></div>
              <Button variant="destructive" disabled={busy || confirmForm.checked.length !== checklist.length}
                onClick={() => act(() => api(`/v1/admin/fatma/incidents/${id}/confirm`, { method: "POST", json: {
                  justification: confirmForm.justification, checklist: confirmForm.checked,
                  evidence_refs: confirmForm.refs.split(",").map((s) => s.trim()).filter(Boolean) } }))}>
                Confirm incident
              </Button>
            </CardContent>
          </Card>
        </Can>
      ) : <p className="text-sm">Confirmed at {fmtDate(inc.confirmed_at)}.</p>}
    </div>
  );
}
