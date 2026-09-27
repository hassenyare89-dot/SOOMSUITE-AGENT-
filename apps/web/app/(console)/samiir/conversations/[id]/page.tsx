"use client";

import { useParams } from "next/navigation";
import * as React from "react";
import { Can } from "@/components/session";
import { ErrorNote, PageHeader } from "@/components/page";
import { StatusBadge } from "@/components/status";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { Textarea } from "@/components/ui/input";
import { api, useApi, useRealtime } from "@/lib/api";
import { cn, fmtDate } from "@/lib/utils";

type Detail = {
  conversation: { id: string; channel: string; status: string; summary: string | null;
    escalation_reason: string | null };
  messages: { id: string; sender: string; text: string; created_at: string;
    injection_score: number | null; delivery_status: string | null;
    cards: { type: string; data: Record<string, unknown> }[] }[];
};

export default function ConversationDetail() {
  const { id } = useParams<{ id: string }>();
  const { data, error, reload } = useApi<Detail>(`/v1/admin/samiir/conversations/${id}`);
  const [reply, setReply] = React.useState("");
  const [err, setErr] = React.useState<string | null>(null);
  useRealtime("samiir", ["message.inbound", "message.outbound"], () => void reload());
  async function act(fn: () => Promise<unknown>) {
    setErr(null);
    try { await fn(); await reload(); } catch (e) { setErr(e instanceof Error ? e.message : "Failed"); }
  }
  const c = data?.conversation;
  return (
    <div>
      <PageHeader title={`Conversation ${id.slice(0, 8)}`}
        description={c ? `${c.channel} · ${c.escalation_reason ?? "no escalation"}` : undefined}
        actions={c ? <>
          <StatusBadge value={c.status} />
          <Can perm="conversation:manage">
            <Button size="sm" variant="outline" onClick={() => act(() => api(`/v1/admin/samiir/conversations/${id}/status`, { method: "POST", json: { status: "HUMAN_HANDLING" } }))}>Take over</Button>
            <Button size="sm" variant="outline" onClick={() => act(() => api(`/v1/admin/samiir/conversations/${id}/status`, { method: "POST", json: { status: "OPEN" } }))}>Return to SAMIIR</Button>
            <Button size="sm" variant="outline" onClick={() => act(() => api(`/v1/admin/samiir/conversations/${id}/status`, { method: "POST", json: { status: "CLOSED" } }))}>Close</Button>
          </Can>
          <Button size="sm" variant="outline" onClick={() => act(() => api(`/v1/admin/samiir/conversations/${id}/summarize`, { method: "POST" }))}>Summarize</Button>
        </> : null} />
      <ErrorNote error={error ?? err} />
      {c?.summary ? <Card className="mb-4"><CardContent className="pt-4 text-sm">{c.summary}</CardContent></Card> : null}
      <div className="space-y-3">
        {data?.messages.map((m) => (
          <div key={m.id} className={cn("max-w-2xl rounded-lg border border-border p-3 text-sm",
            m.sender === "customer" ? "bg-surface" : "ml-auto bg-background")}>
            <p className="mb-1 text-xs text-muted">
              {m.sender} · {fmtDate(m.created_at)}{m.delivery_status ? ` · ${m.delivery_status}` : ""}
              {m.injection_score && m.injection_score >= 0.5 ? " · ⚠ possible prompt injection" : ""}
            </p>
            {/* Customer text is rendered as a text node (escaped), never as HTML. */}
            <p className="whitespace-pre-wrap break-words">{m.text}</p>
            {m.cards.length ? <p className="mt-1 text-xs text-subtle">cards: {m.cards.map((x) => x.type).join(", ")}</p> : null}
          </div>
        ))}
      </div>
      <Can perm="conversation:manage">
        <div className="mt-6 max-w-2xl space-y-2">
          <Textarea value={reply} maxLength={4000} onChange={(e) => setReply(e.target.value)}
                    placeholder="Reply as a human agent…" aria-label="Reply" />
          <Button disabled={!reply.trim()} onClick={() => act(async () => {
            await api(`/v1/admin/samiir/conversations/${id}/reply`, { method: "POST", json: { text: reply } });
            setReply("");
          })}>Send reply</Button>
        </div>
      </Can>
    </div>
  );
}
