"use client";

import * as React from "react";
import { ErrorNote, PageHeader } from "@/components/page";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { Textarea } from "@/components/ui/input";
import { api } from "@/lib/api";

export default function AskFatma() {
  const [q, setQ] = React.useState("");
  const [answer, setAnswer] = React.useState<{ answer: string; tools_used: string[] } | null>(null);
  const [err, setErr] = React.useState<string | null>(null);
  const [busy, setBusy] = React.useState(false);
  return (
    <div className="max-w-3xl">
      <PageHeader title="Ask FATMA" description="Read-mostly analyst assistant. It can recommend actions, never execute them, and never confirms breaches." />
      <ErrorNote error={err} />
      <Textarea value={q} maxLength={2000} onChange={(e) => setQ(e.target.value)} placeholder="e.g. What are the most urgent open incidents and why?" aria-label="Question" />
      <Button className="mt-2" disabled={busy || q.length < 3} onClick={async () => {
        setErr(null); setBusy(true);
        try { setAnswer(await api("/v1/admin/fatma/ask", { method: "POST", json: { question: q } })); }
        catch (e) { setErr(e instanceof Error ? e.message : "Failed"); } finally { setBusy(false); }
      }}>{busy ? "Analysing…" : "Ask"}</Button>
      {answer ? <Card className="mt-4"><CardContent className="pt-4">
        <p className="whitespace-pre-wrap text-sm">{answer.answer}</p>
        <p className="mt-3 text-xs text-muted">Tools used: {answer.tools_used.join(", ") || "none"}</p>
      </CardContent></Card> : null}
    </div>
  );
}
