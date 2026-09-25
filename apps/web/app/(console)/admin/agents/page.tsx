"use client";

import { PageHeader } from "@/components/page";
import { RiskBadge } from "@/components/status";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Table, TBody, TD, TH, THead, TR } from "@/components/ui/table";
import { useApi } from "@/lib/api";
import { fmtDate } from "@/lib/utils";

type Config = { agent: string; runtime: string; model: string | null; service_identity: string;
  system_prompt_sha256: string; system_prompt: string;
  tools: { name: string; risk: string; permissions: string[]; requires_approval: boolean }[] };
type Run = { id: string; status: string; runtime: string; model: string | null; latency_ms: number | null;
  input_tokens: number; output_tokens: number; guardrail_flags: string[]; started_at: string; denied_tool_calls_total: number };

export default function Agents() {
  const cfg = useApi<Config>("/v1/admin/samiir/agent/config");
  const runs = useApi<Run[]>("/v1/admin/samiir/agent-runs?limit=30");
  return (
    <div className="space-y-6">
      <PageHeader title="Agent configuration" description="Each agent has its own identity, tool registry, permissions and database role. Tool registries are code-reviewed and enforced outside the model." />
      {cfg.data ? (
        <Card><CardHeader><CardTitle>SAMIIR</CardTitle>
          <CardDescription>runtime {cfg.data.runtime} · model {cfg.data.model ?? "none (deterministic)"} · identity {cfg.data.service_identity} · prompt sha256 {cfg.data.system_prompt_sha256.slice(0, 16)}…</CardDescription></CardHeader>
          <CardContent className="grid gap-4 lg:grid-cols-2">
            <Table><THead><tr><TH>Tool</TH><TH>Risk</TH><TH>Permission</TH></tr></THead>
              <TBody>{cfg.data.tools.map((t) => <TR key={t.name}><TD className="font-mono text-xs">{t.name}</TD><TD><RiskBadge level={t.risk} /></TD><TD className="text-xs">{t.permissions.join(" | ")}</TD></TR>)}</TBody></Table>
            <pre className="max-h-80 overflow-auto whitespace-pre-wrap rounded bg-background p-3 text-xs">{cfg.data.system_prompt}</pre>
          </CardContent></Card>
      ) : null}
      <Card><CardHeader><CardTitle>FATMA</CardTitle>
        <CardDescription>Separate service (fatma-soc) and identity; reachable only through the admin gateway by security staff. Recommend-only tools: security.query_events, incidents.get, incidents.list_open, findings.list, assets.get, incidents.add_note, defense.recommend_action, notifications.notify_security_team.</CardDescription></CardHeader></Card>
      <Card><CardHeader><CardTitle>Recent SAMIIR runs</CardTitle>
        <CardDescription>{runs.data?.[0] ? `${runs.data[0].denied_tool_calls_total} denied tool calls recorded in total` : ""}</CardDescription></CardHeader>
        <CardContent><Table><THead><tr><TH>Started</TH><TH>Status</TH><TH>Runtime</TH><TH>Latency</TH><TH>Tokens</TH><TH>Guardrail flags</TH></tr></THead>
          <TBody>{runs.data?.map((r) => <TR key={r.id}><TD>{fmtDate(r.started_at)}</TD><TD>{r.status}</TD><TD>{r.runtime}</TD>
            <TD className="tabular">{r.latency_ms ?? "—"} ms</TD><TD className="tabular">{r.input_tokens}/{r.output_tokens}</TD>
            <TD className="text-xs">{r.guardrail_flags.join(", ") || "—"}</TD></TR>)}</TBody></Table></CardContent></Card>
    </div>
  );
}
