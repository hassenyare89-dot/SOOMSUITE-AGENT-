"use client";

import * as React from "react";
import { Can } from "@/components/session";
import { ErrorNote, PageHeader } from "@/components/page";
import { ResourceTable } from "@/components/resource-table";
import { StatusBadge } from "@/components/status";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input, Label, Select, Textarea } from "@/components/ui/input";
import { api } from "@/lib/api";
import { fmtDate } from "@/lib/utils";

const CATEGORIES = ["company_profile", "services", "products", "pricing", "faq", "onboarding",
  "service_scope", "included", "excluded", "delivery_timeline", "support_procedures",
  "customer_service_policies", "appointment_rules", "sales_qualification_rules",
  "refund_escalation_policies", "security_services", "legal_approved_messaging"];

type Doc = { id: string; title: string; category: string; visibility: string; version: number;
  status: string; injection_flags: string[]; approved_at: string | null; review_date: string | null;
  updated_at: string };

export default function Knowledge() {
  const [tick, setTick] = React.useState(0);
  const [err, setErr] = React.useState<string | null>(null);
  const [form, setForm] = React.useState({ title: "", content: "", category: "faq", source: "",
    visibility: "public", pricing: "" });
  async function act(fn: () => Promise<unknown>) {
    setErr(null);
    try { await fn(); setTick((t) => t + 1); } catch (e) { setErr(e instanceof Error ? e.message : "Failed"); }
  }
  return (
    <div>
      <PageHeader title="Knowledge base"
        description="Only APPROVED, public, currently effective documents are ever retrieved for customers. Approval requires a second person." />
      <ErrorNote error={err} />
      <Can perm="knowledge:write">
        <Card className="mb-6">
          <CardHeader><CardTitle>New draft</CardTitle></CardHeader>
          <CardContent className="grid gap-3 md:grid-cols-2">
            <div><Label>Title</Label><Input value={form.title} onChange={(e) => setForm({ ...form, title: e.target.value })} /></div>
            <div><Label>Source</Label><Input value={form.source} placeholder="e.g. Legal-approved 2026-09" onChange={(e) => setForm({ ...form, source: e.target.value })} /></div>
            <div><Label>Category</Label><Select value={form.category} onChange={(e) => setForm({ ...form, category: e.target.value })}>
              {CATEGORIES.map((c) => <option key={c}>{c}</option>)}</Select></div>
            <div><Label>Visibility</Label><Select value={form.visibility} onChange={(e) => setForm({ ...form, visibility: e.target.value })}>
              <option value="public">public (customer agent)</option><option value="internal">internal</option></Select></div>
            <div className="md:col-span-2"><Label>Content</Label><Textarea value={form.content} onChange={(e) => setForm({ ...form, content: e.target.value })} /></div>
            {form.category === "pricing" ? (
              <div className="md:col-span-2"><Label>Structured pricing (JSON)</Label>
                <Textarea className="font-mono text-xs" value={form.pricing} placeholder='{"currency":"USD","items":[{"service":"Monitoring","price":"499","unit":"per month"}]}'
                  onChange={(e) => setForm({ ...form, pricing: e.target.value })} /></div>
            ) : null}
            <div><Button onClick={() => act(async () => {
              const structured = form.category === "pricing" ? JSON.parse(form.pricing || "null") : null;
              await api("/v1/admin/knowledge/documents", { method: "POST", json: {
                title: form.title, content: form.content, category: form.category, source: form.source,
                visibility: form.visibility, structured_data: structured } });
              setForm({ ...form, title: "", content: "", pricing: "" });
            })}>Save draft</Button></div>
          </CardContent>
        </Card>
      </Can>
      <ResourceTable<Doc> path="/v1/admin/knowledge/documents" rowKey={(r) => r.id} reloadSignal={tick} columns={[
        { key: "title", header: "Title", render: (r) => r.title },
        { key: "category", header: "Category", render: (r) => r.category },
        { key: "vis", header: "Visibility", render: (r) => r.visibility },
        { key: "ver", header: "Version", render: (r) => `v${r.version}` },
        { key: "status", header: "Status", render: (r) => <StatusBadge value={r.status} /> },
        { key: "flags", header: "Injection flags", render: (r) => r.injection_flags.length ? <span className="text-warning">⚠ {r.injection_flags.join(", ")}</span> : "—" },
        { key: "review", header: "Review by", render: (r) => fmtDate(r.review_date) },
        { key: "actions", header: "", render: (r) => (
          <div className="flex gap-1">
            {r.status === "DRAFT" ? <Button size="sm" variant="outline" onClick={() => act(() => api(`/v1/admin/knowledge/documents/${r.id}/submit`, { method: "POST" }))}>Submit</Button> : null}
            {r.status === "PENDING_APPROVAL" ? <Can perm="knowledge:approve"><Button size="sm" onClick={() => act(() => api(`/v1/admin/knowledge/documents/${r.id}/approve`, { method: "POST", json: { acknowledge_flags: r.injection_flags.length > 0 && confirm("This document contains instruction-like text. Approve anyway?") } }))}>Approve</Button></Can> : null}
            {r.status === "APPROVED" ? <Can perm="knowledge:approve"><Button size="sm" variant="outline" onClick={() => act(() => api(`/v1/admin/knowledge/documents/${r.id}/archive`, { method: "POST" }))}>Archive</Button></Can> : null}
          </div>) },
      ]} />
    </div>
  );
}
