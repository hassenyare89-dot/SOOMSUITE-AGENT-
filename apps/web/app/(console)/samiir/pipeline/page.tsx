"use client";

import * as React from "react";
import { useSession } from "@/components/session";
import { ErrorNote, PageHeader } from "@/components/page";
import { Card } from "@/components/ui/card";
import { Select } from "@/components/ui/input";
import { api, type Page, useApi, useRealtime } from "@/lib/api";

const STAGES = ["NEW_LEAD", "QUALIFIED", "APPOINTMENT_BOOKED", "SECURITY_REVIEW", "PROPOSAL",
                "NEGOTIATION", "WON", "LOST"];
type Opp = { id: string; title: string; stage: string; estimated_value: string | null;
  currency: string; version: number; service_interest: string | null };

export default function Pipeline() {
  const { can } = useSession();
  const { data, error, reload } = useApi<Page<Opp>>("/v1/admin/crm/opportunities?limit=200");
  const [err, setErr] = React.useState<string | null>(null);
  useRealtime("samiir", ["pipeline.changed", "lead.updated"], () => void reload());
  async function move(o: Opp, stage: string) {
    setErr(null);
    try {
      await api(`/v1/admin/crm/opportunities/${o.id}/stage`, { method: "POST",
        json: { stage, expected_version: o.version } });
      await reload();
    } catch (e) { setErr(e instanceof Error ? e.message : "Failed"); }
  }
  return (
    <div>
      <PageHeader title="CRM pipeline" description="Stage changes are validated server-side and use optimistic locking." />
      <ErrorNote error={error ?? err} />
      <div className="grid gap-3 overflow-x-auto md:grid-cols-4 xl:grid-cols-8">
        {STAGES.map((stage) => {
          const items = data?.items.filter((o) => o.stage === stage) ?? [];
          return (
            <div key={stage} className="min-w-44">
              <p className="mb-2 text-xs font-medium text-muted">{stage.replaceAll("_", " ")} · {items.length}</p>
              <div className="space-y-2">
                {items.map((o) => (
                  <Card key={o.id} className="p-3 text-sm">
                    <p className="font-medium">{o.title}</p>
                    <p className="text-xs text-muted">{o.estimated_value ? `${o.currency} ${o.estimated_value}` : "No value"}</p>
                    {can("crm:write") ? (
                      <Select className="mt-2 h-8 text-xs" value={o.stage} aria-label="Move stage"
                              onChange={(e) => void move(o, e.target.value)}>
                        {STAGES.map((s) => <option key={s} value={s}>{s}</option>)}
                      </Select>
                    ) : null}
                  </Card>
                ))}
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}
