"use client";

import { PageHeader } from "@/components/page";
import { ResourceTable } from "@/components/resource-table";
import { StatusBadge } from "@/components/status";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { useApi } from "@/lib/api";
import { fmtDate } from "@/lib/utils";

type Status = { configured: boolean; phone_number_id?: string; approved_templates?: string[]; graph_version?: string };
type Notif = { id: string; template: string; status: string; scheduled_for: string; sent_at: string | null; last_error: string | null };

export default function WhatsApp() {
  const { data } = useApi<Status>("/v1/admin/whatsapp/status");
  return (
    <div>
      <PageHeader title="WhatsApp" description="Meta WhatsApp Business Cloud API. Access tokens stay in the secret manager and are never exposed to SAMIIR." />
      <Card className="mb-6">
        <CardHeader><CardTitle>Channel</CardTitle></CardHeader>
        <CardContent className="text-sm">
          {data?.configured ? (
            <ul className="space-y-1">
              <li>Phone number ID: <span className="font-mono">{data.phone_number_id}</span></li>
              <li>Graph API: {data.graph_version}</li>
              <li>Approved templates: {data.approved_templates?.join(", ") || "none"}</li>
              <li>Webhook: <span className="font-mono">/v1/whatsapp/webhook</span> (HMAC-SHA256 signature verified)</li>
            </ul>
          ) : <p className="text-muted">Not configured. Add a <code>whatsapp.cloud</code> integration with a secret reference.</p>}
        </CardContent>
      </Card>
      <h2 className="mb-2 text-sm font-semibold">Outbound WhatsApp notifications</h2>
      <ResourceTable<Notif> path="/v1/admin/notifications/notifications?channel=whatsapp" rowKey={(r) => r.id} columns={[
        { key: "t", header: "Template", render: (r) => r.template },
        { key: "s", header: "Status", render: (r) => <StatusBadge value={r.status} /> },
        { key: "when", header: "Scheduled", render: (r) => fmtDate(r.scheduled_for) },
        { key: "sent", header: "Sent", render: (r) => fmtDate(r.sent_at) },
        { key: "err", header: "Note", render: (r) => r.last_error ?? "—" },
      ]} />
    </div>
  );
}
