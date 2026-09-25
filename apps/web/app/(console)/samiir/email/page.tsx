"use client";

import { PageHeader } from "@/components/page";
import { ResourceTable } from "@/components/resource-table";
import { StatusBadge } from "@/components/status";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { useApi } from "@/lib/api";
import { fmtDate } from "@/lib/utils";

type Tpl = { name: string; category: string; email_subject: string; email_body: string };
type Notif = { id: string; template: string; status: string; scheduled_for: string; sent_at: string | null; attempts: number; last_error: string | null };

export default function Email() {
  const { data } = useApi<Tpl[]>("/v1/admin/notifications/templates");
  return (
    <div>
      <PageHeader title="Email" description="Transactional email (confirmations, reminders, security alerts) from approved templates only." />
      <div className="mb-6 grid gap-4 md:grid-cols-2">
        {data?.map((t) => (
          <Card key={t.name}>
            <CardHeader><CardTitle>{t.name}</CardTitle></CardHeader>
            <CardContent className="text-xs">
              <p className="font-medium">{t.email_subject}</p>
              <p className="mt-2 whitespace-pre-wrap text-muted">{t.email_body}</p>
            </CardContent>
          </Card>
        ))}
      </div>
      <ResourceTable<Notif> path="/v1/admin/notifications/notifications?channel=email" rowKey={(r) => r.id} columns={[
        { key: "t", header: "Template", render: (r) => r.template },
        { key: "s", header: "Status", render: (r) => <StatusBadge value={r.status} /> },
        { key: "when", header: "Scheduled", render: (r) => fmtDate(r.scheduled_for) },
        { key: "sent", header: "Sent", render: (r) => fmtDate(r.sent_at) },
        { key: "a", header: "Attempts", render: (r) => r.attempts },
        { key: "err", header: "Note", render: (r) => r.last_error ?? "—" },
      ]} />
    </div>
  );
}
