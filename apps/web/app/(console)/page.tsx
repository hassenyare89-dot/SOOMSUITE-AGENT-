"use client";

import { Can, useSession } from "@/components/session";
import { PageHeader, StatTile } from "@/components/page";
import { SocWidgets, type Overview } from "@/components/soc/widgets";
import { useApi, useRealtime } from "@/lib/api";

type CrmMetrics = { new_leads_30d: number; won_30d: number; activities_30d: number;
  pipeline: { stage: string; count: number; value: string }[] };

export default function Dashboard() {
  const { can } = useSession();
  const crm = useApi<CrmMetrics>(can("crm:read") ? "/v1/admin/crm/metrics" : null);
  const soc = useApi<Overview>(can("incident:read") ? "/v1/admin/fatma/soc/overview" : null);
  useRealtime("samiir,fatma", ["lead.updated", "pipeline.changed", "appointment.booked",
                               "incident.updated"], () => { void crm.reload(); void soc.reload(); });
  return (
    <div>
      <PageHeader title="Dashboard" description="Live overview of customer operations and security posture." />
      <Can perm="crm:read">
        <h2 className="mb-2 text-sm font-semibold">SAMIIR · customer operations</h2>
        <div className="mb-8 grid grid-cols-2 gap-4 lg:grid-cols-4">
          <StatTile label="New leads (30d)" value={crm.data?.new_leads_30d ?? "—"} />
          <StatTile label="Won (30d)" value={crm.data?.won_30d ?? "—"} />
          <StatTile label="CRM activities (30d)" value={crm.data?.activities_30d ?? "—"} />
          <StatTile label="Appointments booked"
                    value={crm.data?.pipeline.find((p) => p.stage === "APPOINTMENT_BOOKED")?.count ?? "—"}
                    hint="Opportunities in APPOINTMENT_BOOKED" />
        </div>
      </Can>
      <Can perm="incident:read">
        <h2 className="mb-2 text-sm font-semibold">FATMA · security operations</h2>
        {soc.data ? <SocWidgets o={soc.data} /> : <p className="text-sm text-muted">Loading…</p>}
      </Can>
    </div>
  );
}
