"use client";

import { PageHeader } from "@/components/page";
import { SocWidgets, type Overview } from "@/components/soc/widgets";
import { useApi, useRealtime } from "@/lib/api";

export default function SocOverview() {
  const { data, error, reload } = useApi<Overview>("/v1/admin/fatma/soc/overview");
  useRealtime("fatma", ["incident.updated", "scan.updated", "action.updated"], () => void reload());
  return (
    <div>
      <PageHeader title="SOC overview" description="FATMA's defensive view of your verified assets." />
      {error ? <p className="text-sm text-critical">{error}</p> : null}
      {data ? <SocWidgets o={data} /> : <p className="text-sm text-muted">Loading…</p>}
    </div>
  );
}
