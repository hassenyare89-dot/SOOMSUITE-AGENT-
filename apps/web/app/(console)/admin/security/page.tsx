"use client";

import { PageHeader } from "@/components/page";
import { Card, CardContent } from "@/components/ui/card";
import { useApi } from "@/lib/api";

export default function SecuritySettings() {
  const { data } = useApi<Record<string, unknown>>("/v1/admin/identity/security-settings");
  return (
    <div>
      <PageHeader title="Security settings" description="Effective platform security configuration (read-only; changed through deployment configuration)." />
      <Card><CardContent className="pt-4">
        <dl className="grid gap-3 text-sm md:grid-cols-2">
          {data ? Object.entries(data).map(([k, v]) => (
            <div key={k}><dt className="text-xs text-muted">{k.replaceAll("_", " ")}</dt>
              <dd className="font-mono text-xs">{typeof v === "object" ? JSON.stringify(v) : String(v)}</dd></div>
          )) : null}
        </dl>
      </CardContent></Card>
    </div>
  );
}
