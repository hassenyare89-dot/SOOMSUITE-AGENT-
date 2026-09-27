"use client";

import { PageHeader } from "@/components/page";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { useApi } from "@/lib/api";

type R = { role: string; permissions: string[]; mfa_required_permissions: string[] };

export default function Roles() {
  const { data } = useApi<R[]>("/v1/admin/identity/roles");
  return (
    <div>
      <PageHeader title="Roles" description="The RBAC catalog is defined in code and changed only via review. Permissions marked * require an MFA/passkey session." />
      <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-3">
        {data?.map((r) => (
          <Card key={r.role}><CardHeader><CardTitle>{r.role}</CardTitle></CardHeader>
            <CardContent><ul className="space-y-0.5 font-mono text-xs">{r.permissions.map((p) => (
              <li key={p}>{p}{r.mfa_required_permissions.includes(p) ? " *" : ""}</li>))}</ul></CardContent></Card>
        ))}
      </div>
    </div>
  );
}
