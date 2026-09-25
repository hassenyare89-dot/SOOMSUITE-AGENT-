"use client";

import * as React from "react";
import { PageHeader } from "@/components/page";
import { ResourceTable } from "@/components/resource-table";
import { StatusBadge } from "@/components/status";
import { Button } from "@/components/ui/button";
import { useRealtime } from "@/lib/api";
import { fmtDate } from "@/lib/utils";

type Appt = { id: string; appointment_type: string | null; starts_at: string; ends_at: string;
  timezone: string; status: string; provider: string; external_event_id: string | null };

export default function Appointments() {
  const [upcoming, setUpcoming] = React.useState(true);
  const [tick, setTick] = React.useState(0);
  useRealtime("samiir", ["appointment.booked"], () => setTick((t) => t + 1));
  return (
    <div>
      <PageHeader title="Appointments" description="Booked through SAMIIR against real calendar availability (no double-booking)."
        actions={<Button variant="outline" onClick={() => setUpcoming(!upcoming)}>{upcoming ? "Show all" : "Upcoming only"}</Button>} />
      <ResourceTable<Appt> path={`/v1/admin/scheduling/appointments?upcoming=${upcoming}`} rowKey={(r) => r.id}
        reloadSignal={tick} columns={[
          { key: "type", header: "Type", render: (r) => r.appointment_type ?? "—" },
          { key: "start", header: "Starts", render: (r) => fmtDate(r.starts_at) },
          { key: "tz", header: "Customer TZ", render: (r) => r.timezone },
          { key: "status", header: "Status", render: (r) => <StatusBadge value={r.status} /> },
          { key: "provider", header: "Calendar", render: (r) => r.provider },
        ]} />
    </div>
  );
}
