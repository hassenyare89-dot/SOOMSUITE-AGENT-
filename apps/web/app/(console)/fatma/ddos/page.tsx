"use client";

import { EventsTable } from "@/components/fatma/events-table";
import { PageHeader } from "@/components/page";

export default function Ddos() {
  return (
    <div>
      <PageHeader title="DDoS events" description="Layer-7 floods, rate anomalies, edge DDoS mitigations and bot spikes from WAF/CDN telemetry." />
      <EventsTable query="?category=ddos&category=rate_anomaly&category=bot" />
    </div>
  );
}
