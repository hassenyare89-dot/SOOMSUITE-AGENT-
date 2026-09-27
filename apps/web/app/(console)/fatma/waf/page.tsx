"use client";

import { EventsTable } from "@/components/fatma/events-table";
import { PageHeader } from "@/components/page";

export default function Waf() {
  return (
    <div>
      <PageHeader title="WAF events" description="Cloudflare and AWS WAF events (blocked, challenged and logged requests)." />
      <EventsTable query="?source=cloudflare" />
      <div className="mt-8"><EventsTable query="?source=aws_waf" /></div>
    </div>
  );
}
