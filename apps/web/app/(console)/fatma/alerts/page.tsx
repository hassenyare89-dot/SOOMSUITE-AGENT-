"use client";

import * as React from "react";
import { EventsTable } from "@/components/fatma/events-table";
import { PageHeader } from "@/components/page";
import { Select } from "@/components/ui/input";

const CATS = ["", "sql_injection", "xss", "path_traversal", "web_attack", "credential_attack",
  "auth_anomaly", "bot", "ddos", "rate_anomaly", "malware", "vulnerability", "exposure", "waf_block"];

export default function Alerts() {
  const [cat, setCat] = React.useState("");
  return (
    <div>
      <PageHeader title="Security alerts" description="Normalized, redacted events from WAF/CDN, SIEM, application, proxy, auth and scanner sources."
        actions={<Select value={cat} onChange={(e) => setCat(e.target.value)} aria-label="Category">
          {CATS.map((c) => <option key={c} value={c}>{c || "All categories"}</option>)}</Select>} />
      <EventsTable query={cat ? `?category=${cat}` : "?category=sql_injection&category=xss&category=path_traversal&category=web_attack&category=credential_attack&category=auth_anomaly&category=bot&category=ddos&category=malware&category=waf_block&category=rate_anomaly&category=exposure&category=vulnerability"} />
    </div>
  );
}
