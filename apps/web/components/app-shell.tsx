"use client";

import {
  Activity, Bot, Building2, CalendarDays, ClipboardCheck, FileSearch, Gauge, Globe, KeyRound,
  LayoutDashboard, LibraryBig, LogOut, Mail, MessageSquare, MessagesSquare, Plug, Radar,
  ScrollText, Settings2, Shield, ShieldAlert, ShieldCheck, Siren, Target, Users, UserSquare,
  Bug, Waves, Workflow, Lightbulb, Building,
} from "lucide-react";
import Link from "next/link";
import { usePathname } from "next/navigation";
import * as React from "react";
import { useSession } from "@/components/session";
import { api } from "@/lib/api";
import { cn } from "@/lib/utils";

type Item = { href: string; label: string; icon: typeof Activity; perm?: string };
const NAV: { section: string; perm?: string; items: Item[] }[] = [
  { section: "Overview", items: [{ href: "/", label: "Dashboard", icon: LayoutDashboard }] },
  {
    section: "SAMIIR", perm: "conversation:read",
    items: [
      { href: "/samiir/conversations", label: "Conversations", icon: MessagesSquare },
      { href: "/samiir/contacts", label: "Contacts", icon: UserSquare, perm: "crm:read" },
      { href: "/samiir/companies", label: "Companies", icon: Building2, perm: "crm:read" },
      { href: "/samiir/leads", label: "Leads", icon: Target, perm: "crm:read" },
      { href: "/samiir/pipeline", label: "CRM pipeline", icon: Workflow, perm: "crm:read" },
      { href: "/samiir/appointments", label: "Appointments", icon: CalendarDays },
      { href: "/samiir/knowledge", label: "Knowledge base", icon: LibraryBig },
      { href: "/samiir/whatsapp", label: "WhatsApp", icon: MessageSquare },
      { href: "/samiir/email", label: "Email", icon: Mail },
    ],
  },
  {
    section: "FATMA", perm: "incident:read",
    items: [
      { href: "/fatma", label: "SOC overview", icon: Radar },
      { href: "/fatma/alerts", label: "Security alerts", icon: Siren },
      { href: "/fatma/incidents", label: "Incidents", icon: ShieldAlert },
      { href: "/fatma/assets", label: "Assets", icon: Globe },
      { href: "/fatma/findings", label: "Vulnerability findings", icon: FileSearch },
      { href: "/fatma/scans", label: "Scan history", icon: Activity },
      { href: "/fatma/risk", label: "Risk dashboard", icon: Gauge },
      { href: "/fatma/malware", label: "Malware events", icon: Bug },
      { href: "/fatma/ddos", label: "DDoS events", icon: Waves },
      { href: "/fatma/waf", label: "WAF events", icon: Shield },
      { href: "/fatma/recommendations", label: "Recommendations", icon: Lightbulb },
      { href: "/fatma/ask", label: "Ask FATMA", icon: Bot, perm: "fatma:ask" },
    ],
  },
  {
    section: "Administration",
    items: [
      { href: "/admin/users", label: "Users", icon: Users, perm: "tenant:user:manage" },
      { href: "/admin/roles", label: "Roles", icon: KeyRound },
      { href: "/admin/tenant", label: "Tenant", icon: Building, perm: "tenant:settings:manage" },
      { href: "/admin/integrations", label: "Integrations", icon: Plug, perm: "tenant:integration:manage" },
      { href: "/admin/audit", label: "Audit log", icon: ScrollText, perm: "audit:read" },
      { href: "/admin/agents", label: "Agent configuration", icon: Settings2, perm: "agent:config:manage" },
      { href: "/admin/approvals", label: "Approvals", icon: ClipboardCheck, perm: "approval:read" },
      { href: "/admin/security", label: "Security settings", icon: ShieldCheck },
    ],
  },
];

export function AppShell({ children }: { children: React.ReactNode }) {
  const { me, can } = useSession();
  const path = usePathname();
  async function logout() {
    await api("/auth/logout", { method: "POST" }).catch(() => undefined);
    window.location.href = "/login";
  }
  return (
    <div className="flex min-h-screen">
      <aside className="hidden w-64 shrink-0 border-r border-border bg-surface md:block">
        <div className="border-b border-border px-4 py-4">
          <p className="text-sm font-semibold">SAMIIR + FATMA</p>
          <p className="truncate text-xs text-muted">{me?.tenant_name}</p>
        </div>
        <nav className="space-y-4 p-3 text-sm" aria-label="Primary">
          {NAV.filter((s) => !s.perm || can(s.perm)).map((s) => (
            <div key={s.section}>
              <p className="px-2 pb-1 text-xs font-medium uppercase tracking-wide text-subtle">{s.section}</p>
              {s.items.filter((i) => !i.perm || can(i.perm)).map((i) => {
                const active = i.href === "/" ? path === "/" : path.startsWith(i.href) &&
                  !(i.href === "/fatma" && path !== "/fatma");
                return (
                  <Link key={i.href} href={i.href}
                        className={cn("flex items-center gap-2 rounded-md px-2 py-1.5 text-muted hover:bg-background hover:text-foreground",
                                      active && "bg-background font-medium text-foreground")}>
                    <i.icon aria-hidden className="h-4 w-4" />{i.label}
                  </Link>
                );
              })}
            </div>
          ))}
        </nav>
      </aside>
      <div className="flex min-w-0 flex-1 flex-col">
        <header className="flex items-center justify-between border-b border-border bg-surface px-6 py-3">
          <p className="text-sm text-muted">
            {me?.display_name} · {me?.roles.join(", ")}
            {me?.mfa ? " · MFA verified" : " · MFA not verified"}
          </p>
          <button onClick={() => void logout()} className="inline-flex items-center gap-1 text-sm text-muted hover:text-foreground">
            <LogOut aria-hidden className="h-4 w-4" /> Sign out
          </button>
        </header>
        <main className="min-w-0 flex-1 p-6">{children}</main>
      </div>
    </div>
  );
}
