import { AlertOctagon, AlertTriangle, CheckCircle2, Info, ShieldAlert } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { cn } from "@/lib/utils";

/** Status colour is never used alone: every badge pairs an icon with a text label. */
const LEVELS: Record<string, { cls: string; Icon: typeof Info }> = {
  CRITICAL: { cls: "text-critical border-critical/40", Icon: AlertOctagon },
  critical: { cls: "text-critical border-critical/40", Icon: AlertOctagon },
  "HIGH RISK": { cls: "text-serious border-serious/40", Icon: ShieldAlert },
  high: { cls: "text-serious border-serious/40", Icon: ShieldAlert },
  HIGH: { cls: "text-serious border-serious/40", Icon: ShieldAlert },
  SUSPICIOUS: { cls: "text-warning border-warning/40", Icon: AlertTriangle },
  medium: { cls: "text-warning border-warning/40", Icon: AlertTriangle },
  MEDIUM: { cls: "text-warning border-warning/40", Icon: AlertTriangle },
  NORMAL: { cls: "text-good border-good/40", Icon: CheckCircle2 },
  low: { cls: "text-muted", Icon: Info },
  LOW: { cls: "text-muted", Icon: Info },
  info: { cls: "text-muted", Icon: Info },
  malicious: { cls: "text-critical border-critical/40", Icon: AlertOctagon },
  suspicious: { cls: "text-warning border-warning/40", Icon: AlertTriangle },
  clean: { cls: "text-good border-good/40", Icon: CheckCircle2 },
};

export function RiskBadge({ level }: { level: string | null | undefined }) {
  if (!level) return <span className="text-subtle">—</span>;
  const cfg = LEVELS[level] ?? { cls: "text-muted", Icon: Info };
  return (
    <Badge className={cn(cfg.cls)}>
      <cfg.Icon aria-hidden className="h-3 w-3" />
      {level}
    </Badge>
  );
}

export function ClaimBadge({ claim }: { claim: string }) {
  const confirmed = claim === "CONFIRMED INCIDENT";
  return (
    <Badge className={confirmed ? "border-critical/40 text-critical" : "text-muted"}>
      {confirmed ? <AlertOctagon aria-hidden className="h-3 w-3" /> : <Info aria-hidden className="h-3 w-3" />}
      {claim}
    </Badge>
  );
}

export function StatusBadge({ value }: { value: string | null | undefined }) {
  return <Badge className="text-muted">{value ?? "—"}</Badge>;
}
