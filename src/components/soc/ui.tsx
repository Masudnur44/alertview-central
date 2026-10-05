import type { ReactNode } from "react";
import { formatDistanceToNowStrict } from "date-fns";
import { cn } from "@/lib/utils";

export type Severity = "critical" | "high" | "medium" | "low" | "info";
export const SEVERITIES: Severity[] = ["critical", "high", "medium", "low", "info"];

const sevClass: Record<Severity, string> = {
  critical: "bg-sev-critical/15 text-sev-critical border-sev-critical/40",
  high: "bg-sev-high/15 text-sev-high border-sev-high/40",
  medium: "bg-sev-medium/15 text-sev-medium border-sev-medium/40",
  low: "bg-sev-low/15 text-sev-low border-sev-low/40",
  info: "bg-sev-info/15 text-sev-info border-sev-info/40",
};
export const sevText: Record<Severity, string> = {
  critical: "text-sev-critical", high: "text-sev-high", medium: "text-sev-medium", low: "text-sev-low", info: "text-sev-info",
};

export function SeverityBadge({ s }: { s: Severity }) {
  return (
    <span className={cn("data inline-flex rounded border px-1.5 py-0.5 text-[10px] font-bold uppercase tracking-wider", sevClass[s])}>
      {s}
    </span>
  );
}

export function StatusPill({ status }: { status: string }) {
  const good = ["online", "resolved", "closed", "fixed", "contained"].includes(status);
  const bad = ["offline", "new", "escalated", "open"].includes(status);
  return (
    <span className={cn("data inline-flex items-center gap-1.5 text-xs", good ? "text-ok" : bad ? "text-sev-high" : "text-muted-foreground")}>
      <span className={cn("h-1.5 w-1.5 rounded-full", good ? "bg-ok" : bad ? "bg-sev-high" : "bg-muted-foreground")} />
      {status.replace(/_/g, " ")}
    </span>
  );
}

export function Panel({ title, action, children, className }: { title?: string; action?: ReactNode; children: ReactNode; className?: string }) {
  return (
    <section className={cn("rounded-lg border bg-card", className)}>
      {title && (
        <header className="flex items-center justify-between border-b px-4 py-2.5">
          <h2 className="data text-[11px] font-bold uppercase tracking-[0.2em] text-muted-foreground">{title}</h2>
          {action}
        </header>
      )}
      <div className="p-4">{children}</div>
    </section>
  );
}

export function PageHeader({ title, sub, action }: { title: string; sub?: string; action?: ReactNode }) {
  return (
    <div className="mb-6 flex flex-wrap items-end justify-between gap-4">
      <div>
        <h1 className="text-2xl font-semibold">{title}</h1>
        {sub && <p className="mt-1 text-sm text-muted-foreground">{sub}</p>}
      </div>
      {action}
    </div>
  );
}

export function Stat({ label, value, tone, hint }: { label: string; value: ReactNode; tone?: string; hint?: string }) {
  return (
    <div className="rounded-lg border bg-card p-4">
      <p className="data text-[10px] uppercase tracking-[0.2em] text-muted-foreground">{label}</p>
      <p className={cn("data mt-2 text-3xl font-bold", tone)}>{value}</p>
      {hint && <p className="mt-1 text-xs text-muted-foreground">{hint}</p>}
    </div>
  );
}

export function ago(d?: string | null) {
  if (!d) return "—";
  return formatDistanceToNowStrict(new Date(d), { addSuffix: true });
}

export function Th({ children }: { children?: ReactNode }) {
  return <th className="data px-3 py-2 text-left text-[10px] font-bold uppercase tracking-[0.15em] text-muted-foreground">{children}</th>;
}
export function Td({ children, className }: { children?: ReactNode; className?: string }) {
  return <td className={cn("px-3 py-2.5 text-sm", className)}>{children}</td>;
}
export function Table({ children }: { children: ReactNode }) {
  return (
    <div className="overflow-x-auto rounded-lg border bg-card">
      <table className="w-full [&_tbody_tr]:border-t [&_tbody_tr:hover]:bg-accent/40">{children}</table>
    </div>
  );
}
