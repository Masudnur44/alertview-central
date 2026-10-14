// Renders an issue brief: what is wrong, impact, where, when, evidence, likely causes and fix steps.
// Used by the SOC (alert diagnosis, issue page) and by developers (secure link, My issues).
import { AlertTriangle, CheckCircle2, Crosshair, Lightbulb, ListChecks, MapPin, Search, Clock } from "lucide-react";
import type { Brief } from "@/lib/types";

type Props = { brief: Brief; compact?: boolean };

function Rows({ rows }: { rows: { label: string; value: string }[] }) {
  if (!rows.length) return null;
  return (
    <dl className="grid grid-cols-[minmax(110px,max-content)_1fr] gap-x-4 gap-y-1 text-xs">
      {rows.map((r, i) => (
        <div key={i} className="contents">
          <dt className="text-muted-foreground">{r.label}</dt>
          <dd className="data break-words">{r.value}</dd>
        </div>
      ))}
    </dl>
  );
}

function Section({ icon: Icon, title, children }: { icon: typeof MapPin; title: string; children: React.ReactNode }) {
  return (
    <section className="mt-4">
      <h4 className="data mb-1.5 flex items-center gap-1.5 text-[11px] font-bold uppercase tracking-[0.15em] text-muted-foreground">
        <Icon className="h-3.5 w-3.5 text-primary" /> {title}
      </h4>
      {children}
    </section>
  );
}

export function BriefView({ brief, compact }: Props) {
  return (
    <div>
      <p className="text-sm">{brief.meaning}</p>
      <p className="mt-2 flex items-start gap-2 rounded border border-sev-high/30 bg-sev-high/10 p-2 text-xs text-sev-high">
        <AlertTriangle className="mt-0.5 h-3.5 w-3.5 shrink-0" /> {brief.impact}
      </p>
      <Section icon={MapPin} title="Where"><Rows rows={brief.where} /></Section>
      <Section icon={Clock} title="When"><Rows rows={brief.when} /></Section>
      {brief.checks.length > 0 && (
        <div className="mt-2 flex items-center gap-1">
          <span className="data mr-1 text-[10px] text-muted-foreground">recent checks</span>
          {[...brief.checks].reverse().map((c, i) => (
            <span key={i} title={`${new Date(c.at).toLocaleString()} — ${c.detail}`} className={`h-4 w-1.5 rounded-sm ${c.ok ? "bg-ok/70" : "bg-sev-critical"}`} />
          ))}
        </div>
      )}
      <Section icon={Crosshair} title="Evidence"><Rows rows={compact ? brief.evidence.slice(0, 6) : brief.evidence} /></Section>
      {!compact && brief.events.length > 0 && (
        <Section icon={ListChecks} title="Related events">
          <ul className="data space-y-0.5 text-[11px]">
            {brief.events.map((e, i) => (
              <li key={i} className="truncate">
                <span className="text-muted-foreground">{new Date(e.at).toLocaleTimeString()}</span>{" "}
                <span className="text-primary">{e.type}</span> {e.user ?? ""} <span className={e.outcome === "failure" ? "text-sev-high" : ""}>{e.outcome ?? ""}</span>{" "}
                <span className="text-muted-foreground">{e.ip ?? ""} {e.message ?? ""}</span>
              </li>
            ))}
          </ul>
        </Section>
      )}
      {brief.causes.length > 0 && (
        <Section icon={Lightbulb} title="Likely causes">
          <ul className="list-disc space-y-0.5 pl-5 text-xs">{brief.causes.map((c, i) => <li key={i}>{c}</li>)}</ul>
        </Section>
      )}
      {brief.whereToLook.length > 0 && (
        <Section icon={Search} title="Where to look">
          <ul className="list-disc space-y-0.5 pl-5 text-xs">{brief.whereToLook.map((c, i) => <li key={i}>{c}</li>)}</ul>
        </Section>
      )}
      {brief.fix.length > 0 && (
        <Section icon={CheckCircle2} title="How to fix">
          <ol className="list-decimal space-y-0.5 pl-5 text-xs">{brief.fix.map((c, i) => <li key={i}>{c}</li>)}</ol>
          <p className="mt-2 text-[11px] text-muted-foreground">{brief.verify}</p>
        </Section>
      )}
    </div>
  );
}
