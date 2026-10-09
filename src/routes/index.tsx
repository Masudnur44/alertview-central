import { createFileRoute, Link } from "@tanstack/react-router";
import { ShieldCheck, Radar, Siren, Activity } from "lucide-react";

export const Route = createFileRoute("/")({
  head: () => ({
    meta: [
      { title: "FINPAY SOC — Security Operations Center" },
      { name: "description", content: "Continuous monitoring, detection and incident response for FINPAYTECH." },
      { property: "og:title", content: "FINPAY SOC — Security Operations Center" },
      { property: "og:description", content: "Continuous monitoring, detection and incident response for FINPAYTECH." },
      { property: "og:type", content: "website" },
      { name: "twitter:card", content: "summary_large_image" },
    ],
  }),
  component: Landing,
});

function Landing() {
  const items = [
    { icon: Radar, t: "Attack surface", d: "Domains, APIs, IPs and certificates watched around the clock." },
    { icon: Siren, t: "Detection", d: "Rules mapped to MITRE ATT&CK raise prioritized alerts." },
    { icon: Activity, t: "Response", d: "Incidents with timelines, evidence and ownership." },
  ];
  return (
    <div className="min-h-screen">
      <header className="mx-auto flex max-w-6xl items-center justify-between px-6 py-6">
        <div className="flex items-center gap-2">
          <ShieldCheck className="h-6 w-6 text-primary" />
          <span className="data text-sm font-bold tracking-widest">FINPAY//SOC</span>
        </div>
        <Link to="/auth" className="rounded-md border border-primary/40 px-4 py-2 text-sm text-primary hover:bg-primary/10">
          Sign in
        </Link>
      </header>
      <main className="mx-auto max-w-6xl px-6 pt-20 pb-24">
        <p className="data flex items-center gap-2 text-xs uppercase tracking-[0.3em] text-ok">
          <span className="pulse-dot h-2 w-2 rounded-full bg-ok" /> Monitoring active
        </p>
        <h1 className="mt-6 max-w-3xl text-5xl font-semibold leading-tight md:text-6xl">
          One console for everything happening across FINPAYTECH.
        </h1>
        <p className="mt-6 max-w-xl text-lg text-muted-foreground">
          Assets, exposures, suspicious activity, vulnerabilities and incidents — continuously collected, correlated and prioritized.
        </p>
        <Link to="/auth" className="glow mt-10 inline-flex rounded-md bg-primary px-6 py-3 font-medium text-primary-foreground">
          Enter the SOC
        </Link>
        <div className="mt-24 grid gap-4 md:grid-cols-3">
          {items.map(({ icon: Icon, t, d }) => (
            <div key={t} className="rounded-lg border bg-card p-6">
              <Icon className="h-5 w-5 text-primary" />
              <h3 className="mt-4 font-semibold">{t}</h3>
              <p className="mt-2 text-sm text-muted-foreground">{d}</p>
            </div>
          ))}
        </div>
      </main>
      <footer className="border-t">
        <div className="mx-auto flex max-w-6xl flex-wrap items-center justify-between gap-4 px-6 py-8">
          <span className="data text-xs tracking-widest text-muted-foreground">FINPAY//SOC — FINPAYTECH</span>
          <div className="flex items-center gap-6 text-sm">
            <a href="mailto:masudn058@gmail.com" className="text-primary hover:underline">masudn058@gmail.com</a>
            <a href="tel:+254703480258" className="text-primary hover:underline">0703 480 258</a>
          </div>
        </div>
      </footer>
    </div>
  );
}
