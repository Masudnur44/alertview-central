import type { ReactNode } from "react";
import { ShieldCheck } from "lucide-react";

export function AuthCard({ children, title, sub }: { children: ReactNode; title: string; sub?: string }) {
  return (
    <div className="flex min-h-screen items-center justify-center px-4 py-10">
      <div className="w-full max-w-sm rounded-lg border bg-card p-8 glow">
        <div className="flex items-center gap-2">
          <ShieldCheck className="h-6 w-6 text-primary" />
          <span className="data text-sm font-bold tracking-widest">FINPAY//SOC</span>
        </div>
        <h1 className="mt-6 text-2xl font-semibold">{title}</h1>
        {sub && <p className="mt-1 text-sm text-muted-foreground">{sub}</p>}
        {children}
      </div>
    </div>
  );
}
