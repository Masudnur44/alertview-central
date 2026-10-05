import { createFileRoute, Outlet, redirect, Link, useNavigate } from "@tanstack/react-router";
import { useQueryClient } from "@tanstack/react-query";
import {
  LayoutDashboard, Server, Radar, Siren, FolderKanban, Bug, Activity, FileBarChart, Settings, ShieldCheck, LogOut,
} from "lucide-react";
import { supabase } from "@/integrations/supabase/client";

export const Route = createFileRoute("/_authenticated")({
  ssr: false,
  beforeLoad: async () => {
    const { data, error } = await supabase.auth.getUser();
    if (error || !data.user) throw redirect({ to: "/auth" });
    return { user: data.user };
  },
  component: Shell,
});

const nav = [
  { to: "/dashboard", label: "Overview", icon: LayoutDashboard },
  { to: "/assets", label: "Assets", icon: Server },
  { to: "/surface", label: "External Surface", icon: Radar },
  { to: "/alerts", label: "Alerts", icon: Siren },
  { to: "/incidents", label: "Incidents", icon: FolderKanban },
  { to: "/vulnerabilities", label: "Vulnerabilities", icon: Bug },
  { to: "/activity", label: "Activity", icon: Activity },
  { to: "/reports", label: "Reports", icon: FileBarChart },
  { to: "/settings", label: "Settings", icon: Settings },
] as const;

function Shell() {
  const { user } = Route.useRouteContext();
  const navigate = useNavigate();
  const qc = useQueryClient();
  async function signOut() {
    await qc.cancelQueries();
    qc.clear();
    await supabase.auth.signOut();
    navigate({ to: "/auth", replace: true });
  }
  return (
    <div className="flex min-h-screen">
      <aside className="sticky top-0 hidden h-screen w-60 shrink-0 flex-col border-r border-sidebar-border bg-sidebar md:flex">
        <div className="flex items-center gap-2 px-5 py-5">
          <ShieldCheck className="h-5 w-5 text-primary" />
          <span className="data text-xs font-bold tracking-widest">FINPAY//SOC</span>
        </div>
        <div className="data mx-5 mb-4 flex items-center gap-2 rounded border border-ok/30 bg-ok/10 px-2 py-1 text-[10px] uppercase tracking-widest text-ok">
          <span className="pulse-dot h-1.5 w-1.5 rounded-full bg-ok" /> Live · 24/7
        </div>
        <nav className="flex-1 space-y-0.5 px-3">
          {nav.map(({ to, label, icon: Icon }) => (
            <Link key={to} to={to}
              className="flex items-center gap-3 rounded-md px-3 py-2 text-sm text-sidebar-foreground/75 hover:bg-sidebar-accent hover:text-sidebar-accent-foreground"
              activeProps={{ className: "bg-sidebar-accent text-primary! border-l-2 border-primary" }}>
              <Icon className="h-4 w-4" /> {label}
            </Link>
          ))}
        </nav>
        <div className="border-t border-sidebar-border p-4">
          <p className="truncate text-xs text-muted-foreground">{user.email}</p>
          <button onClick={signOut} className="mt-2 flex items-center gap-2 text-xs text-muted-foreground hover:text-foreground">
            <LogOut className="h-3.5 w-3.5" /> Sign out
          </button>
        </div>
      </aside>
      <div className="flex min-w-0 flex-1 flex-col">
        <div className="flex gap-1 overflow-x-auto border-b px-3 py-2 md:hidden">
          {nav.map(({ to, label }) => (
            <Link key={to} to={to} className="whitespace-nowrap rounded px-2 py-1 text-xs text-muted-foreground"
              activeProps={{ className: "bg-accent text-primary!" }}>{label}</Link>
          ))}
        </div>
        <main className="flex-1 p-6 lg:p-8"><Outlet /></main>
      </div>
    </div>
  );
}
