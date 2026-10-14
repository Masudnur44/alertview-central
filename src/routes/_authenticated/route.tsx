import { createFileRoute, Outlet, redirect, Link, useNavigate } from "@tanstack/react-router";
import { useQueryClient } from "@tanstack/react-query";
import {
  LayoutDashboard, Server, Radar, Siren, FolderKanban, Bug, Activity, FileBarChart, Settings, ShieldCheck, LogOut, UserCog, MonitorDot, Send, Wrench,
} from "lucide-react";
import { getSession, signOut } from "@/lib/api/auth.functions";
import { roleLabel } from "@/lib/permissions";

export const Route = createFileRoute("/_authenticated")({
  ssr: false,
  beforeLoad: async ({ location }) => {
    const session = await getSession();
    if (!session) throw redirect({ to: "/auth" });
    if (session.needsMfa) throw redirect({ to: "/auth/mfa" });
    if (session.user.status !== "active") throw redirect({ to: "/pending" });
    if (session.mustEnrollMfa && location.pathname !== "/account") throw redirect({ to: "/account", search: { setup: "mfa" } });
    // Developers only see the issues handed to their team.
    const developerOnly = session.user.roles.length > 0 && session.user.roles.every((r) => r === "developer");
    if (developerOnly && !location.pathname.startsWith("/my-issues") && location.pathname !== "/account") throw redirect({ to: "/my-issues" });
    return { session };
  },
  component: Shell,
});

const devNav = [{ to: "/my-issues", label: "My issues", icon: Wrench }] as const;

const nav = [
  { to: "/command", label: "Command Center", icon: MonitorDot },
  { to: "/dashboard", label: "Overview", icon: LayoutDashboard },
  { to: "/assets", label: "Assets", icon: Server },
  { to: "/surface", label: "External Surface", icon: Radar },
  { to: "/alerts", label: "Alerts", icon: Siren },
  { to: "/issues", label: "Issues to devs", icon: Send },
  { to: "/incidents", label: "Incidents", icon: FolderKanban },
  { to: "/vulnerabilities", label: "Vulnerabilities", icon: Bug },
  { to: "/activity", label: "Activity", icon: Activity },
  { to: "/reports", label: "Reports", icon: FileBarChart },
  { to: "/settings", label: "Settings", icon: Settings },
] as const;

function Shell() {
  const { session } = Route.useRouteContext();
  const navigate = useNavigate();
  const qc = useQueryClient();
  const enrolling = session.mustEnrollMfa;
  const developerOnly = session.user.roles.every((r) => r === "developer");
  const items = developerOnly ? devNav : nav;
  async function doSignOut() {
    await qc.cancelQueries();
    qc.clear();
    await signOut();
    navigate({ to: "/auth", replace: true });
  }
  return (
    <div className="flex min-h-screen">
      <aside className="sticky top-0 hidden h-screen w-60 print:hidden shrink-0 flex-col border-r border-sidebar-border bg-sidebar md:flex">
        <div className="flex items-center gap-2 px-5 py-5">
          <ShieldCheck className="h-5 w-5 text-primary" />
          <span className="data text-xs font-bold tracking-widest">FINPAY//SOC</span>
        </div>
        <div className="data mx-5 mb-4 flex items-center gap-2 rounded border border-ok/30 bg-ok/10 px-2 py-1 text-[10px] uppercase tracking-widest text-ok">
          <span className="pulse-dot h-1.5 w-1.5 rounded-full bg-ok" /> Live · 24/7
        </div>
        <nav className="flex-1 space-y-0.5 overflow-y-auto px-3">
          {!enrolling && items.map(({ to, label, icon: Icon }) => (
            <Link key={to} to={to}
              className="flex items-center gap-3 rounded-md px-3 py-2 text-sm text-sidebar-foreground/75 hover:bg-sidebar-accent hover:text-sidebar-accent-foreground"
              activeProps={{ className: "bg-sidebar-accent text-primary! border-l-2 border-primary" }}>
              <Icon className="h-4 w-4" /> {label}
            </Link>
          ))}
        </nav>
        <div className="border-t border-sidebar-border p-4">
          <p className="truncate text-sm">{session.user.displayName}</p>
          <p className="truncate text-xs text-muted-foreground">{session.user.email}</p>
          <p className="data mt-1 truncate text-[10px] uppercase tracking-wider text-primary/80">{session.user.roles.map(roleLabel).join(" · ")}</p>
          <div className="mt-3 flex gap-4">
            <Link to="/account" className="flex items-center gap-1.5 text-xs text-muted-foreground hover:text-foreground"><UserCog className="h-3.5 w-3.5" /> Account</Link>
            <button onClick={doSignOut} className="flex items-center gap-1.5 text-xs text-muted-foreground hover:text-foreground">
              <LogOut className="h-3.5 w-3.5" /> Sign out
            </button>
          </div>
        </div>
      </aside>
      <div className="flex min-w-0 flex-1 flex-col">
        <div className="flex gap-1 overflow-x-auto border-b px-3 py-2 md:hidden print:hidden">
          {!enrolling && items.map(({ to, label }) => (
            <Link key={to} to={to} className="whitespace-nowrap rounded px-2 py-1 text-xs text-muted-foreground"
              activeProps={{ className: "bg-accent text-primary!" }}>{label}</Link>
          ))}
          <Link to="/account" className="whitespace-nowrap rounded px-2 py-1 text-xs text-muted-foreground">Account</Link>
          <button onClick={doSignOut} className="whitespace-nowrap rounded px-2 py-1 text-xs text-muted-foreground">Sign out</button>
        </div>
        <main className="flex-1 p-4 sm:p-6 lg:p-8"><Outlet /></main>
      </div>
    </div>
  );
}
