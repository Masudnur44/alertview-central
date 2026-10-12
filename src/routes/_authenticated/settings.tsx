import { createFileRoute } from "@tanstack/react-router";
import { z } from "zod";
import { PageHeader } from "@/components/soc/ui";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { TeamPanel } from "@/components/soc/settings/TeamPanel";
import { SourcesPanel } from "@/components/soc/settings/SourcesPanel";
import { RulesPanel } from "@/components/soc/settings/RulesPanel";
import { ChannelsPanel } from "@/components/soc/settings/ChannelsPanel";
import { PlatformPanel } from "@/components/soc/settings/PlatformPanel";
import { AuditPanel } from "@/components/soc/settings/AuditPanel";
import { useMe } from "@/lib/session";
import { can, roleLabel } from "@/lib/permissions";

export const Route = createFileRoute("/_authenticated/settings")({
  validateSearch: z.object({ tab: z.string().max(20).optional() }),
  head: () => ({ meta: [{ title: "Settings — FINPAY SOC" }, { name: "description", content: "Team, event sources, detections, notifications, platform and audit." }] }),
  component: Settings,
});

function Settings() {
  const me = useMe();
  const search = Route.useSearch();
  const navigate = Route.useNavigate();
  const tabs = [
    { id: "team", label: "Team & access", show: can(me.roles, "users.manage"), el: <TeamPanel /> },
    { id: "sources", label: "Event sources", show: can(me.roles, "sources.manage"), el: <SourcesPanel /> },
    { id: "rules", label: "Detection rules", show: true, el: <RulesPanel /> },
    { id: "channels", label: "Notifications", show: can(me.roles, "channels.manage"), el: <ChannelsPanel /> },
    { id: "platform", label: "Platform & intel", show: true, el: <PlatformPanel /> },
    { id: "audit", label: "Audit trail", show: can(me.roles, "audit.view"), el: <AuditPanel /> },
  ].filter((t) => t.show);
  const active = tabs.find((t) => t.id === search.tab)?.id ?? tabs[0]!.id;
  return (
    <div>
      <PageHeader title="Settings" sub={`Signed in as ${me.displayName} · ${me.roles.map(roleLabel).join(", ")}`} />
      <Tabs value={active} onValueChange={(v) => navigate({ search: { tab: v }, replace: true })}>
        <TabsList className="mb-4 flex h-auto flex-wrap justify-start">
          {tabs.map((t) => <TabsTrigger key={t.id} value={t.id}>{t.label}</TabsTrigger>)}
        </TabsList>
        {tabs.map((t) => <TabsContent key={t.id} value={t.id}>{t.el}</TabsContent>)}
      </Tabs>
    </div>
  );
}
