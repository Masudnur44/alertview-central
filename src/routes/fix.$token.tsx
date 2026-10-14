// Public page behind the secure link the SOC sends to developers (email / Telegram / WhatsApp).
// No login: the unguessable token in the URL is the credential. It expires, can be revoked,
// and only ever shows this one issue.
import { createFileRoute } from "@tanstack/react-router";
import { useMutation, useQuery } from "@tanstack/react-query";
import { toast } from "sonner";
import { ShieldAlert } from "lucide-react";
import { DevIssuePanel } from "@/components/soc/DevIssuePanel";
import { getIssueByLink, updateIssueByLink } from "@/lib/api/dev.functions";

export const Route = createFileRoute("/fix/$token")({
  head: () => ({
    meta: [
      { title: "Issue from the SOC — FINPAY" },
      { name: "robots", content: "noindex, nofollow" },
      { name: "referrer", content: "no-referrer" },
    ],
  }),
  ssr: false,
  component: FixPage,
});

const validToken = (t: string) => /^[A-Za-z0-9_-]{30,60}$/.test(t);

function FixPage() {
  const { token } = Route.useParams();
  const ok = validToken(token);
  const { data: issue, isLoading, error, refetch } = useQuery({
    queryKey: ["fix", token], queryFn: () => getIssueByLink({ data: { token } }), enabled: ok, retry: false,
  });
  const update = useMutation({
    mutationFn: (u: { status?: "acknowledged" | "in_progress" | "fixed"; comment?: string; name?: string }) =>
      updateIssueByLink({ data: { token, name: u.name ?? "", status: u.status, comment: u.comment } }),
    onSuccess: () => { toast.success("Thanks — the SOC can see your update"); refetch(); },
    onError: (e: Error) => toast.error(e.message),
  });

  return (
    <div className="min-h-screen bg-background px-4 py-6">
      <div className="mx-auto max-w-3xl">
        <div className="mb-5 flex items-center gap-2">
          <ShieldAlert className="h-5 w-5 text-primary" />
          <span className="font-semibold tracking-wide">FINPAY SOC</span>
          <span className="data text-[11px] text-muted-foreground">· issue sent to your team</span>
        </div>
        {!ok || (!isLoading && !issue) || error ? (
          <div className="rounded-lg border p-6 text-sm">
            <p className="font-semibold">This link is invalid or has expired.</p>
            <p className="mt-1 text-muted-foreground">{error instanceof Error && /Too many/.test(error.message) ? error.message : "Ask the SOC to send you a new link."}</p>
          </div>
        ) : isLoading || !issue ? (
          <p className="text-sm text-muted-foreground">Loading…</p>
        ) : (
          <DevIssuePanel issue={issue} askName busy={update.isPending} onUpdate={(u) => update.mutateAsync(u)} />
        )}
        <p className="mt-8 text-[11px] text-muted-foreground">Don't forward this link — anyone who has it can update this issue.</p>
      </div>
    </div>
  );
}
