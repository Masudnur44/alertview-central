<!-- LOVABLE:BEGIN -->
> [!IMPORTANT]
> This project is connected to [Lovable](https://lovable.dev). Avoid rewriting
> published git history — force pushing, or rebasing/amending/squashing commits
> that are already pushed — as it rewrites history on Lovable's side and the
> user will likely lose their project history.
>
> Commits you push to the connected branch sync back to Lovable and show up in
> the editor, so keep the branch in a working state.
<!-- LOVABLE:END -->

## FINPAY SOC
- Signed-in pages live under src/routes/_authenticated and read data with the browser client; RLS (is_soc_member / can_operate / has_role) is the security boundary.
- Monitoring/detection logic lives in src/lib/monitor.server.ts and is shared by the run-checks server fn, /api/public/checks (cron secret) and /api/public/ingest (per-source x-soc-key).
