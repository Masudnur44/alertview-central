# FINPAY SOC in Codespaces

The codespace installs everything, creates a PostgreSQL database, loads the FINPAYTECH demo data and starts the app and worker. Port **8080** opens as a live preview.

1. Open the **Ports** tab → port 8080 → globe icon to open it in a browser tab (the in-editor preview works too).
2. Choose **Request access** and sign up with `masudn058@gmail.com` (the bootstrap admin set in `.env.local`) — you are approved as Security Administrator automatically.
3. Code changes reload instantly.

Logs: `tail -f /tmp/soc-app.log /tmp/soc-worker.log` · Restart: `bash .devcontainer/start.sh` · Reset demo data: `npm run db:seed-demo -- --remove && npm run db:seed-demo`

Two-factor is off in the codespace (`REQUIRE_MFA=false` in `.env.local`) to keep previewing quick; it is on by default in production.
External checks cannot reach the demo FINPAYTECH hosts from here; add any public website as an asset to see live checks.
