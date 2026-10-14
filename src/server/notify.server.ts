// Alert notifications. New alerts are queued by a database trigger (public.notifications);
// the worker delivers them here, with retries and back-off.
import { createHmac } from "node:crypto";
import { asSystem } from "./db.server";
import { env } from "./env.server";
import { decrypt, encrypt } from "./crypto.server";
import { sendMail, simpleHtml } from "./mail.server";
import { resolveTarget } from "./monitor/net.server";

export type ChannelKind = "email" | "slack" | "teams" | "telegram" | "webhook";

export type ChannelConfig =
  | { kind: "email"; to: string[] }
  | { kind: "slack"; webhook_url: string }
  | { kind: "teams"; webhook_url: string }
  | { kind: "telegram"; bot_token: string; chat_id: string }
  | { kind: "webhook"; url: string; secret?: string };

export type AlertMessage = {
  id: string;
  title: string;
  description: string | null;
  severity: string;
  source: string;
  asset: string | null;
  technique: string | null;
  detected_at: string;
};

// Channel configs hold webhook URLs and bot tokens, so they are encrypted at rest.
export function sealConfig(config: ChannelConfig): Record<string, string> {
  return { sealed: encrypt(JSON.stringify(config), env().APP_SECRET, "channel") };
}

export function openConfig(stored: unknown): ChannelConfig {
  const s = stored as { sealed?: string };
  if (!s?.sealed) throw new Error("channel config is not sealed");
  return JSON.parse(decrypt(s.sealed, env().APP_SECRET, "channel")) as ChannelConfig;
}

/** Show admins enough to recognise a channel without revealing secrets. */
export function describeConfig(c: ChannelConfig): string {
  switch (c.kind) {
    case "email": return c.to.join(", ");
    case "slack":
    case "teams": return `${new URL(c.webhook_url).host}/…`;
    case "telegram": return `chat ${c.chat_id}`;
    case "webhook": return new URL(c.url).origin;
  }
}

const SEV_EMOJI: Record<string, string> = { critical: "🔴", high: "🟠", medium: "🟡", low: "🔵", info: "⚪" };

function link(alertId: string) {
  return `${env().APP_URL}/alerts?focus=${alertId}`;
}

async function safePost(url: string, body: unknown, headers: Record<string, string> = {}) {
  const u = new URL(url);
  if (u.protocol !== "https:" && !env().ALLOW_PRIVATE_TARGETS) throw new Error("webhook URLs must use https");
  await resolveTarget(u.hostname, env().ALLOW_PRIVATE_TARGETS);
  const payload = JSON.stringify(body);
  const res = await fetch(u, { method: "POST", headers: { "content-type": "application/json", ...headers }, body: payload, signal: AbortSignal.timeout(15_000), redirect: "error" });
  if (!res.ok) throw new Error(`HTTP ${res.status}: ${(await res.text()).slice(0, 200)}`);
}

export async function deliver(config: ChannelConfig, a: AlertMessage): Promise<void> {
  const head = `${SEV_EMOJI[a.severity] ?? ""} [${a.severity.toUpperCase()}] ${a.title}`;
  const lines = [
    a.description ?? "",
    `Asset: ${a.asset ?? "—"} · Source: ${a.source}${a.technique ? ` · ATT&CK: ${a.technique}` : ""}`,
    `Detected: ${new Date(a.detected_at).toUTCString()}`,
  ].filter(Boolean);
  switch (config.kind) {
    case "email":
      await sendMail({
        to: config.to,
        subject: `[SOC ${a.severity.toUpperCase()}] ${a.title}`,
        text: `${head}\n\n${lines.join("\n")}\n\nOpen in SOC: ${link(a.id)}`,
        html: simpleHtml(head, lines, { href: link(a.id), label: "Open alert" }),
      });
      return;
    case "slack":
      await safePost(config.webhook_url, {
        text: head,
        blocks: [
          { type: "section", text: { type: "mrkdwn", text: `*${head}*\n${lines.join("\n")}` } },
          { type: "actions", elements: [{ type: "button", text: { type: "plain_text", text: "Open alert" }, url: link(a.id) }] },
        ],
      });
      return;
    case "teams":
      await safePost(config.webhook_url, {
        type: "message",
        attachments: [{
          contentType: "application/vnd.microsoft.card.adaptive",
          content: {
            $schema: "http://adaptivecards.io/schemas/adaptive-card.json", type: "AdaptiveCard", version: "1.4",
            body: [
              { type: "TextBlock", text: head, weight: "Bolder", wrap: true, color: ["critical", "high"].includes(a.severity) ? "Attention" : "Warning" },
              ...lines.map((l) => ({ type: "TextBlock", text: l, wrap: true, spacing: "Small" })),
            ],
            actions: [{ type: "Action.OpenUrl", title: "Open alert", url: link(a.id) }],
          },
        }],
      });
      return;
    case "telegram":
      await safePost(`https://api.telegram.org/bot${config.bot_token}/sendMessage`, {
        chat_id: config.chat_id,
        text: `${head}\n\n${lines.join("\n")}\n\n${link(a.id)}`,
        disable_web_page_preview: true,
      });
      return;
    case "webhook": {
      const body = { type: "alert.created", alert: { ...a, url: link(a.id) } };
      const headers: Record<string, string> = {};
      if (config.secret) {
        const ts = Math.floor(Date.now() / 1000).toString();
        headers["x-soc-timestamp"] = ts;
        headers["x-soc-signature"] = `sha256=${createHmac("sha256", config.secret).update(`${ts}.${JSON.stringify(body)}`).digest("hex")}`;
      }
      await safePost(config.url, body, headers);
      return;
    }
  }
}

const BACKOFF_MIN = [1, 5, 15, 60, 180];

export function notificationRetry(attempt: number): { giveUp: boolean; delayMinutes: number } {
  return { giveUp: attempt > BACKOFF_MIN.length, delayMinutes: BACKOFF_MIN[Math.min(Math.max(attempt - 1, 0), BACKOFF_MIN.length - 1)]! };
}

export async function deliverPending(limit = 50): Promise<{ sent: number; failed: number }> {
  const jobs = await asSystem((tx) => tx`
    select n.id, n.attempts, c.id as channel_id, c.config,
           a.id as alert_id, a.title, a.description, a.severity::text, a.source, a.mitre_technique, a.detected_at, s.name as asset
    from notifications n
    join notification_channels c on c.id = n.channel_id and c.enabled
    join alerts a on a.id = n.alert_id
    left join assets s on s.id = a.asset_id
    where n.status = 'pending' and n.next_attempt_at <= now()
    order by n.id limit ${limit}`);
  let sent = 0, failed = 0;
  for (const j of jobs) {
    try {
      await deliver(openConfig(j.config), {
        id: j.alert_id, title: j.title, description: j.description, severity: j.severity, source: j.source,
        asset: j.asset, technique: j.mitre_technique, detected_at: j.detected_at,
      });
      await asSystem(async (tx) => {
        await tx`update notifications set status = 'sent', sent_at = now(), attempts = attempts + 1 where id = ${j.id}`;
        await tx`update notification_channels set last_sent_at = now(), last_error = null where id = ${j.channel_id}`;
      });
      sent++;
    } catch (e) {
      failed++;
      const msg = (e as Error).message.slice(0, 500);
      const attempt = Number(j.attempts) + 1;
      const retry = notificationRetry(attempt);
      await asSystem(async (tx) => {
        await tx`update notifications set attempts = ${attempt}, last_error = ${msg},
                   status = ${retry.giveUp ? "failed" : "pending"},
                   next_attempt_at = now() + make_interval(mins => ${retry.delayMinutes})
                 where id = ${j.id}`;
        await tx`update notification_channels set last_error = ${msg} where id = ${j.channel_id}`;
      });
    }
  }
  return { sent, failed };
}
