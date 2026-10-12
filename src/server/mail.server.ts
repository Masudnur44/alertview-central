// Outgoing email over SMTP (any provider: Microsoft 365, Google Workspace, SES, Mailgun, a local relay...).
import { env, smtpConfigured } from "./env.server";

type Mail = { to: string | string[]; subject: string; text: string; html?: string };

let transporter: { sendMail: (m: Record<string, unknown>) => Promise<unknown> } | undefined;

async function transport(): Promise<NonNullable<typeof transporter>> {
  if (!transporter) {
    const nodemailer = await import("nodemailer");
    const e = env();
    transporter = nodemailer.createTransport({
      host: e.SMTP_HOST,
      port: e.SMTP_PORT,
      secure: e.SMTP_SECURE,
      auth: e.SMTP_USER ? { user: e.SMTP_USER, pass: e.SMTP_PASS ?? "" } : undefined,
      requireTLS: !e.SMTP_SECURE && e.SMTP_PORT === 587,
    }) as NonNullable<typeof transporter>;
  }
  return transporter!;
}

export async function sendMail(mail: Mail): Promise<void> {
  if (!smtpConfigured()) throw new Error("Email is not configured (set SMTP_HOST and SMTP_FROM).");
  const t = await transport();
  await t.sendMail({ from: env().SMTP_FROM, to: mail.to, subject: mail.subject, text: mail.text, html: mail.html });
}

export function escapeHtml(s: string): string {
  return s.replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]!);
}

export function simpleHtml(title: string, lines: string[], link?: { href: string; label: string }): string {
  const body = lines.map((l) => `<p style="margin:0 0 12px">${escapeHtml(l)}</p>`).join("");
  const button = link
    ? `<p><a href="${escapeHtml(link.href)}" style="display:inline-block;background:#0ea5b7;color:#00161a;padding:10px 16px;border-radius:6px;text-decoration:none;font-weight:600">${escapeHtml(link.label)}</a></p>`
    : "";
  return `<div style="font-family:system-ui,sans-serif;max-width:560px;margin:auto;color:#111"><h2 style="font-size:18px">${escapeHtml(title)}</h2>${body}${button}<p style="color:#666;font-size:12px">${escapeHtml(env().ORG_NAME)} Security Operations</p></div>`;
}
