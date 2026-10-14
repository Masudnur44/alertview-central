// Runtime configuration, read once from the environment and validated.
import { z } from "zod";

const bool = (def: boolean) =>
  z.preprocess((v) => (v === undefined || v === "" ? def : ["1", "true", "yes", "on"].includes(String(v).toLowerCase())), z.boolean());
const list = z.preprocess(
  (v) => (typeof v === "string" ? v.split(",").map((s) => s.trim().toLowerCase()).filter(Boolean) : []),
  z.array(z.string()),
);

const Schema = z.object({
  NODE_ENV: z.string().default("production"),
  DATABASE_URL: z.string().min(1, "DATABASE_URL is required"),
  APP_URL: z.string().url("APP_URL must be the public URL, e.g. https://soc.finpaytech.com"),
  APP_SECRET: z.string().min(32, "APP_SECRET must be at least 32 random characters"),
  ORG_NAME: z.string().default("FINPAYTECH"),

  // Access control
  ALLOWED_EMAIL_DOMAINS: list,
  BOOTSTRAP_ADMIN_EMAIL: z.string().email().optional().or(z.literal("").transform(() => undefined)),
  REQUIRE_MFA: bool(true),
  ALLOW_SIGNUP: bool(true),
  SESSION_IDLE_HOURS: z.coerce.number().min(1).max(168).default(12),
  SESSION_MAX_DAYS: z.coerce.number().min(1).max(30).default(7),
  TRUST_PROXY: bool(true),

  // Google sign-in (optional)
  GOOGLE_CLIENT_ID: z.string().optional(),
  GOOGLE_CLIENT_SECRET: z.string().optional(),

  // Outgoing email (optional; enables verification, resets and email alerts)
  SMTP_HOST: z.string().optional(),
  SMTP_PORT: z.coerce.number().default(587),
  SMTP_SECURE: bool(false),
  SMTP_USER: z.string().optional(),
  SMTP_PASS: z.string().optional(),
  SMTP_FROM: z.string().optional(),

  // Messages to developer teams (optional)
  TELEGRAM_BOT_TOKEN: z.string().optional(),
  WHATSAPP_TOKEN: z.string().optional(),
  WHATSAPP_PHONE_NUMBER_ID: z.string().optional(),
  WHATSAPP_TEMPLATE: z.string().optional(),
  WHATSAPP_TEMPLATE_LANG: z.string().default("en"),
  ISSUE_LINK_DAYS: z.coerce.number().min(1).max(90).default(14),

  // Monitoring
  ALLOW_PRIVATE_TARGETS: bool(false),
  CHECK_CONCURRENCY: z.coerce.number().min(1).max(50).default(8),
  INGEST_RATE_PER_MINUTE: z.coerce.number().min(10).default(1200),
});

export type Env = z.infer<typeof Schema>;

let cached: Env | undefined;

export function env(): Env {
  if (!cached) {
    // Treat empty variables (e.g. "SMTP_HOST=" in .env) as unset so defaults apply.
    const raw = Object.fromEntries(Object.entries(process.env).filter(([, v]) => v !== undefined && v.trim() !== ""));
    const parsed = Schema.safeParse(raw);
    if (!parsed.success) {
      const problems = parsed.error.issues.map((i) => `  - ${i.path.join(".")}: ${i.message}`).join("\n");
      throw new Error(`Invalid configuration:\n${problems}`);
    }
    cached = parsed.data;
  }
  return cached;
}

export const isProd = () => env().NODE_ENV === "production";
export const secureCookies = () => env().APP_URL.startsWith("https://");
export const smtpConfigured = () => Boolean(env().SMTP_HOST && env().SMTP_FROM);
export const googleConfigured = () => Boolean(env().GOOGLE_CLIENT_ID && env().GOOGLE_CLIENT_SECRET);
export const telegramConfigured = () => Boolean(env().TELEGRAM_BOT_TOKEN);
export const whatsappConfigured = () => Boolean(env().WHATSAPP_TOKEN && env().WHATSAPP_PHONE_NUMBER_ID);
