import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";

const root = process.cwd();
const resultsDir = path.join(root, "security-results");
const baselinePath = path.join(root, "security", "baseline.json");
const allowPartial = process.argv.includes("--allow-partial");

function fingerprint(scanner, rule, file, line, description) {
  return crypto
    .createHash("sha256")
    .update([scanner, rule || "", file || "", line || "", description || ""].join("|"))
    .digest("hex")
    .slice(0, 24);
}

function normalizeSeverity(result) {
  const value = String(
    typeof result === "string"
      ? result
      : (result?.properties?.["security-severity"] ??
          result?.properties?.severity ??
          result?.severity ??
          result?.level ??
          ""),
  ).toLowerCase();
  if (value === "critical" || value === "error") return "critical";
  if (value === "high") return "high";
  if (value === "medium" || value === "moderate" || value === "warning") return "medium";
  if (value === "low") return "low";
  return "info";
}

const findings = [];
function walkFiles(dir) {
  if (!fs.existsSync(dir)) return [];
  const files = [];
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) files.push(...walkFiles(full));
    else files.push(full);
  }
  return files;
}

if (fs.existsSync(resultsDir)) {
  for (const file of walkFiles(resultsDir).filter(
    (item) => item.endsWith(".sarif") || item.endsWith(".sarif.json"),
  )) {
    const name = path.basename(file);
    let sarif;
    try {
      sarif = JSON.parse(fs.readFileSync(file, "utf8"));
    } catch {
      continue;
    }
    for (const run of sarif.runs ?? []) {
      const scanner = run.tool?.driver?.name ?? name.replace(/\.sarif$/, "");
      const rules = new Map((run.tool?.driver?.rules ?? []).map((rule) => [rule.id, rule]));
      for (const result of run.results ?? []) {
        const ruleId = result.ruleId ?? "unknown";
        const rule = rules.get(ruleId);
        const location = result.locations?.[0]?.physicalLocation;
        const fileName = (location?.artifactLocation?.uri ?? "")
          .replace(/^file:\/\/\//, "")
          .replace(/^\/github\/workspace\//, "");
        const line = location?.region?.startLine ?? null;
        const description = (result.message?.text ?? rule?.shortDescription?.text ?? ruleId)
          .replace(/[^\t\n\r\x20-\x7E]/g, "")
          .slice(0, 500);
        findings.push({
          scanner,
          severity: normalizeSeverity({
            severity: result.properties?.["security-severity"] ?? result.properties?.severity,
            level: result.level ?? rule?.defaultConfiguration?.level,
          }),
          rule: ruleId,
          file: fileName,
          line,
          description,
          fingerprint: fingerprint(scanner, ruleId, fileName, line, description),
          accepted: "initial-baseline",
        });
      }
    }
  }
}

const npmAuditPath = path.join(resultsDir, "npm-audit", "npm-audit.json");
if (fs.existsSync(npmAuditPath)) {
  let audit;
  try {
    audit = JSON.parse(fs.readFileSync(npmAuditPath, "utf8"));
  } catch {
    audit = null;
  }
  for (const [packageName, item] of Object.entries(audit?.vulnerabilities ?? {})) {
    const severity = normalizeSeverity(item.severity);
    const advisories = (item.via ?? [])
      .filter((via) => typeof via === "object")
      .map((via) => via.url?.match(/GHSA-[0-9a-z-]+/i)?.[0])
      .filter(Boolean)
      .sort();
    const rule = `npm-audit:${packageName}:${advisories.join(",") || "unknown"}`;
    const description = `${packageName}: ${
      item.via
        ?.map((via) => (typeof via === "string" ? via : via.title))
        .filter(Boolean)
        .join("; ") || "npm audit vulnerability"
    }`.slice(0, 500);
    findings.push({
      scanner: "npm audit",
      severity,
      rule,
      file: "package-lock.json",
      line: null,
      description,
      fingerprint: fingerprint("npm audit", rule, "package-lock.json", null, description),
      accepted: "initial-baseline",
    });
  }
}

const allBaselinedFiles = walkFiles(resultsDir);
const required = [
  { name: "Semgrep", present: allBaselinedFiles.some((file) => /semgrep.*\.sarif$/i.test(file)) },
  { name: "Gitleaks", present: allBaselinedFiles.some((file) => /gitleaks.*\.sarif$/i.test(file)) },
  {
    name: "Trivy filesystem",
    present: allBaselinedFiles.some((file) => /trivy-fs.*\.sarif$/i.test(file)),
  },
  {
    name: "Trivy configuration",
    present: allBaselinedFiles.some((file) => /trivy-config.*\.sarif$/i.test(file)),
  },
  {
    name: "Trivy image",
    present: allBaselinedFiles.some((file) => /trivy-image.*\.sarif$/i.test(file)),
  },
  {
    name: "OWASP Dependency-Check",
    present: allBaselinedFiles.some((file) =>
      /(dependency-check|dependency).*\.sarif$/i.test(file),
    ),
  },
  {
    name: "npm audit",
    present: (() => {
      if (!fs.existsSync(npmAuditPath)) return false;
      try {
        return JSON.parse(fs.readFileSync(npmAuditPath, "utf8"))?.auditReportVersion === 2;
      } catch {
        return false;
      }
    })(),
  },
];
const missing = required.filter((item) => !item.present);
if (missing.length && !allowPartial) {
  console.error(
    `Refusing to establish a partial baseline. Missing: ${missing.map((item) => item.name).join(", ")}`,
  );
  process.exitCode = 3;
} else {
  if (missing.length) {
    console.warn(
      `Creating a partial baseline from successfully executed scanners: missing ${missing.map((item) => item.name).join(", ")}`,
    );
  }

  const unique = new Map();
  for (const finding of findings) unique.set(finding.fingerprint, finding);
  const baseline = {
    version: 1,
    established_at: new Date().toISOString(),
    description: "Exact known scanner findings accepted during the initial baseline period.",
    findings: [...unique.values()].sort(
      (a, b) => a.scanner.localeCompare(b.scanner) || a.fingerprint.localeCompare(b.fingerprint),
    ),
  };
  fs.mkdirSync(path.dirname(baselinePath), { recursive: true });
  fs.writeFileSync(baselinePath, JSON.stringify(baseline, null, 2) + "\n");
  console.log(`Established baseline with ${baseline.findings.length} finding(s).`);
}
