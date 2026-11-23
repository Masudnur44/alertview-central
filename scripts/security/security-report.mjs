import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";

const root = process.argv[2] ? path.resolve(process.argv[2]) : process.cwd();
const resultsDir = path.join(root, "security-results");
const baselinePath = path.join(root, "security", "baseline.json");

const severities = ["critical", "high", "medium", "low", "info"];
const localMode = process.argv.includes("--allow-local-missing");

function readJson(file) {
  try {
    return JSON.parse(fs.readFileSync(file, "utf8"));
  } catch {
    return null;
  }
}

function readValidSarif(file) {
  const sarif = readJson(file);
  return Boolean(sarif?.version && Array.isArray(sarif?.runs)) ? sarif : null;
}

function walkFiles(dir) {
  if (!fs.existsSync(dir)) return [];
  const out = [];
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) out.push(...walkFiles(full));
    else out.push(full);
  }
  return out;
}

function normalizeSeverity(raw) {
  const value = String(raw ?? "").toLowerCase();
  if (value === "critical" || value === "error") return "critical";
  if (value === "high") return "high";
  if (value === "medium" || value === "moderate" || value === "warning") return "medium";
  if (value === "low") return "low";
  return "info";
}

function fingerprint(scanner, rule, file, line, description) {
  const identity = [scanner, rule || "", file || "", line || "", description || ""].join("|");
  return crypto.createHash("sha256").update(identity).digest("hex").slice(0, 24);
}

function readSarif(file, fallbackScanner) {
  const sarif = readValidSarif(file);
  if (!sarif?.runs) return [];
  const scanner = path.basename(file).replace(/\.sarif(?:\.json)?$/, "") || fallbackScanner;
  const findings = [];
  for (const run of sarif.runs) {
    const toolName = run.tool?.driver?.name ?? fallbackScanner ?? scanner;
    const rules = new Map((run.tool?.driver?.rules ?? []).map((rule) => [rule.id, rule]));
    for (const result of run.results ?? []) {
      const ruleId =
        result.ruleId ?? result.rule?.id ?? result.message?.text?.slice(0, 80) ?? "unknown";
      const rule = rules.get(ruleId);
      const location = result.locations?.[0]?.physicalLocation;
      let file = location?.artifactLocation?.uri ?? "";
      file = file.replace(/^file:\/\/\//, "").replace(/^\/github\/workspace\//, "");
      const line = location?.region?.startLine ?? null;
      const properties = result.properties ?? {};
      const rawSeverity =
        properties["security-severity"] ??
        properties.severity ??
        result.level ??
        rule?.defaultConfiguration?.level;
      const description =
        result.message?.text ??
        rule?.shortDescription?.text ??
        rule?.fullDescription?.text ??
        ruleId;
      const cve =
        [ruleId, description, JSON.stringify(properties)]
          .join(" ")
          .match(/\bCVE-\d{4}-\d{4,7}\b/i)?.[0] ?? null;
      const severity = normalizeSeverity(rawSeverity);
      const ruleName = ruleId || rule?.name || "unknown";
      findings.push({
        scanner: toolName,
        severity,
        rule: ruleName,
        file,
        line,
        cve,
        description: description.replace(/[^\t\n\r\x20-\x7E]/g, "").slice(0, 500),
        remediation:
          rule?.helpUri ??
          rule?.help?.text ??
          "Review the finding and apply the vendor-recommended remediation.",
        fingerprint: fingerprint(toolName, ruleName, file, line, description),
      });
    }
  }
  return findings;
}

function uniqueFindings(findings) {
  const seen = new Set();
  return findings.filter((finding) => {
    const key = [
      finding.scanner,
      finding.rule,
      finding.file,
      finding.line,
      finding.cve,
      finding.description,
    ].join("|");
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

const sarifFiles = walkFiles(resultsDir).filter((file) => /\.sarif(?:\.json)?$/i.test(file));
const invalidSarif = sarifFiles.filter((file) => !readValidSarif(file));
const findings = uniqueFindings(
  sarifFiles
    .filter((file) => readValidSarif(file))
    .flatMap((file) => {
      return readSarif(file, path.basename(path.dirname(file)));
    }),
);

const npmAuditPath = path.join(resultsDir, "npm-audit", "npm-audit.json");
if (fs.existsSync(npmAuditPath)) {
  let audit;
  try {
    audit = readJson(npmAuditPath);
  } catch {
    audit = null;
  }
  if (!audit?.auditReportVersion || !audit?.vulnerabilities) {
    console.error("Security gate failed: npm audit output is missing or invalid.");
    process.exitCode = 3;
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
      cve: null,
      description,
      remediation:
        "Upgrade to a patched compatible version; review release changes before merging.",
      fingerprint: fingerprint("npm audit", rule, "package-lock.json", null, description),
    });
  }
}

const allFiles = walkFiles(resultsDir);
const hasSarif = (names) =>
  allFiles.some(
    (file) =>
      /\.sarif(?:\.json)?$/i.test(file) &&
      names.some((name) => path.basename(file).toLowerCase().includes(name)),
  );

const expected = [
  {
    scanner: "Semgrep",
    result: process.env.SEMGREP_JOB_RESULT,
    present: hasSarif(["semgrep"]),
  },
  {
    scanner: "Gitleaks",
    result: process.env.GITLEAKS_JOB_RESULT,
    present: hasSarif(["gitleaks"]),
  },
  {
    scanner: "Trivy filesystem",
    result: process.env.TRIVY_FS_JOB_RESULT,
    present: hasSarif(["trivy-fs"]),
  },
  {
    scanner: "Trivy configuration",
    result: process.env.TRIVY_CONFIG_JOB_RESULT,
    present: hasSarif(["trivy-config"]),
  },
  {
    scanner: "Trivy image",
    result: process.env.TRIVY_IMAGE_JOB_RESULT,
    present: hasSarif(["trivy-image"]),
  },
  {
    scanner: "OWASP Dependency-Check",
    result: process.env.DEPENDENCY_CHECK_JOB_RESULT,
    present: hasSarif(["dependency", "dependency-check"]),
  },
  {
    scanner: "npm audit",
    result: process.env.NPM_AUDIT_JOB_RESULT,
    present: fs.existsSync(npmAuditPath) && readJson(npmAuditPath)?.auditReportVersion === 2,
  },
];

const invalidSarifScannerNames = invalidSarif.map((file) => path.basename(file)).sort();
const missingOrFailed = [
  ...expected.filter((item) => (item.result && item.result !== "success") || !item.present),
  ...invalidSarifScannerNames.map((scanner) => ({
    scanner: `Invalid SARIF: ${scanner}`,
    result: "failure",
    present: false,
  })),
];

const baseline = readJson(baselinePath) ?? { version: 1, findings: [] };
const baselineIds = new Set((baseline.findings ?? []).map((finding) => finding.fingerprint));
const newFindings = findings.filter((finding) => !baselineIds.has(finding.fingerprint));
const criticalOrHigh = newFindings.filter(
  (finding) => finding.severity === "critical" || finding.severity === "high",
);

const report = {
  scan_date: new Date().toISOString(),
  baseline: baseline.established_at,
  missing_or_failed_scanners: missingOrFailed.map((item) => ({
    scanner: item.scanner,
    job_result: item.result ?? "not-provided",
    output_present: item.present,
  })),
  summary: Object.fromEntries(
    severities.map((severity) => [
      severity,
      findings.filter((finding) => finding.severity === severity).length,
    ]),
  ),
  total: findings.length,
  new_critical_high: criticalOrHigh.length,
  findings,
  new_findings: newFindings,
  blocked: criticalOrHigh,
};

fs.mkdirSync(resultsDir, { recursive: true });
fs.writeFileSync(path.join(resultsDir, "consolidated.json"), JSON.stringify(report, null, 2));

const lines = [
  "# Consolidated Security Report",
  "",
  `Generated: ${report.scan_date}`,
  `Baseline established: ${baseline.established_at ?? "not established"}`,
  "",
  "## Summary",
  "",
  "| Severity | Findings |",
  "|---|---:|",
  ...severities.map((severity) => `| ${severity.toUpperCase()} | ${report.summary[severity]} |`),
  "",
  `**New critical/high findings:** ${criticalOrHigh.length}`,
  "",
  "## Scanner Execution",
  "",
];

if (missingOrFailed.length && !localMode) {
  lines.push("| Scanner | Job Result | Output Present |");
  lines.push("|---|---|---|");
  for (const item of missingOrFailed) {
    lines.push(
      `| ${item.scanner} | ${item.result ?? "not-provided"} | ${item.present ? "yes" : "no"} |`,
    );
  }
  lines.push("");
}

lines.push("## Findings", "");

if (!findings.length) {
  lines.push("No SARIF findings were reported.");
} else {
  lines.push("| Severity | Scanner | Rule | File | Line | CVE | Finding |");
  lines.push("|---|---|---|---|---:|---|---|");
  for (const finding of findings) {
    const file = (finding.file || "N/A").replace(/\|/g, "\\|");
    const rule = (finding.rule || "N/A").replace(/\|/g, "\\|");
    const description = finding.description.replace(/\|/g, "\\|");
    lines.push(
      `| ${finding.severity.toUpperCase()} | ${finding.scanner} | ${rule} | ${file} | ${finding.line ?? "N/A"} | ${finding.cve ?? "N/A"} | ${description} |`,
    );
  }
}

fs.writeFileSync(path.join(resultsDir, "consolidated.md"), lines.join("\n") + "\n");

if (missingOrFailed.length && !localMode) {
  console.error(
    `Security gate failed safely: ${missingOrFailed.map((item) => item.scanner).join(", ")} did not produce a usable result.`,
  );
  process.exitCode = 3;
} else if (criticalOrHigh.length) {
  console.error(`Security gate blocked: ${criticalOrHigh.length} new critical/high finding(s).`);
  process.exitCode = 2;
} else {
  console.log("Security gate passed: no new critical/high findings.");
}
