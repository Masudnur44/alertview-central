# Security Pipeline Architecture

## Workflows

| Workflow       | Responsibility                                                                   | Triggers                           |
| -------------- | -------------------------------------------------------------------------------- | ---------------------------------- |
| `quality.yml`  | Locked install, npm audit, typecheck, lint, tests and production build           | Push, pull request, manual         |
| `security.yml` | Semgrep, Gitleaks, Trivy, OWASP Dependency-Check, npm audit, consolidated report | Push, pull request, weekly, manual |
| `codeql.yml`   | CodeQL JavaScript/TypeScript and Python analysis                                 | Push, pull request, weekly, manual |
| `zap-dast.yml` | ZAP baseline against a disposable local application instance                     | Push, pull request, weekly, manual |

## Data Flow

Scanner outputs are stored under `security-results/`. SARIF findings are uploaded to GitHub Code
Scanning with scanner-specific categories. Consolidated JSON and Markdown reports are uploaded
as the `security-consolidated-report` artifact.

The gate verifies every upstream scanner job succeeded, every required output or valid npm audit
JSON exists, findings are compared against exact baseline fingerprints, and new critical/high
findings block the gate. Missing or failed scanner infrastructure is itself a gate failure.

## Baseline

`security/baseline.json` contains accepted exact finding identifiers.

- SARIF findings use scanner, rule, file, line and CVE data.
- npm findings use package name and GHSA advisory identifiers.
- Broad scanner-rule suppressions are not permitted.

## DAST Boundary

ZAP scans only `127.0.0.1:3000` on the GitHub-hosted runner. The target is built and started by
the workflow. No production, public or third-party target is accepted.
