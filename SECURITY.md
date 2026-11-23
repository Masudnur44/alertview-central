# Security Policy

## Reporting Vulnerabilities

Do not disclose vulnerabilities publicly or include secret values in issues or pull requests.
Report suspected vulnerabilities to the FINPAYTECH security team through the approved private
channel. Include reproduction steps, affected components and potential impact.

## Supported Scope

The policy covers application, Docker configuration, database migrations, server functions,
worker jobs, agents and GitHub Actions workflows in this repository.

## Automated Security Controls

Security scans run on pushes, pull requests, a weekly schedule and manually:

- Semgrep SAST
- Gitleaks secret scanning
- Trivy dependency, filesystem, Docker image and configuration scanning
- OWASP Dependency-Check
- GitHub CodeQL for JavaScript/TypeScript and Python
- GitHub Dependabot

Scanner findings are uploaded to GitHub Code Scanning as SARIF where supported.

## Severity Policy

| Severity      | Requirement                                     |
| ------------- | ----------------------------------------------- |
| Critical      | Block merge                                     |
| High          | Block merge unless an approved exception exists |
| Medium        | Report and track                                |
| Low           | Report and monitor                              |
| Informational | Record                                          |

The `security/baseline.json` records accepted findings established during the initial scan period.
Only exact new critical and high findings enter the merge gate.

## Secrets

Never commit `.env` files, database credentials, OAuth secrets, SMTP passwords, agent keys,
webhook secrets or recovery codes. Gitleaks and Trivy secret scans redact sensitive values.
If a secret is exposed, revoke it immediately and replace it before closing the finding.
