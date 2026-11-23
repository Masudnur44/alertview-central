# FINPAYTECH DevSecOps Implementation

## Pipeline

[.github/workflows/security.yml](../.github/workflows/security.yml) runs parallel application
security scanners for pushes, pull requests, weekly schedules and manual execution.
[.github/workflows/codeql.yml](../.github/workflows/codeql.yml) runs CodeQL for
JavaScript/TypeScript and Python.

The pipeline uses read-only repository permissions by default. Jobs that upload SARIF explicitly
request `security-events: write`. Dependabot monitors npm, Docker and GitHub Actions updates.

The ZAP workflow in [.github/workflows/zap-dast.yml](../.github/workflows/zap-dast.yml) scans only
the loopback disposable instance started by that workflow.

## Baseline and Enforcement

`security/baseline.json` contains exact fingerprints from the initial security baseline.
The consolidated report script compares each finding against that baseline.
Existing findings remain visible and do not fail development. A critical or high finding absent
from the baseline fails the final gate.

Establish or refresh the baseline only after a security review:

```sh
npm run security:baseline
npm run security:report
```

The baseline command must receive local or downloaded SARIF files in `security-results/`.
Never baseline exposed secret values or broadly suppress a scanner rule.
To deliberately establish a partial local baseline from scanners that completed successfully:

```sh
npm run security:baseline:partial
npm run security:report:local
```

This local mode is diagnostic only. GitHub execution must provide every required scanner output
before the baseline or merge gate is accepted.

## SARIF and GitHub Code Scanning

Each applicable scanner uploads SARIF with a unique category. Consolidated Markdown and JSON
reports are retained as workflow artifacts for 90 days.

## Reusable Adoption

The scripts and workflow structure are repository-local and can be copied into FINPAYTECH
repositories. Repositories with no Dockerfile should omit the image job. Python is optional,
and CodeQL's language matrix can be narrowed to supported languages.
