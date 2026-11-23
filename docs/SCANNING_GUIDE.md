# Scanning Guide

## GitHub Execution

Workflows execute automatically for:

- Pushes to `main` or `master`
- Pull requests
- Every Monday schedule
- Manual `workflow_dispatch`

Open **Actions** and select **Application Security** or **CodeQL**.

## Local Compatibility

Use Docker where available:

```sh
npx semgrep --config p/security-audit --config p/secrets --config p/owasp-top-ten .
docker run --rm -v "$PWD:/repo" -w /repo zricethezav/gitleaks:v8.24.6 detect --source . --redact 100 --no-banner
docker run --rm -v "$PWD:/src" aquasec/trivy:latest fs --skip-dirs node_modules,.git,.output /src
docker run --rm -v "$PWD:/src" aquasec/trivy:latest config /src
npm run security:report
```

The consolidated report requires SARIF inputs under `security-results/`.
GitHub-only scans cannot be verified locally until a workflow has executed on GitHub.

## Quality and SBOM

The **Build and Quality** workflow installs only from `package-lock.json`, runs npm audit,
TypeScript, ESLint, tests and the production build.

The security workflow creates CycloneDX SBOMs for both the application filesystem and built
container image. They are downloaded as `security-sbom` and retained for 90 days.
