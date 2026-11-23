# Remediation Guide

## Triage

1. Open the GitHub Code Scanning alert or workflow artifact.
2. Confirm the finding is in the repository and is reachable.
3. Record the scanner, severity, file, line, CVE/rule and remediation.
4. Do not copy credentials or secret values into tickets or logs.

## Critical and High

- Critical findings block merge.
- High findings block merge unless an approved exception is recorded.
- Remove or rotate leaked credentials immediately.
- Fix dependencies to a patched version or document the approved exception.
- Re-run the relevant scanner and the complete security workflow.

## Medium, Low and Informational

Track medium findings. Monitor low and informational findings. Update the baseline only after
the initial review and remediation/risk acceptance decision.

## Dependency Updates

Dependabot proposes npm, Docker and GitHub Actions updates. Review release changes and run tests
before merging. Do not silently disable Dependency-Check or ignore all CVEs.

## Exception Process

Create a private security review record that states:

- Finding and affected asset
- Business justification
- Compensating controls
- Owner
- Expiry date
- Approval
