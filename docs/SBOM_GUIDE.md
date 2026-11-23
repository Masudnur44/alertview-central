# SBOM Guide

## Generated SBOMs

The security workflow generates CycloneDX JSON in two scopes:

| Artifact                  | Workflow file                                | SBOM scope                                 |
| ------------------------- | -------------------------------------------- | ------------------------------------------ |
| `security-sbom`           | `security-results/sbom/application.cdx.json` | Repository filesystem and dependency graph |
| `security-sbom-container` | `security-results/sbom/container.cdx.json`   | Built application container image          |

Both SBOM artifacts are retained for 90 days.

## Use

Use the SBOM to track package names and versions across investigations, correlate CVEs with
components, provide dependency evidence for assessments and compare application versus runtime
image dependencies.

## Validation

Download a CycloneDX artifact and verify valid JSON with `"bomFormat": "CycloneDX"`.

```sh
trivy fs --format cyclonedx --output application.cdx.json .
trivy image --format cyclonedx --output container.cdx.json alertview-central:security-scan
```

The workflow image SBOM proves the container built during that run; it does not prove a deployed
image is identical.
