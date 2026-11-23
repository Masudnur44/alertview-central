# Security Baseline Policy

The baseline contains exact findings accepted during the initial security scanning period.
An accepted baseline finding must never include a secret value, key, token or password.

Do not add broad suppressions. Baseline entries may be removed only after remediation or a
documented risk acceptance approved under the FINPAYTECH security exception process.

New critical or high findings are gated by exact scanner/fingerprint matching:

- The baseline does not suppress findings from an unrelated scanner.
- A finding that changes location or rule may produce a new fingerprint and require review.
- Secret findings are normalized so no secret value appears in reports or workflow logs.
