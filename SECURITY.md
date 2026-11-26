# Security Policy

## Supported Versions

Only the latest state of the `main` branch is actively maintained and supported with security updates.

| Branch / Version | Supported |
| ---------------- | --------- |
| `main`           | Yes       |
| Older commits    | No        |

## Reporting a Vulnerability

Please **do not** report security vulnerabilities, authentication bypasses, SQL injection flaws, or audit-ledger integrity issues through public GitHub Issues or Pull Requests.

Instead, report vulnerabilities privately via one of the following channels:

1. **GitHub Private Vulnerability Reporting:** Use the **Report a vulnerability** button under the **Security** tab of `apensabene/scim-iga-lifecycle-engine`.
2. **Direct Contact:** Email **apensabene@pm.me** with the subject line `[SECURITY] scim-iga-lifecycle-engine - <Brief Summary>`.

### What to Include
* Description of the issue and affected component(s) (FastAPI `/Users` or `/Groups` SCIM 2.0 endpoints, OAuth 2.0 `private_key_jwt` client, SQLite persistence, or UAR certification engine)
* Potential impact (e.g., unauthorized user provisioning/deprovisioning, privilege escalation, or compliance evidence tampering)
* Steps to reproduce or suggested remediation

### Response Timeline
* **Initial Acknowledgment:** Within 48 hours
* **Triage & Remediation Assessment:** Within 5 business days

## Security Architecture & Baseline Controls

This repository enforces the following security practices:
* **Asymmetric Service Authentication:** Uses OAuth 2.0 `private_key_jwt` (RS256) assertions for identity provider integration without hardcoded client secrets.
* **Strict Schema & Input Validation:** Validates RFC 7643/7644 SCIM payloads via Pydantic models and parameterized database queries.
* **Tamper-Evident Audit Evidence:** Maintains an append-only Joiner-Mover-Leaver (JML) event ledger and exports SHA-256 hashed User Access Review (UAR) certification reports aligned to NIST SP 800-53 AC-2 and HIPAA.
