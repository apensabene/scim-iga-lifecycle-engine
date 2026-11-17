# IGA & Lifecycle Governance Control Mapping

This repository maps RFC 7643/7644 SCIM 2.0 automated Joiner-Mover-Leaver (JML) provisioning and periodic User Access Reviews (UAR) to **NIST SP 800-53 Rev. 5**, **HIPAA Security Rule (45 CFR § 164.308)**, and **Zero Trust Governance**.

| Governance Objective | Engine Implementation | NIST SP 800-53 Rev. 5 | HIPAA Security Rule |
| :--- | :--- | :--- | :--- |
| **Automated Account Provisioning & Termination** | Real-time SCIM 2.0 `/Users` & `/Groups` endpoints (`POST`, `PUT`, `PATCH`, `DELETE`) triggered by Okta lifecycle events | **AC-2(1)** (Automated System Account Management) | **§ 164.308(a)(3)(ii)(C)** (Termination Procedures) |
| **Dormant & Stale Account Detection** | `access_certification_engine.py` flags active accounts exceeding inactivity thresholds (`>30` days without login) | **AC-2(3)** (Disable Accounts — Inactive Accounts) | **§ 164.308(a)(4)(ii)(C)** (Access Establishment & Modification) |
| **Periodic Access Recertification** | Automated export of user-to-group/role entitlement matrices with immutable SHA-256 evidence manifests | **AC-2(j)** (Periodic Review of Account Privileges) | **§ 164.308(a)(1)(ii)(D)** (Information System Activity Review) |
| **Least-Privilege API Authentication** | OAuth 2.0 `client_credentials` with RS256 `private_key_jwt` assertions (`okta.users.read`, `okta.groups.read`) | **IA-2** / **AC-6** (Least Privilege) | **§ 164.312(d)** (Person or Entity Authentication) |