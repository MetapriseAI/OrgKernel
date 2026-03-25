# Changelog
All notable changes to OrgKernel will be documented in this file.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
---
## [1.0.0] - 2026-03-25
### Added
- **AgentIdentity** — Ed25519 keypair generation, X.509-style certificate issuance signed by Org CA, revoke/suspend/reactivate lifecycle, and challenge-response authentication with one-time nonces
- **ExecutionToken** — Instance-scoped permission tokens with tool allowlists, bounded numeric params, immutable params, Ed25519 signatures, and one-time consumption enforcement
- **Audit Chain** — Three-layer (L1 Business / L2 Execution / L3 Compliance) SHA-256 hash-chained audit logging persisted to PostgreSQL with integrity verification API
- 61 test cases across all 8 modules — 100% pass rate
- Apache 2.0 open-source license
---
*For questions or issues, contact developer@metaprise.ai*