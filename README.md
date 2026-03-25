# OrgKernel

<p align="center">
  <strong>The open-source trust foundation of the Metaprise AURA platform.</strong><br/>
  Cryptographic agent identity, instance-scoped permissions, and tamper-proof audit logging —<br/>
  transparent by design, not by promise.
</p>

<p align="center">
  <a href="https://github.com/MetapriseAI/OrgKernel/blob/main/LICENSE">
    <img src="https://img.shields.io/badge/License-Apache%202.0-blue.svg" alt="License: Apache 2.0" />
  </a>
  <a href="https://github.com/MetapriseAI/OrgKernel/stargazers">
    <img src="https://img.shields.io/github/stars/MetapriseAI/OrgKernel?style=flat&color=yellow" alt="GitHub Stars" />
  </a>
  <a href="https://github.com/MetapriseAI/OrgKernel/issues">
    <img src="https://img.shields.io/github/issues/MetapriseAI/OrgKernel" alt="GitHub Issues" />
  </a>
  <a href="https://github.com/MetapriseAI/OrgKernel/pulls">
    <img src="https://img.shields.io/github/issues-pr/MetapriseAI/OrgKernel" alt="Pull Requests" />
  </a>
  <img src="https://img.shields.io/badge/TypeScript-supported-3178C6?logo=typescript" alt="TypeScript" />
  <img src="https://img.shields.io/badge/Rust-supported-orange?logo=rust" alt="Rust" />
  <img src="https://img.shields.io/badge/Python-supported-3776AB?logo=python" alt="Python" />
  <img src="https://img.shields.io/badge/coverage-100%25-brightgreen" alt="Test Coverage" />
</p>

---

## Overview

**OrgKernel** is the open-source security and identity infrastructure layer that powers every AI agent in the [Metaprise AURA](https://www.trymetaprise.com/aura) platform. It provides the cryptographic primitives, permission enforcement, and audit mechanisms that enterprise AI deployments depend on.

Rather than trusting an agent runtime by convention, OrgKernel makes trust **verifiable** — every identity is cryptographically signed, every permission is scoped to a single execution instance, and every action is recorded in a tamper-proof chain you can independently audit.

> **Transparent by design, not by promise.**

---

## Core Modules

OrgKernel is composed of five pillars of agent trust:

### Module 01 — AgentIdentity · Cryptographic Organizational Identity

Ed25519 cryptographically signed organizational identity credentials — revocable, time-limited, and bound to org units. Every agent action is traceable to a verifiable identity.

- `ED25519` elliptic-curve signing — fast, compact, quantum-resistant upgrade path
- `REVOCABLE` — instant revocation propagates across the entire execution graph
- `TIME-LIMITED` — credentials expire on a configurable schedule; no permanent tokens
- `ORG-BOUND` — identity is scoped to a specific business unit, department, or team

---

### Module 02 — ExecutionToken · Instance-Scoped Permission Tokens

Per-execution permission tokens enforced at the Tool Gateway layer. Each agent execution receives exactly the permissions it needs — no more, no less. Scoped to a single instance.

- `INSTANCE-SCOPED` — tokens are valid for exactly one mission execution
- `TOOL GATEWAY` — enforcement at the gateway before any tool call proceeds
- `LEAST PRIVILEGE` — ExecutionToken carries only the permissions the mission requires

---

### Module 03 — AuditChain · Tamper-Proof Audit Logging

SHA-256 hash-chained tamper-proof audit log, written synchronously. Every agent action — tool calls, data access, state changes — is recorded in an immutable, verifiable chain.

- `SHA-256` — modifying any historical entry breaks the chain instantly
- `HASH-CHAINED` — each entry contains prev_hash, action, timestamp, agent_id, and payload_hash
- `SYNCHRONOUS` — execution blocks until the audit entry is persisted; no fire-and-forget
- `IMMUTABLE` — entries can never be modified or deleted after commit

---

### Module 04 — SSO / SAML Integration · Enterprise Single Sign-On

Full enterprise SSO support with SAML 2.0. Integrate agent identity management with your existing identity provider — Okta, Azure AD, Ping Identity, OneLogin, and any SAML-compliant IdP.

- `SAML 2.0` — any compliant IdP supported
- `MFA ENFORCEMENT` — OrgKernel inherits your IdP's multi-factor policies
- `SESSION MANAGEMENT` — configurable session lifetimes and forced re-authentication

---

### Module 05 — SCIM User Sync · Cross-Domain Identity Management

Automatic user provisioning and deprovisioning via SCIM 2.0. When an employee joins, moves, or leaves your organization, agent permissions update automatically — no manual intervention.

- `AUTO-PROVISION` — new employees receive agent access and permissions on day one
- `ROLE MAPPING` — IdP groups map to OrgKernel authority levels (L1–L4)
- `AUTO-DEPROVISION` — offboarded users lose all agent access instantly; no orphaned permissions
- `CROSS-DOMAIN` — manage identity across multiple business units and subsidiaries

---

## Authentication Flow

Every agent execution passes through a six-step verified pipeline. No step can be skipped; each produces an audit entry before the next begins.

```
STEP 01  ->  SSO Login          SAML assertion from enterprise IdP
STEP 02  ->  Identity Verify    Ed25519 signature validation
STEP 03  ->  Token Issue        DualToken issued for this execution
STEP 04  ->  Policy Check       Control Plane PERMIT / DENY
STEP 05  ->  Tool Gateway       Validated request hits the tool layer
STEP 06  ->  Audit Write        SHA-256 entry appended to chain
```

The **DualToken** (AgentIdentity credential + ExecutionToken) must fully validate at the gateway before any tool call is permitted to proceed.

---

## Quick Start

### Python

```python
# Install OrgKernel
pip install orgkernel

from orgkernel import OrgKernel, AgentIdentity

# Initialize with your org and SSO provider
kernel = OrgKernel.init(
    org_id="acme-corp",
    sso_provider="okta"
)

# Register a cryptographic agent identity
identity = kernel.create_identity(
    name="compliance-agent",
    org_unit="legal/compliance",
    ttl="24h"
)

# Issue an instance-scoped execution token
token = kernel.issue_token(
    identity=identity,
    tools=["doc_reader", "email_sender"],
    authority_level=2
)

# Verify audit chain integrity
valid = kernel.audit_chain.verify()
# True (all SHA-256 hashes valid)
```

### TypeScript

```typescript
import { OrgKernel } from "@metaprise/orgkernel";

// Initialize OrgKernel
const kernel = await OrgKernel.init({
  orgId: "acme-corp",
  ssoProvider: "okta",
});

// Register a cryptographic agent identity
const identity = await kernel.createIdentity({
  name: "compliance-agent",
  orgUnit: "legal/compliance",
  ttl: "24h",
});

// Issue an instance-scoped execution token
const token = await kernel.issueToken({
  identity,
  tools: ["doc_reader", "email_sender"],
  authorityLevel: 2,
});

// Verify audit chain integrity
const valid = await kernel.auditChain.verify();
// true (all SHA-256 hashes valid)
```

### Rust

```rust
use orgkernel::{OrgKernel, IdentityConfig, TokenConfig};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize OrgKernel
    let kernel = OrgKernel::init("acme-corp", "okta").await?;

    // Register a cryptographic agent identity
    let identity = kernel.create_identity(IdentityConfig {
        name: "compliance-agent".into(),
        org_unit: "legal/compliance".into(),
        ttl: "24h".into(),
    }).await?;

    // Issue an instance-scoped execution token
    let token = kernel.issue_token(TokenConfig {
        identity: &identity,
        tools: vec!["doc_reader", "email_sender"],
        authority_level: 2,
    }).await?;

    // Verify audit chain integrity
    let valid = kernel.audit_chain().verify().await?;
    // true (all SHA-256 hashes valid)

    Ok(())
}
```

---

## Architecture

```
+---------------------------------------------+
|                AURA Platform                |
+---------------------------------------------+
|              Agent Runtime                  |
+------------+------------+--------------------+
|   Agent    |   Agent    |       Agent        |
|  Identity  |  Identity  |      Identity      |
+------------+------------+--------------------+
|           OrgKernel Trust Layer             |
|  +-----------+  +------------------------+  |
|  |AgentIdent.|  |    ExecutionToken      |  |
|  | Ed25519   |  |   Instance-Scoped      |  |
|  +-----+-----+  +----------+-------------+  |
|        |                   |                |
|  +-----+-------------------+-------------+  |
|  |       Tool Gateway (Enforcer)         |  |
|  +---------------------+-----------------+  |
|                        |                   |
|  +---------------------+-----------------+  |
|  |      AuditChain (SHA-256 Log)         |  |
|  +---------------------------------------+  |
+---------------------------------------------+
|   Enterprise Identity: SSO + SCIM           |
|   (Okta / Azure AD / Ping / OneLogin)       |
+---------------------------------------------+
```

---

## Compliance & Verification

OrgKernel's AuditChain is designed to satisfy evidentiary requirements across regulated industries:

- **Full Replay** — reconstruct any agent's entire action history from the chain
- **Selective Audit** — query the chain by agent, mission, time range, or action type
- **External Verification** — third-party auditors can independently verify chain integrity without access to the runtime
- **Regulatory Evidence** — meets requirements for financial services, healthcare (HIPAA), and legal compliance

---

## Supported Identity Providers

| Provider | SSO (SAML 2.0) | SCIM 2.0 |
|---|---|---|
| Okta | Yes | Yes |
| Azure Active Directory | Yes | Yes |
| Ping Identity | Yes | Yes |
| OneLogin | Yes | Yes |
| Google Workspace | Yes | Yes |
| Custom SAML IdP | Yes | — |

---

## Contributing

We welcome contributions from the community. OrgKernel is the cryptographic trust foundation of an enterprise agent platform — quality and security are paramount.

### How to Contribute

1. **Fork** the repository and create your branch from `main`
2. **Write tests** for any new functionality — we maintain 100% test coverage
3. **Ensure** all existing tests pass before submitting
4. **Document** any new public APIs or modules
5. **Submit** a Pull Request with a clear description of the change and its motivation

### Reporting Security Issues

If you discover a security vulnerability, **do not open a public issue**. Please disclose responsibly by emailing [developer@metaprise.ai](mailto:developer@metaprise.ai). We will acknowledge receipt within 48 hours and provide a remediation timeline.

### Reporting Bugs & Feature Requests

Open an [issue](https://github.com/MetapriseAI/OrgKernel/issues) and use the appropriate template. Please include:

- A clear and descriptive title
- Steps to reproduce (for bugs)
- Expected vs. actual behavior
- Environment details (OS, language runtime version)

### Code of Conduct

All contributors are expected to adhere to our [Code of Conduct](CODE_OF_CONDUCT.md). We are committed to providing a welcoming and inclusive environment for everyone.

---

## License

OrgKernel is licensed under the **Apache License 2.0**. See [LICENSE](LICENSE) for the full text.

> The trust foundation you depend on is fully open-source. Inspect every line, audit the cryptography, fork for your own infrastructure, and contribute improvements back to the community. No vendor lock-in, no black boxes.

---

<p align="center">
  Built by <a href="https://www.metaprise.ai">Metaprise</a> &nbsp;·&nbsp;
  <a href="https://www.trymetaprise.com/aura/orgkernel.html">Documentation</a> &nbsp;·&nbsp;
  <a href="https://github.com/MetapriseAI/OrgKernel/issues">Issues</a> &nbsp;·&nbsp;
  <a href="mailto:developer@metaprise.ai">Contact</a>
</p>
