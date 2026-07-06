# OrgKernel

<p align="center">
  <strong>The Open-Source Trust Layer for AI Agents</strong><br/>
  Cryptographic agent identity, scoped execution, and tamper-evident audit trails —<br/>
  transparent by design, not by promise.
</p>

<p align="center">
  <a href="https://github.com/MetapriseAI/OrgKernel/blob/main/LICENSE"><img src="https://img.shields.io/badge/License-Apache%202.0-blue.svg" alt="License: Apache 2.0" /></a>
  <a href="https://github.com/MetapriseAI/OrgKernel/stargazers"><img src="https://img.shields.io/github/stars/MetapriseAI/OrgKernel?style=flat&color=yellow" alt="GitHub Stars" /></a>
  <a href="https://github.com/MetapriseAI/OrgKernel/issues"><img src="https://img.shields.io/github/issues/MetapriseAI/OrgKernel" alt="GitHub Issues" /></a>
  <a href="https://github.com/MetapriseAI/OrgKernel/pulls"><img src="https://img.shields.io/github/issues-pr/MetapriseAI/OrgKernel" alt="Pull Requests" /></a>
  <img src="https://img.shields.io/badge/Python-3.10+-3776AB?logo=python" alt="Python 3.10+" />
  <img src="https://img.shields.io/badge/FastAPI-supported-009688?logo=fastapi" alt="FastAPI" />
  <img src="https://img.shields.io/badge/PostgreSQL-supported-336791?logo=postgresql" alt="PostgreSQL" />
</p>

<p align="center">
  <b>3</b> Core Modules &nbsp;·&nbsp; <b>27</b> REST Endpoints &nbsp;·&nbsp; PostgreSQL / MySQL / SQLite Persistence &nbsp;·&nbsp; Works with LangGraph, CrewAI &amp; AutoGen
</p>

---

## The four questions

Every organization that deploys AI agents eventually asks the same four questions:

1. **Who is this agent?** → `AgentIdentity` — a cryptographic credential (Ed25519 keypair) signed by your Org CA
2. **What can it do?** → `ExecutionToken` — scoped, time-bounded permissions with tool allowlists and parameter bounds
3. **What did it do?** → `AuditChain` — an append-only, SHA-256 hash-chained execution log
4. **Who authorized it?** → the organizational authority chain — a verifiable lineage of who granted what

Agent frameworks help you *build* and *orchestrate* agents. None of them answer these questions. OrgKernel does — and because it sits in the execution path, it can't be bypassed. Governance is built into the engine, not left to the application developer.

### Authorization is not a boolean — it's a graph

In a real organization, permission is never a single yes/no flag. A mission's execution permission is determined jointly by four layers — **organization**, **department**, **role**, and **instance**. Any layer's denial blocks execution.

Consider an agent that attempts to spend $10,000 to complete a task. The request is blocked — purchasing authority at that amount belongs to the department lead. With OrgKernel, the block is enforced at the token scope check, and the full context (which agent, which mission, what it requested, why it was denied) is already in the audit chain when the department lead asks what happened.

📖 Read the launch announcement: [Introducing OrgKernel](https://blog.metaprise.ai/)

---

## Part of Metaprise AURA

OrgKernel is the open-source trust foundation of [AURA](https://metaprise.ai/aura/aura.html), the execution governance engine of the [Metaprise Enterprise Agent Operating System](https://www.metaprise.ai). Every agent running on Metaprise — across banking, healthcare, insurance, and capital-markets deployments — authenticates, executes, and is audited through OrgKernel primitives.

You don't need Metaprise to use OrgKernel. It's a standalone Apache 2.0 Python library that runs entirely on your own infrastructure — no API key, no phone-home, no vendor lock-in. Inspect every line, audit the cryptography, fork it for your own stack.

---

## What's in the box

| Capability                       | Status       | Description                                                                                                                          |
| -------------------------------- | ------------ | ------------------------------------------------------------------------------------------------------------------------------------ |
| **Cryptographic Identity (PKI)** | ✅ Available  | Ed25519 keypairs, Org CA signing, CSR flow, challenge-response verification, full suspend/revoke/reactivate lifecycle                |
| **Scoped Execution Tokens**      | ✅ Available  | Mission-scoped permission tokens with tool allowlists, immutable & bounded parameters, and Ed25519 signatures to prevent token grafting |
| **Hash-Chained Audit Trail**     | ✅ Available  | Three-layer audit (IDENTITY / EXECUTION / COMPLIANCE) persisted to PostgreSQL/MySQL/SQLite with SHA-256 hash chaining and integrity verification |

Identity plus execution token together form the **DualToken** model: at execution time an agent presents both its organizational identity credential and an instance-scoped execution token. Both must validate before a tool call proceeds.

Upcoming capabilities (mission lifecycle, tool gateway, policy engine, authority graph, data classifier, SSO/SAML, SCIM) are tracked in the [Roadmap](#roadmap).

---

## Why OrgKernel

| If you use…                        | You get…                                  | What's missing                                          |
| ---------------------------------- | ------------------------------------------ | -------------------------------------------------------- |
| LangGraph / CrewAI / AutoGen alone | Agent orchestration                        | No verifiable identity, no scoped authority, no tamper-evident audit |
| API keys per agent                 | Coarse access control                      | Keys are permanent, unscoped, unauditable, and shareable |
| Application-level logging          | A log you *hope* is complete               | Logs can be edited or deleted; nothing proves integrity  |
| **OrgKernel**                      | Identity + scoped authority + audit, enforced in the execution path | —                                        |

Key properties:

- **Enforced, not advisory.** Scope checks run before every tool call. There is no code path around them.
- **Tamper-evident, not tamper-"proof by promise".** Any deletion, modification, or reordering of audit entries breaks the SHA-256 chain and is detected by the integrity API.
- **Least privilege by construction.** Tokens carry only the tools and parameter bounds a single mission needs, and they expire.
- **Compliance-grade evidence.** The audit chain supports full replay of any agent's history and independent third-party verification — designed for the evidentiary requirements of financial, healthcare, and legal deployments.

---

## System Architecture

```
Agent Platform
    |
    |-- CSR submitted --> AgentIdentityService.submit_csr()
    |                      |-- validates duplicate
    |                      v
    |-- CSR issued -----> AgentIdentityService.issue_from_csr()
    |                      |-- generates Ed25519 keypair (server-side)
    |                      |-- signs certificate with Org CA
    |                      |-- returns certificate + private_key_pem ONCE
    |                      |-- persists identity record (NO private key)
    |                      v
    |                  AgentCertificate + AgentIdentity
    |
    |-- token mint ----> ExecutionTokenService.mint()
    |                      |-- Ed25519-signed by Org CA (prevents Token Grafting)
    |                      |-- tool allowlist + numeric bounds
    |                      v
    |                  ExecutionToken
    |
    |-- scope check ---> ExecutionTokenService.check_scope()
    |                      |-- tool in scope?
    |                      |-- bounded params within limits?
    |                      v
    |                  ScopeCheckResponse (ALLOWED or BLOCKED)
    |
    |-- audit init ----> AuditChainService.initialize()
    |                      |-- writes genesis IDENTITY entry (SHA-256)
    |                      v
    |-- audit append ---> AuditChainService.append()
    |                      |-- SHA-256 prev_hash chain
    |                      v
    |-- audit verify ---> AuditChainService.verify_integrity()
                           |-- recomputes all hashes
                           |-- detects deletion / tampering / reorder
```

### Challenge-Response Authentication

| Step | Party            | Action                                                                                                                                                               |
| ---- | ---------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 1    | Verifier         | Calls `AgentIdentityService.request_challenge(agent_id, issued_by)` — generates random nonce + `challenge_id`, stored in memory with 5-minute TTL                    |
| 2    | Verifier → Agent | Sends nonce to the target Agent                                                                                                                                      |
| 3    | Agent            | Signs the nonce with its Ed25519 private key, constructs `ChallengeResponse(challenge_id, nonce, public_key, signature)`                                             |
| 4    | Verifier         | Calls `AgentIdentityService.verify_challenge(response)` — validates: nonce one-time use (anti-replay), Ed25519 signature correct, certificate ACTIVE and not expired |

**Attack vectors prevented:** Replay attack (nonce consumed after one use), private key theft (signature must match nonce), Token Grafting (`token.agent_id == caller.agent_id` verified at every scope check).

### Three-Layer Audit Semantics

| Audit Layer       | Triggered By                                          | Semantics                                                            |
| ----------------- | ----------------------------------------------------- | -------------------------------------------------------------------- |
| **L1 Business**   | `AuditChainService.initialize()`                      | Business perspective: who, in which org, for which mission           |
| **L2 Execution**  | Every tool call + state transition + approval + close | Execution perspective: every behavior the system performed           |
| **L3 Compliance** | Escalation to human compliance review                 | Compliance perspective: what triggered human compliance intervention |

---

## Security Model

### Token Grafting Prevention

The Execution Token is Ed25519-signed by the Org CA covering the full payload (scope, bounds, expiry). Any modification invalidates the signature. The scope check verifies `token.agent_id == caller.agent_id` on every call.

### Challenge-Response Authentication

Agents prove identity via Ed25519 challenge-response with one-time nonces. Certificates are verified against the Org CA's public key. Revocation and expiry are enforced at verification time.

### Tamper-Evident Audit Chain

Every audit entry carries a SHA-256 hash of its content and a `prev_hash` linking to the previous entry. The integrity API recomputes all hashes and detects any deleted, modified, or reordered entries.

| Check                                             | Detects                          |
| ------------------------------------------------- | -------------------------------- |
| Hash present                                      | Hash stripped by attacker        |
| Sequence continuity (IDs increment by 1)          | Entry deletion                   |
| `prev_hash` linkage                               | Entry modification or reordering |
| Content hash match (stored == recomputed SHA-256) | Entry content tampering          |

---

## Quick Start

### Install

Requires Python 3.10+. Install from source:

```bash
git clone https://github.com/MetapriseAI/OrgKernel.git
cd OrgKernel
pip install -e ".[postgres]"   # postgres | mysql | sqlite
```

Database driver extras: `[postgres]` — PostgreSQL (recommended) · `[mysql]` — MySQL / MariaDB · `[sqlite]` — SQLite for local dev.

### Service layer

Direct Python async — no HTTP, no API key.

```python
from datetime import datetime, timedelta, timezone
from sqlalchemy.ext.asyncio import AsyncSession

from orgkernel.database import async_engine, init_db, get_session_factory
from orgkernel.services import AgentIdentityService, ExecutionTokenService, AuditChainService
from orgkernel.schemas import AgentIdentityCSR, ExecutionTokenCreate, ScopeCheckRequest, AuditLayer

async def demo(db: AsyncSession) -> None:
    # Configure database
    async_engine.url = "postgresql+asyncpg://user:pass@localhost:5432/orgkernel"
    await init_db()

    identity_svc = AgentIdentityService(db)
    token_svc    = ExecutionTokenService(db)
    audit_svc    = AuditChainService()

    # 1. Issue agent identity (CSR flow)
    csr = AgentIdentityCSR(
        agent_name="invoice-processor",
        org_id="acme-corp",
        requested_ou="finance_team",
        public_key="<agent-ed25519-public-key-base64url>",
        purpose="automated-invoice-processing",
    )
    issued = await identity_svc.issue_from_csr(csr)
    print(f"Agent ID: {issued.identity.agent_id}")       # → "aid_7f3k9..."
    print(f"Private key (returned once): {issued.agent_private_key_pem[:30]}...")

    # 2. Mint scoped execution token (Ed25519-signed by Org CA)
    token = await token_svc.mint(
        ExecutionTokenCreate(
            agent_id=issued.identity.agent_id,
            mission_id="msn_invoice01",
            execution_scope=["read_invoice", "write_payment_draft"],
            immutable_params={"currency": "USD"},
            bounded_params=[{"name": "amount", "upper_bound": 50000}],
            expires_at=datetime.now(timezone.utc) + timedelta(hours=4),
        )
    )
    print(f"Token: {token.token_id}")   # → "tok_abc123..."
    print(f"Signed: {token.token_signature[:20]}...")

    # 3. Enforce scope before every tool call
    allowed = await token_svc.check_scope(
        ScopeCheckRequest(
            token_id=token.token_id,
            tool_name="read_invoice",
            params={"invoice_id": "4521"},
        )
    )
    print(f"Scope check passed: {allowed.passed}")  # → True

    # 4. Initialize audit chain (writes genesis IDENTITY entry)
    chain_id = await audit_svc.initialize(
        db,
        mission_id="msn_invoice01",
        agent_id=issued.identity.agent_id,
    )

    # 5. Append audit entries
    await audit_svc.append(
        db,
        chain_id=chain_id,
        layer=AuditLayer.EXECUTION,
        event="EXECUTION_tool_call",
        agent_id=issued.identity.agent_id,
        mission_id="msn_invoice01",
        data={"tool": "read_invoice", "invoice_id": "4521", "result": "success", "duration_ms": 230},
        token_id=token.token_id,
    )

    # 6. Verify audit integrity
    assert await audit_svc.verify_integrity(db, chain_id) is True

    await db.commit()
```

### FastAPI integration

Mount the built-in HTTP router for 27 REST endpoints across identity, token, and audit.

```python
from fastapi import FastAPI, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from orgkernel.database import async_engine, get_session_factory, init_db
from orgkernel.pyapi.router import router

app = FastAPI(title="Agent Platform powered by OrgKernel")

@app.on_event("startup")
async def startup() -> None:
    async_engine.url = "postgresql+asyncpg://user:pass@localhost:5432/orgkernel"
    await init_db()

async def get_db() -> AsyncSession:
    factory = get_session_factory(async_engine)
    async with factory() as session:
        yield session

app.include_router(router, prefix="/orgkernel", get_db=get_db)
# All 27 endpoints under /orgkernel/...
```

---

## Using OrgKernel with agent frameworks

OrgKernel is framework-agnostic: it wraps the *tool boundary*, so it works with LangGraph, CrewAI, AutoGen, or any custom agent loop. The pattern is always the same — check scope before the call, append to the audit chain after.

```python
# Generic tool wrapper — drop into any framework's tool layer
async def governed_tool_call(db, token_svc, audit_svc, *, token_id, chain_id,
                             agent_id, mission_id, tool_name, params, tool_fn):
    check = await token_svc.check_scope(
        ScopeCheckRequest(token_id=token_id, tool_name=tool_name, params=params)
    )
    if not check.passed:
        await audit_svc.append(db, chain_id=chain_id, layer=AuditLayer.EXECUTION,
                               event="EXECUTION_tool_blocked", agent_id=agent_id,
                               mission_id=mission_id, token_id=token_id,
                               data={"tool": tool_name, "params": params})
        raise PermissionError(f"{tool_name} blocked by execution token scope")

    result = await tool_fn(**params)

    await audit_svc.append(db, chain_id=chain_id, layer=AuditLayer.EXECUTION,
                           event="EXECUTION_tool_call", agent_id=agent_id,
                           mission_id=mission_id, token_id=token_id,
                           data={"tool": tool_name, "params": params, "result": "success"})
    return result
```

With LangGraph, wrap each tool node; with CrewAI, wrap each `Tool`'s `func`; with AutoGen, wrap registered functions. Every agent action becomes identity-bound, scope-checked, and audit-chained without changing your orchestration logic.

---

## REST API Reference

All endpoints are prefixed `/orgkernel`. No API key — the server is your own infrastructure.

### Endpoint overview

| Method | Path                                           | Description                              |
| ------ | ---------------------------------------------- | ---------------------------------------- |
| `POST` | `/orgkernel/identity/csr/submit`               | Submit CSR (step 1 of PKI lifecycle)     |
| `POST` | `/orgkernel/identity/issue`                    | Issue identity from CSR (step 2–3)       |
| `GET`  | `/orgkernel/identity/{agent_id}`               | Get identity by ID                       |
| `GET`  | `/orgkernel/identity/{agent_id}/certificate`   | Get signed certificate                   |
| `POST` | `/orgkernel/identity/verify`                   | Static verification (status + expiry)    |
| `POST` | `/orgkernel/identity/challenge/request`        | Request cryptographic challenge          |
| `POST` | `/orgkernel/identity/challenge/verify`         | Verify signed challenge                  |
| `POST` | `/orgkernel/identity/{agent_id}/suspend`       | Suspend identity                         |
| `POST` | `/orgkernel/identity/{agent_id}/reactivate`    | Reactivate suspended identity            |
| `POST` | `/orgkernel/identity/{agent_id}/revoke`        | Permanently revoke identity              |
| `GET`  | `/orgkernel/identity/org/{org_id}`             | List all identities for an org           |
| `GET`  | `/orgkernel/identity/org/{org_id}/page`        | Paginated list by org                    |
| `POST` | `/orgkernel/token/mint`                        | Mint a scoped, time-bounded token        |
| `GET`  | `/orgkernel/token/{token_id}`                  | Get token by ID                          |
| `POST` | `/orgkernel/token/scope/check`                 | Validate a tool call against token scope |
| `POST` | `/orgkernel/token/{token_id}/use`              | Mark token as consumed                   |
| `POST` | `/orgkernel/token/{token_id}/invalidate`       | Early invalidation with reason           |
| `GET`  | `/orgkernel/token/mission/{mission_id}/active` | Get active token for a mission           |
| `GET`  | `/orgkernel/token/mission/{mission_id}/page`   | Paginated tokens by mission              |
| `GET`  | `/orgkernel/token/agent/{agent_id}/page`       | Paginated tokens by agent                |
| `POST` | `/orgkernel/audit/initialize`                  | Initialize a new AuditChain              |
| `POST` | `/orgkernel/audit/{chain_id}/append`           | Append an audit entry                    |
| `POST` | `/orgkernel/audit/{chain_id}/close`            | Close an AuditChain                      |
| `GET`  | `/orgkernel/audit/mission/{mission_id}`        | Get AuditChain by mission\_id            |
| `GET`  | `/orgkernel/audit/{chain_id}`                  | Get AuditChain by chain\_id              |
| `GET`  | `/orgkernel/audit/{chain_id}/verify`           | Verify chain integrity                   |
| `GET`  | `/orgkernel/audit/agent/{agent_id}/page`       | Paginated chains by agent                |

### curl examples

```bash
BASE="http://localhost:8000/orgkernel"

# 1. Submit CSR and issue identity
curl -X POST "$BASE/identity/csr/submit" \
  -H "Content-Type: application/json" \
  -d '{
    "agent_name": "compliance-agent",
    "org_id": "acme-corp",
    "requested_ou": "legal/compliance",
    "public_key": "<agent-ed25519-public-key-base64url>",
    "purpose": "policy-audit"
  }'

curl -X POST "$BASE/identity/issue" \
  -H "Content-Type: application/json" \
  -d '{
    "agent_name": "compliance-agent",
    "org_id": "acme-corp",
    "requested_ou": "legal/compliance",
    "public_key": "<agent-ed25519-public-key-base64url>",
    "purpose": "policy-audit"
  }'

# 2. Mint an ExecutionToken (set expires_at to a future timestamp)
curl -X POST "$BASE/token/mint" \
  -H "Content-Type: application/json" \
  -d '{
    "agent_id": "aid_7f3k9...",
    "mission_id": "msn_audit01",
    "execution_scope": ["doc_reader", "email_sender"],
    "expires_at": "2027-01-01T12:00:00Z"
  }'

# 3. Enforce scope on every tool call
curl -X POST "$BASE/token/scope/check" \
  -H "Content-Type: application/json" \
  -d '{
    "token_id": "tok_abc123...",
    "tool_name": "doc_reader",
    "params": {"doc_id": "POL-001"}
  }'
# → {"passed": true, "blocked": false, ...}

# 4. Initialize AuditChain
curl -X POST "$BASE/audit/initialize" \
  -H "Content-Type: application/json" \
  -d '{
    "mission_id": "msn_audit01",
    "agent_id": "aid_7f3k9..."
  }'
# → {"chain_id": "ac_xyz...", "message": "AuditChain initialized"}

# 5. Append audit entry
curl -X POST "$BASE/audit/ac_xyz.../append" \
  -H "Content-Type: application/json" \
  -d '{
    "layer": "EXECUTION",
    "event": "EXECUTION_tool_call",
    "agent_id": "aid_7f3k9...",
    "mission_id": "msn_audit01",
    "data": {"tool": "doc_reader", "doc_id": "POL-001", "result": "success"},
    "token_id": "tok_abc123..."
  }'

# 6. Verify AuditChain integrity
curl "$BASE/audit/ac_xyz.../verify"
# → {"chain_id": "ac_xyz...", "valid": true, "message": "Integrity check passed"}
```

---

## Schema Reference

### AgentIdentity

| Field                                           | Type     | Description                                               |
| ----------------------------------------------- | -------- | --------------------------------------------------------- |
| `agent_id`                                      | string   | Unique ID prefixed `aid_`, validated as `^aid_[a-z0-9]+$` |
| `agent_name`                                    | string   | Validated as `^[a-z][a-z0-9_-]*$` — unique per org        |
| `org_id`                                        | string   | Organization identifier, validated as `^[a-z][a-z0-9-]*$` |
| `public_key`                                    | string   | Ed25519 public key in Base64url encoding (43-44 chars)    |
| `org_ca_fingerprint`                            | string   | SHA-256 hex fingerprint of Org CA public key (64 chars)   |
| `issued_at`, `valid_until`                      | datetime | Certificate validity window                               |
| `status`                                        | enum     | `ACTIVE`, `SUSPENDED`, `REVOKED`, `EXPIRED`               |
| `revoked_at`, `revoked_by`, `revocation_reason` | mixed    | Set only when `status = REVOKED`                          |

### ExecutionToken

| Field              | Type               | Description                                                                  |
| ------------------ | ------------------ | ---------------------------------------------------------------------------- |
| `token_id`         | string             | Unique ID prefixed `tok_`                                                    |
| `execution_scope`  | list[string]       | Allowlisted tool names, min 1 item                                           |
| `immutable_params` | dict               | Key=value pairs that must match exactly at call time                         |
| `bounded_params`   | list[BoundedParam] | Named numeric bounds: `upper_bound` and `lower_bound` per param              |
| `token_signature`  | string             | Ed25519 EdDSA signature (Base64url, 86-88 chars) over canonical JSON payload |
| `expires_at`       | datetime           | Token expiry                                                                 |
| `used`             | bool               | One-time consumption flag                                                    |

### Audit Chain — Three-Layer Hash Chain

| Layer             | Triggered By                                                  | Content                                       |
| ----------------- | ------------------------------------------------------------- | --------------------------------------------- |
| **L1 Business**   | `AuditChainService.initialize()`                              | Mission objective, org, agent\_id             |
| **L2 Execution**  | `AuditChainService.append()` + state transitions + tool calls | Tool name, params, status, violations         |
| **L3 Compliance** | Escalation to human compliance review                         | Escalation reason, escalated\_to, from\_state |

### Enums

```
AgentIdentityStatus:  ACTIVE | SUSPENDED | REVOKED | EXPIRED
```

---

## Built for regulated industries

The audit chain is designed to meet evidentiary requirements in financial services, healthcare, insurance, and legal deployments:

- **Full replay** — reconstruct any agent's entire action history from the chain
- **Selective audit** — query by agent, mission, time range, or action type
- **External verification** — third-party auditors can independently verify chain integrity without trusting your database
- **Synchronous writes** — an action does not proceed until its audit entry is committed; no fire-and-forget logging

See how Metaprise applies this in [regional banking](https://metaprise.ai/solutions/banking.html), [healthcare](https://metaprise.ai/solutions/healthcare.html), [insurance](https://metaprise.ai/solutions/insurance.html), and [capital markets](https://metaprise.ai/solutions/capital-markets.html).

---

## Roadmap

The three cryptographic primitives above are production-ready. The following capabilities extend OrgKernel from trust primitives to a full governance kernel:

| Capability            | Scope                                                                                                     |
| --------------------- | ---------------------------------------------------------------------------------------------------------- |
| **Mission Lifecycle** | 8-state mission state machine (`CREATED → … → CLOSED`) with enforced transitions and boundary snapshots at approval |
| **Tool Gateway**      | Token scope enforcement in front of every external tool call: token valid, CA signature correct, agent match, tool in scope |
| **Policy Engine**     | Declarative policy CRUD with version history — forbidden tools, time restrictions, spend limits, dual approval |
| **Authority Graph**   | Org hierarchy traversal, L0–L5 approval level resolution, spend authority, multi-step approval chains       |
| **Data Classifier**   | Rule-based classification (PUBLIC → TOP_SECRET) producing routing tiers and data scope constraints          |
| **SSO / SAML 2.0**    | Enterprise single sign-on — Okta, Azure AD, Ping Identity, OneLogin, any SAML-compliant IdP                 |
| **SCIM 2.0 Sync**     | Automatic provisioning/deprovisioning — employee joins, moves, or leaves and agent permissions follow       |

Follow [releases](https://github.com/MetapriseAI/OrgKernel/releases) and the [changelog](CHANGELOG.md) for progress.

---

## Contributing

We welcome contributions from the community. OrgKernel is the cryptographic trust foundation of an enterprise agent platform — quality and security are paramount.

1. **Fork** the repository and create your branch from `main`
2. **Write tests** for any new functionality
3. **Ensure** all existing tests pass before submitting
4. **Document** any new public APIs or modules
5. **Submit** a Pull Request with a clear description of the change and its motivation

See [CONTRIBUTING.md](CONTRIBUTING.md) for details.

### Reporting Security Issues

If you discover a security vulnerability, **do not open a public issue**. Please disclose responsibly by emailing <developer@metaprise.ai>. We will acknowledge receipt within 48 hours and provide a remediation timeline. See [SECURITY.md](SECURITY.md).

### Reporting Bugs & Feature Requests

Open an [issue](https://github.com/MetapriseAI/OrgKernel/issues) with a clear title, steps to reproduce (for bugs), expected vs. actual behavior, and environment details (OS, Python version, database version).

---

## License

OrgKernel is licensed under the **Apache License 2.0**. See [LICENSE](LICENSE) for the full text.

> The trust foundation you depend on is fully open-source. Inspect every line, audit the cryptography, fork for your own infrastructure, and contribute improvements back to the community. No vendor lock-in, no black boxes.

---

Built by [Metaprise](https://www.metaprise.ai) · [AURA](https://metaprise.ai/aura/aura.html) · [Issues](https://github.com/MetapriseAI/OrgKernel/issues) · [Contact](mailto:developer@metaprise.ai)
Python 3.10+ · FastAPI · SQLAlchemy Async · PostgreSQL / MySQL / SQLite
