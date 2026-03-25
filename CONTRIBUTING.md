# Contributing to OrgKernel

Thank you for your interest in contributing to OrgKernel — the open-source cryptographic trust layer for enterprise AI agents. We welcome contributions from the community and are committed to making the process as transparent and collaborative as possible.

## Table of Contents

- [Scope of This Project](#scope-of-this-project)
- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [How to Contribute](#how-to-contribute)
- [Pull Request Process](#pull-request-process)
- [Coding Standards](#coding-standards)
- [Reporting Security Issues](#reporting-security-issues)
- [Reporting Bugs](#reporting-bugs)
- [Feature Requests](#feature-requests)

---

## Scope of This Project

OrgKernel currently implements **three core primitives**:

| Primitive | File | Schema | Description |
|---|---|---|---|
| **AgentIdentity** | `orgkernel/agent_identity.py` | `schemas/agent_identity_schema.json` | Cryptographic organizational credential for AI agents |
| **ExecutionToken** | `orgkernel/execution_token.py` | `schemas/execution_token_schema.json` | Scoped, time-bounded permission token |
| **AuditChain** | `orgkernel/audit_chain.py` | `schemas/audit_chain_schema.json` | Append-only, hash-chained execution audit log |

Contributions outside these three modules will not be accepted unless discussed with maintainers first.

## Code of Conduct

This project adheres to our [Code of Conduct](CODE_OF_CONDUCT.md). By participating, you are expected to uphold this standard. Please report unacceptable behavior to developer@metaprise.ai.

## Getting Started

### Prerequisites

- Python 3.10+ (3.12 recommended)
- A database: PostgreSQL 18.1+, MySQL, or SQLite (for runtime tests)
- Git

### Setup

```bash
git clone https://github.com/MetapriseAI/OrgKernel.git
cd OrgKernel
python -m venv .venv
# Windows
.venv\Scripts\activate
# macOS / Linux
source .venv/bin/activate

pip install -e ".[dev]"

# Optional: configure database
cp env/.env.example env/.env.dev
# edit env/.env.dev with your database connection string
```

### Running Tests

```bash
# Run all module tests
python -m pytest tests/

# Run individual module tests
python -m pytest tests/test_agent_identity.py
python -m pytest tests/test_execution_token.py
python -m pytest tests/test_audit_chain.py
```

## How to Contribute

1. **Fork** the repository
2. **Create a branch** from `main`: `git checkout -b feat/your-feature-name`
   - `feat/` — new features
   - `fix/` — bug fixes
   - `docs/` — documentation only
   - `test/` — test-only changes
3. **Make your changes** — always include or update tests
4. **Ensure all tests pass** — `python -m pytest tests/`
5. **Submit a Pull Request**

## Pull Request Process

- All PRs must target the `main` branch
- Every PR requires at least one review from a maintainer
- We maintain **high test coverage** — new code must include tests
- Update relevant documentation if your change affects public APIs or schemas
- Reference any related issues in your PR description (e.g., `Fixes #42`)
- The three modules in scope are: `AgentIdentity`, `ExecutionToken`, and `AuditChain`. Changes outside this scope require prior discussion

## Coding Standards

- Follow [PEP 8](https://peps.python.org/pep-0008/) for Python code
- Use **type hints** for all public functions and class attributes
- Write **docstrings** for all public classes and methods; reference the canonical schema (`schemas/*.json`) by section
- Keep functions focused and small — each OrgKernel module has a single responsibility
- Use **Pydantic v2** for all data models; never use `pydantic.BaseModel` v1 patterns
- **Never commit secrets, API keys, or credentials** — the `.gitignore` enforces this; always use environment variables
- All ID fields use prefixed formats: `aid_` (AgentIdentity), `tok_` (ExecutionToken), `ac_` (AuditChain), `aue_` (AuditEntry); do not invent new prefixes without schema approval
- Schema files (`schemas/*.json`) are the **canonical source of truth** for data shapes; Python models are reference implementations. Any change that affects a schema must update both

## Reporting Security Issues

**Do not open a public issue for security vulnerabilities.**

Please see [SECURITY.md](SECURITY.md) for our full security disclosure policy. Email developer@metaprise.ai for responsible disclosure.

## Reporting Bugs

Open an [issue](https://github.com/MetapriseAI/OrgKernel/issues) and include:

- A clear and descriptive title prefixed with `[Bug]`
- Steps to reproduce
- Expected vs. actual behavior
- Environment details (OS, Python version, database type and version)
- Relevant logs or error messages
- A minimal test case that reproduces the issue is highly appreciated

## Feature Requests

Open an [issue](https://github.com/MetapriseAI/OrgKernel/issues) with the label `enhancement` and describe:

- Which of the three primitives your request relates to (AgentIdentity / ExecutionToken / AuditChain)
- The problem you are trying to solve
- Your proposed solution
- Any alternatives you considered

Feature requests outside the three core primitives will be closed without discussion unless accompanied by a detailed rationale.
