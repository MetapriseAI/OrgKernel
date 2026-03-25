"""
Pydantic schemas for AgentIdentity.

AgentIdentity follows a full PKI lifecycle:
    1. Agent generates Ed25519 keypair locally
    2. Agent submits CSR (public key + metadata)
    3. Org CA validates and signs -> AgentCertificate
    4. Agent uses certificate for challenge-response verification
    5. Any system verifies signature against Org CA public root

Cryptographic foundation:
    - Ed25519 for high performance and security
    - SHA-256 for CA fingerprint and content hashing
    - Challenge-response to prevent replay attacks
"""
from __future__ import annotations

import base64
import json
import re
import secrets
import time
from datetime import datetime, timezone, timedelta
from enum import Enum
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, Field, field_validator, model_validator


_AGENT_ID_RE   = re.compile(r"^aid_[a-z0-9]+$")
_AGENT_NAME_RE = re.compile(r"^[a-z][a-z0-9_-]*$")
_ORG_ID_RE     = re.compile(r"^[a-z][a-z0-9-]*$")
_CA_FP_RE      = re.compile(r"^[a-f0-9]{64}$")
_B64URL_RE     = re.compile(r"^[A-Za-z0-9_-]{43,44}$")
_B64URL_SIG_RE = re.compile(r"^[A-Za-z0-9_-]{86,88}$")
_NONCE_RE      = re.compile(r"^[A-Za-z0-9_=-]{16,64}$")


def _new_agent_id() -> str:
    return "aid_" + uuid4().hex[:12]


def _now_utc() -> datetime:
    return datetime.now(timezone.utc)


# ── Status Enum ────────────────────────────────────────────────────────────────


class AgentIdentityStatus(str, Enum):
    """Lifecycle status of an AgentIdentity credential."""
    ACTIVE    = "ACTIVE"
    SUSPENDED = "SUSPENDED"
    REVOKED   = "REVOKED"
    EXPIRED   = "EXPIRED"


# ── AgentIdentity ─────────────────────────────────────────────────────────────


class AgentIdentity(BaseModel):
    """
    Cryptographic organizational credential for an AI agent.
    Issued by AgentIdentityService using Ed25519 keypairs signed by the Org CA.

    Not an API key. An AgentIdentity is:
        - Revocable at any time by org authority
        - Time-bounded (optional expiry)
        - Tied to an organizational unit, not a developer account
        - Cryptographically verifiable via public_key + org_ca_fingerprint
    """
    model_config = {"frozen": True}

    agent_id: str = Field(
        default_factory=_new_agent_id,
        description="Globally unique agent identifier. Assigned at issuance.",
    )
    agent_name: str = Field(
        min_length=2, max_length=64,
        description="Human-readable agent name, unique per org.",
    )
    org_id: str = Field(
        min_length=2, max_length=64,
        description="Target organization identifier.",
    )
    issued_by: str = Field(
        min_length=1, max_length=64,
        description="Organizational unit that authorized issuance.",
    )
    public_key: str = Field(
        description="Ed25519 public key in Base64url encoding. Private key never stored here.",
    )
    org_ca_fingerprint: str = Field(
        description="SHA-256 fingerprint of the Org CA that signed this identity.",
    )
    issued_at: datetime = Field(default_factory=_now_utc)
    valid_until: datetime | None = Field(
        default=None,
        description="UTC expiry timestamp. Null means no expiry — valid until explicitly revoked.",
    )
    status: AgentIdentityStatus = Field(default=AgentIdentityStatus.ACTIVE)
    revoked_at: datetime | None = None
    revoked_by: str | None = None
    revocation_reason: str | None = None
    metadata: dict[str, str] = Field(default_factory=dict)

    @field_validator("agent_id")
    @classmethod
    def _validate_agent_id(cls, v: str) -> str:
        if not _AGENT_ID_RE.match(v):
            raise ValueError(f"agent_id '{v}' must match ^aid_[a-z0-9]+$")
        return v

    @field_validator("agent_name")
    @classmethod
    def _validate_agent_name(cls, v: str) -> str:
        if not _AGENT_NAME_RE.match(v):
            raise ValueError(f"agent_name '{v}' must match ^[a-z][a-z0-9_-]*$")
        return v

    @field_validator("org_id")
    @classmethod
    def _validate_org_id(cls, v: str) -> str:
        if not _ORG_ID_RE.match(v):
            raise ValueError(f"org_id '{v}' must match ^[a-z][a-z0-9-]*$")
        return v

    @field_validator("public_key")
    @classmethod
    def _validate_public_key(cls, v: str) -> str:
        if not _B64URL_RE.match(v):
            raise ValueError(
                "public_key must be a 43-44 char Base64url Ed25519 public key."
            )
        return v

    @field_validator("org_ca_fingerprint")
    @classmethod
    def _validate_fingerprint(cls, v: str) -> str:
        if not _CA_FP_RE.match(v):
            raise ValueError(
                "org_ca_fingerprint must be a 64-char lowercase hex SHA-256 hash."
            )
        return v

    @model_validator(mode="after")
    def _validate_revocation_fields(self) -> AgentIdentity:
        if self.status == AgentIdentityStatus.REVOKED:
            if not self.revoked_at:
                raise ValueError("revoked_at is required when status is REVOKED.")
            if not self.revoked_by:
                raise ValueError("revoked_by is required when status is REVOKED.")
        return self

    @property
    def is_active(self) -> bool:
        """True if identity is ACTIVE and not expired."""
        if self.status != AgentIdentityStatus.ACTIVE:
            return False
        if self.valid_until and _now_utc() > self.valid_until:
            return False
        return True

    def revoke(self, revoked_by: str, reason: str) -> AgentIdentity:
        """Return a new AgentIdentity with REVOKED status."""
        return self.model_copy(update={
            "status": AgentIdentityStatus.REVOKED,
            "revoked_at": _now_utc(),
            "revoked_by": revoked_by,
            "revocation_reason": reason,
        })

    def suspend(self) -> AgentIdentity:
        """Return a new AgentIdentity with SUSPENDED status."""
        return self.model_copy(update={"status": AgentIdentityStatus.SUSPENDED})

    def reactivate(self) -> AgentIdentity:
        """
        Return a new AgentIdentity with ACTIVE status.
        Only valid from SUSPENDED. REVOKED identities cannot be reactivated.
        """
        if self.status == AgentIdentityStatus.REVOKED:
            raise ValueError(
                "REVOKED identities cannot be reactivated. Issue a new identity."
            )
        return self.model_copy(update={"status": AgentIdentityStatus.ACTIVE})

    def to_signable_payload(self) -> str:
        """Return canonical JSON for signing."""
        payload = {
            "agent_id": self.agent_id,
            "agent_name": self.agent_name,
            "org_id": self.org_id,
            "issued_by": self.issued_by,
            "public_key": self.public_key,
            "org_ca_fingerprint": self.org_ca_fingerprint,
            "issued_at": self.issued_at.isoformat(),
            "valid_until": self.valid_until.isoformat() if self.valid_until else None,
        }
        return json.dumps(payload, separators=(",", ":"), sort_keys=True)


# ── CSR (Certificate Signing Request) ──────────────────────────────────────────


class AgentIdentityCSR(BaseModel):
    """
    Certificate Signing Request submitted by an agent.

    Step 1 of the PKI lifecycle: Agent generates a keypair locally,
    then submits this CSR with the public key and metadata.
    The Org CA validates the request and issues a signed certificate.
    """
    csr_id: str = Field(
        default_factory=lambda: "csr_" + uuid4().hex[:12],
        description="Unique CSR identifier.",
    )
    agent_name: str = Field(
        min_length=2, max_length=64,
        description="Human-readable agent name, unique per org.",
    )
    org_id: str = Field(
        min_length=2, max_length=64,
        description="Target organization identifier.",
    )
    requested_ou: str = Field(
        min_length=1, max_length=64,
        description="Requested Organizational Unit that will authorize issuance.",
    )
    public_key: str = Field(
        description="Ed25519 public key in Base64url encoding.",
    )
    purpose: str = Field(
        min_length=1, max_length=256,
        description="Intended purpose of this agent identity.",
    )
    metadata: dict[str, str] = Field(
        default_factory=dict,
        description="Additional metadata (e.g., environment, version).",
    )
    requested_validity_days: int | None = Field(
        default=None, ge=1, le=3650,
        description="Requested validity period in days (null = no expiry).",
    )
    submitted_at: datetime = Field(default_factory=_now_utc)

    @field_validator("public_key")
    @classmethod
    def _validate_public_key(cls, v: str) -> str:
        if not _B64URL_RE.match(v):
            raise ValueError(
                "public_key must be a 43-44 char Base64url Ed25519 public key."
            )
        return v

    @field_validator("agent_name")
    @classmethod
    def _validate_agent_name(cls, v: str) -> str:
        if not _AGENT_NAME_RE.match(v):
            raise ValueError(f"agent_name '{v}' must match ^[a-z][a-z0-9_-]*$")
        return v

    @field_validator("org_id")
    @classmethod
    def _validate_org_id(cls, v: str) -> str:
        if not _ORG_ID_RE.match(v):
            raise ValueError(f"org_id '{v}' must match ^[a-z][a-z0-9-]*$")
        return v


# ── Agent Certificate ───────────────────────────────────────────────────────────


class AgentCertificate(BaseModel):
    """
    Signed certificate issued by the Org CA.

    This is the artifact returned after the CA validates a CSR and signs it.
    The agent stores this certificate and presents it as proof of identity.

    Verification flow:
        1. Any system receives a request with this certificate
        2. Extract public_key + ca_signature
        3. Verify ca_signature against Org CA public key
        4. Check certificate fields (org_id, valid_until, status)
        5. Optionally: issue a challenge for dynamic verification
    """
    model_config = {"frozen": True}

    certificate_id: str = Field(
        description="Unique certificate identifier (same as agent_id after issuance).",
    )
    agent_id: str = Field(description="Assigned agent_id (aid_xxx).")
    agent_name: str
    org_id: str
    issued_by: str = Field(
        description="Organizational unit that signed this certificate.",
    )
    public_key: str = Field(
        description="Ed25519 public key from the CSR.",
    )
    ca_fingerprint: str = Field(
        description="SHA-256 fingerprint of the signing Org CA.",
    )
    ca_signature: str = Field(
        description="Ed25519 signature by Org CA over canonical certificate payload.",
    )
    issued_at: datetime
    valid_until: datetime | None = Field(
        default=None,
        description="UTC expiry timestamp. Null = no expiry.",
    )
    status: AgentIdentityStatus = Field(default=AgentIdentityStatus.ACTIVE)

    def to_signable_payload(self) -> str:
        """Return canonical JSON for CA signing / verification."""
        payload = {
            "certificate_id": self.certificate_id,
            "agent_id": self.agent_id,
            "agent_name": self.agent_name,
            "org_id": self.org_id,
            "issued_by": self.issued_by,
            "public_key": self.public_key,
            "ca_fingerprint": self.ca_fingerprint,
            "issued_at": self.issued_at.isoformat(),
            "valid_until": self.valid_until.isoformat() if self.valid_until else None,
        }
        return json.dumps(payload, separators=(",", ":"), sort_keys=True)

    def is_expired(self) -> bool:
        """Check if certificate has expired."""
        if self.valid_until is None:
            return False
        return _now_utc() > self.valid_until

    def is_valid_status(self) -> bool:
        """Check if status is ACTIVE (not revoked/suspended/expired)."""
        return self.status == AgentIdentityStatus.ACTIVE and not self.is_expired()


# ── Challenge-Response ──────────────────────────────────────────────────────────


class ChallengeRequest(BaseModel):
    """
    Request a cryptographic challenge for dynamic verification.

    The verifier sends a random challenge; the agent must sign it with its
    private key to prove possession.
    """
    agent_id: str = Field(min_length=10, max_length=32)
    challenge_id: str = Field(
        default_factory=lambda: "chal_" + uuid4().hex[:12],
        description="Unique challenge identifier.",
    )
    nonce: str = Field(
        min_length=16, max_length=64,
        description="Random nonce generated by the verifier.",
    )
    issued_by: str = Field(
        min_length=1, max_length=64,
        description="Identifier of the requesting system.",
    )
    created_at: datetime = Field(default_factory=_now_utc)
    expires_at: datetime = Field(
        description="UTC expiry timestamp for this challenge.",
    )

    @field_validator("nonce")
    @classmethod
    def _validate_nonce(cls, v: str) -> str:
        if not _NONCE_RE.match(v):
            raise ValueError(
                "nonce must be 16-64 chars of Base64url-safe characters."
            )
        return v

    @field_validator("expires_at")
    @classmethod
    def _validate_expiry(cls, v: datetime) -> datetime:
        if v <= _now_utc():
            raise ValueError("expires_at must be in the future.")
        return v


class ChallengeResponse(BaseModel):
    """
    Response to a challenge — agent signs the nonce with its private key.

    The verifier checks:
        1. challenge_id matches the request
        2. agent_id matches
        3. Signature verifies against the agent's public key in the certificate
    """
    challenge_id: str = Field(
        description="ID of the challenge being responded to.",
    )
    agent_id: str
    signature: str = Field(
        description="Ed25519 signature over nonce using agent's private key.",
    )
    public_key: str = Field(
        description="Ed25519 public key (for verification without DB lookup).",
    )
    certificate_id: str = Field(
        description="Certificate ID (agent_id) being used.",
    )
    issued_at: datetime = Field(default_factory=_now_utc)

    @field_validator("signature")
    @classmethod
    def _validate_signature(cls, v: str) -> str:
        if not _B64URL_SIG_RE.match(v):
            raise ValueError(
                "signature must be a 86-88 char Base64url Ed25519 signature (64 bytes)."
            )
        return v


class ChallengeVerificationResult(BaseModel):
    """Result of challenge-response verification."""
    challenge_id: str
    agent_id: str
    challenge_passed: bool = Field(
        description="True if signature matches agent's public key.",
    )
    certificate_valid: bool = Field(
        description="True if certificate is ACTIVE and not expired.",
    )
    overall_valid: bool = Field(
        description="True if both challenge and certificate are valid.",
    )
    message: str
    verified_at: datetime = Field(default_factory=_now_utc)


# ── Request / Response Schemas ────────────────────────────────────────────────


class AgentIdentityCreate(BaseModel):
    """Request to issue a new AgentIdentity (legacy method — wraps CSR flow)."""
    agent_name: str = Field(min_length=2, max_length=64)
    org_id: str = Field(min_length=2, max_length=64)
    issued_by: str = Field(min_length=1, max_length=64)
    valid_until: datetime | None = Field(
        default=None,
        description="UTC expiry timestamp. Null means no expiry.",
    )
    metadata: dict[str, str] = Field(default_factory=dict)


class AgentIdentityOut(BaseModel):
    """Response schema for AgentIdentity queries."""
    agent_id: str
    agent_name: str
    org_id: str
    issued_by: str
    public_key: str
    org_ca_fingerprint: str
    issued_at: datetime
    valid_until: datetime | None
    status: AgentIdentityStatus
    is_active: bool
    revoked_at: datetime | None
    revoked_by: str | None
    revocation_reason: str | None
    metadata: dict[str, str]

    model_config = {"from_attributes": True}


class AgentIdentityRevoke(BaseModel):
    """Request to revoke an AgentIdentity."""
    revoked_by: str = Field(min_length=1, max_length=64)
    reason: str = Field(min_length=1, max_length=500)


class AgentIdentityVerify(BaseModel):
    """
    Request to verify an AgentIdentity (static check).
    For cryptographic verification, use the challenge-response flow instead.
    """
    agent_id: str = Field(min_length=10, max_length=32)


class AgentIdentityVerifyResponse(BaseModel):
    """Response from an AgentIdentity static verification."""
    agent_id: str
    is_active: bool
    is_valid: bool
    verified_at: datetime
    message: str


# ── Issue Result ───────────────────────────────────────────────────────────────


class AgentIdentityIssueResult(BaseModel):
    """
    Result of issuing an AgentIdentity from a CSR.
    Returned to the agent for secure storage.
    """
    identity: AgentIdentity
    certificate: AgentCertificate
    ca_fingerprint: str
    private_key_pem: str = Field(
        description="PKCS8 PEM private key. MUST be stored securely by the agent — NEVER sent to server.",
    )
