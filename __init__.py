"""
SQLAlchemy ORM models for OrgKernel persistence.

Tables:
    sys_orgkernel_agent_identity   — AgentIdentity records
    sys_orgkernel_execution_token  — ExecutionToken records
    sys_orgkernel_audit_chain      — AuditChain metadata (one per mission)
    sys_orgkernel_audit_entry      — Individual AuditEntry records
"""
from __future__ import annotations

from datetime import datetime

from sqlalchemy import (
    BigInteger,
    Boolean,
    DateTime,
    Index,
    Integer,
    String,
    Text,
)
from sqlalchemy.orm import Mapped, mapped_column, DeclarativeBase


class BaseModel(DeclarativeBase):
    """Base for all OrgKernel SQLAlchemy models."""
    pass


class AgentIdentityModel(BaseModel):
    """
    Stores AgentIdentity records.
    One identity per agent_id. Not linked to sys_user (org-scoped, not user-scoped).
    """

    __tablename__: str = "sys_orgkernel_agent_identity"
    __table_args__ = (
        Index("idx_identity_org_id", "org_id"),
        Index("idx_identity_agent_name", "agent_name"),
        Index("idx_identity_status", "identity_status"),
        {"comment": "OrgKernel AgentIdentity — cryptographic org credentials for AI agents"},
    )

    agent_id: Mapped[str] = mapped_column(
        String(32), primary_key=True, comment="aid_ prefixed global ID"
    )
    agent_name: Mapped[str] = mapped_column(
        String(64), nullable=False, index=True,
        comment="Human-readable agent name, unique per org",
    )
    org_id: Mapped[str] = mapped_column(
        String(64), nullable=False, index=True,
        comment="Org tenant identifier",
    )
    issued_by: Mapped[str] = mapped_column(
        String(64), nullable=False,
        comment="Org unit that authorized issuance",
    )
    public_key: Mapped[str] = mapped_column(
        Text, nullable=False,
        comment="Ed25519 public key, Base64url encoded",
    )
    org_ca_fingerprint: Mapped[str] = mapped_column(
        String(64), nullable=False,
        comment="SHA-256 fingerprint of signing Org CA",
    )
    issued_at: Mapped[datetime] = mapped_column(
        DateTime, nullable=False,
        comment="UTC timestamp of issuance",
    )
    valid_until: Mapped[datetime | None] = mapped_column(
        DateTime, nullable=True,
        comment="UTC expiry, null = no expiry",
    )
    identity_status: Mapped[str] = mapped_column(
        String(16), nullable=False, default="ACTIVE", index=True,
        comment="ACTIVE | SUSPENDED | REVOKED | EXPIRED",
    )
    revoked_at: Mapped[datetime | None] = mapped_column(
        DateTime, nullable=True,
        comment="UTC revocation timestamp",
    )
    revoked_by: Mapped[str | None] = mapped_column(
        String(64), nullable=True,
        comment="Identity that revoked this credential",
    )
    revocation_reason: Mapped[str | None] = mapped_column(
        Text, nullable=True,
        comment="Human-readable revocation reason",
    )
    metadata_json: Mapped[str | None] = mapped_column(
        Text, nullable=True,
        comment="AgentIdentity.metadata serialized as JSON",
    )


class ExecutionTokenModel(BaseModel):
    """
    Stores ExecutionToken records.
    One token per token_id. Tokens are immutable once issued.
    """

    __tablename__: str = "sys_orgkernel_execution_token"
    __table_args__ = (
        Index("idx_token_agent_id", "agent_id"),
        Index("idx_token_mission_id", "mission_id"),
        Index("idx_token_expires", "expires_at"),
        {"comment": "OrgKernel ExecutionToken — scoped, time-bounded execution permission"},
    )

    token_id: Mapped[str] = mapped_column(
        String(32), primary_key=True, comment="tok_ prefixed global ID"
    )
    agent_id: Mapped[str] = mapped_column(
        String(32), nullable=False,
        comment="FK -> sys_orgkernel_agent_identity.agent_id",
    )
    mission_id: Mapped[str] = mapped_column(
        String(32), nullable=False, index=True,
        comment="Mission this token is scoped to",
    )
    execution_scope_json: Mapped[str] = mapped_column(
        Text, nullable=False,
        comment="execution_scope list serialized as JSON",
    )
    immutable_params_json: Mapped[str | None] = mapped_column(
        Text, nullable=True,
        comment="immutable_params dict serialized as JSON",
    )
    bounded_params_json: Mapped[str | None] = mapped_column(
        Text, nullable=True,
        comment="bounded_params list serialized as JSON",
    )
    issued_at: Mapped[datetime] = mapped_column(
        DateTime, nullable=False,
        comment="UTC issuance timestamp",
    )
    expires_at: Mapped[datetime] = mapped_column(
        DateTime, nullable=False,
        comment="UTC expiry timestamp",
    )
    boundary_snapshot_id: Mapped[str | None] = mapped_column(
        String(32), nullable=True,
        comment="FK -> MissionBoundary snapshot ID",
    )
    token_signature: Mapped[str | None] = mapped_column(
        Text, nullable=True,
        comment="Ed25519 signature by Org CA over canonical token payload",
    )
    used: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False,
        comment="True if consumed",
    )
    invalidated_at: Mapped[datetime | None] = mapped_column(
        DateTime, nullable=True,
        comment="UTC invalidation timestamp",
    )
    invalidation_reason: Mapped[str | None] = mapped_column(
        Text, nullable=True,
        comment="Reason for early invalidation",
    )


class AuditChainModel(BaseModel):
    """
    Stores AuditChain metadata. One chain per Mission.
    Entries are stored in AuditEntryModel.
    """

    __tablename__: str = "sys_orgkernel_audit_chain"
    __table_args__ = (
        Index("idx_chain_mission_id", "mission_id", unique=True),
        {"comment": "OrgKernel AuditChain — append-only hash-chained audit log header"},
    )

    chain_id: Mapped[str] = mapped_column(
        String(32), primary_key=True, comment="ac_ prefixed global ID"
    )
    mission_id: Mapped[str] = mapped_column(
        String(32), nullable=False, unique=True, index=True,
        comment="FK -> Mission (one chain per mission)",
    )
    agent_id: Mapped[str] = mapped_column(
        String(32), nullable=False,
        comment="FK -> sys_orgkernel_agent_identity.agent_id",
    )
    initialized_at: Mapped[datetime] = mapped_column(
        DateTime, nullable=False,
        comment="UTC chain initialization timestamp",
    )
    closed_at: Mapped[datetime | None] = mapped_column(
        DateTime, nullable=True,
        comment="UTC chain closure timestamp",
    )
    head_hash: Mapped[str | None] = mapped_column(
        String(64), nullable=True,
        comment="SHA-256 hash of the most recent entry",
    )


class AuditEntryModel(BaseModel):
    """
    Stores individual AuditEntry records. Belongs to one AuditChain.
    """

    __tablename__: str = "sys_orgkernel_audit_entry"
    __table_args__ = (
        Index("idx_entry_chain_id", "chain_id"),
        Index("idx_entry_chain_seq", "chain_id", "sequence"),
        Index("idx_entry_mission_id", "mission_id"),
        Index("idx_entry_agent_id", "agent_id"),
        {"comment": "OrgKernel AuditEntry — single immutable record in AuditChain"},
    )

    entry_id: Mapped[str] = mapped_column(
        String(32), primary_key=True, comment="aue_ prefixed global ID"
    )
    chain_id: Mapped[str] = mapped_column(
        String(32), nullable=False,
        comment="FK -> sys_orgkernel_audit_chain.chain_id",
    )
    sequence: Mapped[int] = mapped_column(
        Integer, nullable=False,
        comment="Monotonically increasing position in chain",
    )
    layer: Mapped[str] = mapped_column(
        String(16), nullable=False,
        comment="IDENTITY | EXECUTION | COMPLIANCE | GOVERNANCE",
    )
    event: Mapped[str] = mapped_column(
        String(128), nullable=False,
        comment="Event identifier, format: LAYER_EventName",
    )
    agent_id: Mapped[str] = mapped_column(
        String(32), nullable=False, index=True,
        comment="Agent that produced this entry",
    )
    mission_id: Mapped[str] = mapped_column(
        String(32), nullable=False, index=True,
        comment="Mission this entry belongs to",
    )
    token_id: Mapped[str | None] = mapped_column(
        String(32), nullable=True,
        comment="ExecutionToken active at this entry",
    )
    timestamp: Mapped[datetime] = mapped_column(
        DateTime, nullable=False,
        comment="UTC timestamp with microsecond precision",
    )
    data_json: Mapped[str | None] = mapped_column(
        Text, nullable=True,
        comment="Event data payload serialized as JSON",
    )
    prev_hash: Mapped[str] = mapped_column(
        String(64), nullable=False,
        comment="SHA-256 hash of previous entry",
    )
    entry_hash: Mapped[str] = mapped_column(
        String(64), nullable=False, unique=True,
        comment="SHA-256 hash of this entry's canonical JSON",
    )
