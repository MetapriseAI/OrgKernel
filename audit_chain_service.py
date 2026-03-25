"""
Pydantic schemas for AuditChain.

AuditChain is append-only and hash-chained. Every write is synchronous.
Audit is not optional and cannot be made async.

For database-backed persistence, use ``orgkernel.database`` or implement a custom
repository that stores AuditChainModel rows. This schema provides the in-memory
representation for testing and SDK use.
"""
from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timezone
from enum import Enum
from uuid import uuid4

from pydantic import BaseModel, Field, field_validator


_CHAIN_ID_RE    = re.compile(r"^ac_[a-z0-9]+$")
_ENTRY_ID_RE    = re.compile(r"^aue_[a-z0-9]+$")
_AGENT_ID_RE    = re.compile(r"^aid_[a-z0-9]+$")
_MISSION_ID_RE  = re.compile(r"^msn_[a-z0-9]+$")
_HASH_RE        = re.compile(r"^[a-f0-9]{64}$")

_GENESIS_HASH = "0" * 64


def _new_chain_id() -> str:
    return "ac_" + uuid4().hex[:12]


def _new_entry_id() -> str:
    return "aue_" + uuid4().hex[:12]


def _now_utc() -> datetime:
    return datetime.now(timezone.utc)


# ── Enums ─────────────────────────────────────────────────────────────────────


class AuditLayer(str, Enum):
    """Layer of the AuditChain entry."""
    IDENTITY   = "IDENTITY"    # AgentIdentity and ExecutionToken events
    EXECUTION  = "EXECUTION"   # Tool calls, state transitions, StateData writes
    COMPLIANCE = "COMPLIANCE"  # PolicyEngine decisions, scope violations
    GOVERNANCE = "GOVERNANCE"  # Authority changes, approvals, re-validation


# ── AuditEntry ─────────────────────────────────────────────────────────────────


class AuditEntry(BaseModel):
    """
    Single immutable record in the AuditChain.
    entry_hash = SHA-256(canonical JSON of this entry, excluding entry_hash itself).
    prev_hash links to the previous entry, forming the tamper-evident chain.
    """
    model_config = {"frozen": True}

    entry_id: str = Field(default_factory=_new_entry_id)
    chain_id: str
    sequence: int = Field(ge=0)
    layer: AuditLayer
    event: str
    agent_id: str
    mission_id: str
    token_id: str | None = None
    timestamp: datetime = Field(default_factory=_now_utc)
    data: dict = Field(default_factory=dict)
    prev_hash: str
    entry_hash: str = ""

    @field_validator("prev_hash", "entry_hash")
    @classmethod
    def _validate_hash(cls, v: str) -> str:
        if v and not _HASH_RE.match(v):
            raise ValueError(f"Hash '{v[:16]}...' must be 64 lowercase hex chars.")
        return v

    @field_validator("chain_id")
    @classmethod
    def _validate_chain_id(cls, v: str) -> str:
        if not _CHAIN_ID_RE.match(v):
            raise ValueError(f"chain_id '{v}' must match ^ac_[a-z0-9]+$")
        return v

    @field_validator("agent_id")
    @classmethod
    def _validate_agent_id(cls, v: str) -> str:
        if not _AGENT_ID_RE.match(v):
            raise ValueError(f"agent_id '{v}' must match ^aid_[a-z0-9]+$")
        return v

    @field_validator("mission_id")
    @classmethod
    def _validate_mission_id(cls, v: str) -> str:
        if not _MISSION_ID_RE.match(v):
            raise ValueError(f"mission_id '{v}' must match ^msn_[a-z0-9]+$")
        return v

    @staticmethod
    def _canonical(entry: AuditEntry) -> bytes:
        """Deterministic JSON serialization for hashing. Excludes entry_hash."""
        d = entry.model_dump(mode="json", exclude={"entry_hash"})
        return json.dumps(d, sort_keys=True, separators=(",", ":")).encode()

    @classmethod
    def create(
        cls,
        *,
        chain_id: str,
        sequence: int,
        layer: AuditLayer,
        event: str,
        agent_id: str,
        mission_id: str,
        prev_hash: str,
        data: dict | None = None,
        token_id: str | None = None,
    ) -> AuditEntry:
        """
        Factory method. Computes entry_hash after construction.
        Always use this instead of direct instantiation.
        """
        entry = cls(
            chain_id=chain_id,
            sequence=sequence,
            layer=layer,
            event=event,
            agent_id=agent_id,
            mission_id=mission_id,
            prev_hash=prev_hash,
            data=data or {},
            token_id=token_id,
            entry_hash="",
        )
        computed = hashlib.sha256(cls._canonical(entry)).hexdigest()
        return entry.model_copy(update={"entry_hash": computed})

    def verify(self) -> bool:
        """Return True if entry_hash is consistent with entry content."""
        recomputed = hashlib.sha256(self._canonical(self)).hexdigest()
        return recomputed == self.entry_hash


# ── AuditChain ─────────────────────────────────────────────────────────────────


class AuditChain(BaseModel):
    """
    Append-only hash-chained audit log for one Mission.
    One chain per Mission. Initialized at CREATED state, closed at CLOSED state.

    Usage::

        chain = AuditChain.initialize(mission_id="msn_...", agent_id="aid_...")

        chain = chain.append(
            layer=AuditLayer.EXECUTION,
            event="EXECUTION_tool_call",
            data={"tool": "accounting_api", "result": "success"},
            token_id="tok_...",
        )

        ok = chain.verify_integrity()

    For database-backed persistence, use ``orgkernel.database`` or implement a custom
    repository that stores AuditChainModel rows.
    """
    chain_id: str = Field(default_factory=_new_chain_id)
    mission_id: str
    agent_id: str
    initialized_at: datetime = Field(default_factory=_now_utc)
    closed_at: datetime | None = None
    entries: list[AuditEntry] = Field(default_factory=list)
    head_hash: str | None = None

    @classmethod
    def initialize(cls, *, mission_id: str, agent_id: str) -> AuditChain:
        """
        Create a new AuditChain and write the genesis IDENTITY entry.
        Call at Mission CREATED state.
        """
        chain = cls(mission_id=mission_id, agent_id=agent_id)
        genesis = AuditEntry.create(
            chain_id=chain.chain_id,
            sequence=0,
            layer=AuditLayer.IDENTITY,
            event="IDENTITY_chain_initialized",
            agent_id=agent_id,
            mission_id=mission_id,
            prev_hash=_GENESIS_HASH,
            data={"initialized_at": chain.initialized_at.isoformat()},
        )
        return chain.model_copy(update={
            "entries": [genesis],
            "head_hash": genesis.entry_hash,
        })

    def append(
        self,
        *,
        layer: AuditLayer,
        event: str,
        data: dict | None = None,
        token_id: str | None = None,
    ) -> AuditChain:
        """
        Append a new entry to the chain. Returns a new AuditChain.
        Raises ValueError if the chain is already closed.
        """
        if self.closed_at is not None:
            raise ValueError("Cannot append to a closed AuditChain.")
        entry = AuditEntry.create(
            chain_id=self.chain_id,
            sequence=len(self.entries),
            layer=layer,
            event=event,
            agent_id=self.agent_id,
            mission_id=self.mission_id,
            prev_hash=self.head_hash or _GENESIS_HASH,
            data=data or {},
            token_id=token_id,
        )
        return self.model_copy(update={
            "entries": [*self.entries, entry],
            "head_hash": entry.entry_hash,
        })

    def close(self) -> AuditChain:
        """
        Close the chain. No further entries may be appended.
        Call at Mission CLOSED state.
        """
        if self.closed_at is not None:
            raise ValueError("AuditChain is already closed.")
        closed = self.append(
            layer=AuditLayer.EXECUTION,
            event="EXECUTION_chain_closed",
            data={"entry_count": len(self.entries) + 1},
        )
        return closed.model_copy(update={"closed_at": _now_utc()})

    def verify_integrity(self) -> bool:
        """
        Verify the entire chain from genesis to head.
        Returns True if no tampering detected.
        Checks:
          1. Each entry's entry_hash is consistent with its content.
          2. Each entry's prev_hash matches the previous entry's entry_hash.
          3. Sequence numbers are contiguous.
        """
        if not self.entries:
            return True
        prev_hash = _GENESIS_HASH
        for i, entry in enumerate(self.entries):
            if entry.sequence != i:
                return False
            if entry.prev_hash != prev_hash:
                return False
            if not entry.verify():
                return False
            prev_hash = entry.entry_hash
        return self.head_hash == self.entries[-1].entry_hash

    def entries_by_layer(self, layer: AuditLayer) -> list[AuditEntry]:
        """Return all entries for a given layer."""
        return [e for e in self.entries if e.layer == layer]

    def entries_by_event(self, event_prefix: str) -> list[AuditEntry]:
        """Return all entries whose event starts with event_prefix."""
        return [e for e in self.entries if e.event.startswith(event_prefix)]
