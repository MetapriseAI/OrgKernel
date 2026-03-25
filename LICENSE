"""
AuditChain service layer: append-only hash-chained audit log persistence and querying.

The AuditChain is append-only and hash-chained. Every write is synchronous —
there is no async option for audit logging.

Architecture:
    - AuditChainModel: one row per logical audit session (per mission)
    - AuditEntryModel: detail rows linked by chain_id
    - Both tables maintain independent SHA-256 hash chains
"""
from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from orgkernel.models import AuditChainModel, AuditEntryModel
from orgkernel.schemas.audit_chain import (
    AuditChain,
    AuditEntry,
    AuditLayer,
)


_GENESIS_HASH = "0" * 64


def _serialize_json(v: dict[str, Any] | list | None) -> str | None:
    if v is None:
        return None
    return json.dumps(v, separators=(",", ":"), ensure_ascii=False)


def _deserialize_json(v: str | None) -> dict[str, Any] | list | None:
    if v is None:
        return None
    return json.loads(v)


def _model_entry_to_pydantic(model: AuditEntryModel) -> AuditEntry:
    """Convert SQLAlchemy AuditEntryModel to Pydantic AuditEntry."""
    return AuditEntry(
        entry_id=model.entry_id,
        chain_id=model.chain_id,
        sequence=model.sequence,
        layer=AuditLayer(model.layer),
        event=model.event,
        agent_id=model.agent_id,
        mission_id=model.mission_id,
        token_id=model.token_id,
        timestamp=model.timestamp,
        data=_deserialize_json(model.data_json) or {},
        prev_hash=model.prev_hash,
        entry_hash=model.entry_hash,
    )


def _model_chain_to_pydantic(
    chain_model: AuditChainModel,
    entries: list[AuditEntryModel],
) -> AuditChain:
    """Convert SQLAlchemy models to Pydantic AuditChain with entries."""
    chain = AuditChain(
        chain_id=chain_model.chain_id,
        mission_id=chain_model.mission_id,
        agent_id=chain_model.agent_id,
        initialized_at=chain_model.initialized_at,
        closed_at=chain_model.closed_at,
        entries=[],
        head_hash=chain_model.head_hash,
    )
    # Rebuild entries
    for em in sorted(entries, key=lambda x: x.sequence):
        chain.entries.append(_model_entry_to_pydantic(em))
    return chain


def _compute_entry_hash(entry: AuditEntry) -> str:
    """Compute SHA-256 hash for an AuditEntry (excluding entry_hash itself)."""
    d = entry.model_dump(mode="json", exclude={"entry_hash"})
    canonical = json.dumps(d, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _now_utc() -> datetime:
    return datetime.now(timezone.utc)


class AuditChainService:
    """
    Service for AuditChain persistence and querying.

    All public methods are async and require an ``AsyncSession`` as the
    first positional argument so the caller controls transaction boundaries.

    Usage::

        svc = AuditChainService()
        chain_id = await svc.initialize(db, mission_id="msn_...", agent_id="aid_...")
        await svc.append(db, chain_id=chain_id, layer=AuditLayer.EXECUTION, event="EXECUTION_tool_call", ...)
        chain = await svc.get_by_mission(db, "msn_...")
        valid = await svc.verify_integrity(db, chain_id)
    """

    async def initialize(
        self,
        db: AsyncSession,
        mission_id: str,
        agent_id: str,
    ) -> str:
        """
        Create a new AuditChain and write the genesis IDENTITY entry.

        Args:
            db: AsyncSession.
            mission_id: Mission this chain belongs to.
            agent_id: Agent that owns this chain.

        Returns:
            The chain_id of the newly created chain.
        """
        # Create chain header
        chain_id = "ac_" + _new_id()
        initialized_at = _now_utc()

        chain_model = AuditChainModel(
            chain_id=chain_id,
            mission_id=mission_id,
            agent_id=agent_id,
            initialized_at=initialized_at,
        )
        db.add(chain_model)

        # Compute genesis entry
        genesis_entry = AuditEntry(
            chain_id=chain_id,
            sequence=0,
            layer=AuditLayer.IDENTITY,
            event="IDENTITY_chain_initialized",
            agent_id=agent_id,
            mission_id=mission_id,
            prev_hash=_GENESIS_HASH,
            data={"initialized_at": initialized_at.isoformat()},
            entry_hash="",  # placeholder
        )
        genesis_hash = _compute_entry_hash(genesis_entry)
        genesis_entry.entry_hash = genesis_hash

        # Update chain head_hash
        chain_model.head_hash = genesis_hash

        entry_model = AuditEntryModel(
            entry_id=genesis_entry.entry_id,
            chain_id=genesis_entry.chain_id,
            sequence=genesis_entry.sequence,
            layer=genesis_entry.layer.value,
            event=genesis_entry.event,
            agent_id=genesis_entry.agent_id,
            mission_id=genesis_entry.mission_id,
            token_id=genesis_entry.token_id,
            timestamp=genesis_entry.timestamp,
            data_json=_serialize_json(genesis_entry.data),
            prev_hash=genesis_entry.prev_hash,
            entry_hash=genesis_entry.entry_hash,
        )
        db.add(entry_model)
        await db.flush()

        return chain_id

    async def append(
        self,
        db: AsyncSession,
        chain_id: str,
        layer: AuditLayer,
        event: str,
        agent_id: str,
        mission_id: str,
        data: dict[str, Any] | None = None,
        token_id: str | None = None,
    ) -> AuditEntry:
        """
        Append a new entry to an existing AuditChain.

        Args:
            db: AsyncSession.
            chain_id: Chain to append to.
            layer: Audit layer (IDENTITY, EXECUTION, COMPLIANCE, GOVERNANCE).
            event: Event identifier, format: LAYER_EventName.
            agent_id: Agent producing this entry.
            mission_id: Mission this entry belongs to.
            data: Optional structured data payload.
            token_id: Optional ExecutionToken active at this entry.

        Returns:
            The created AuditEntry.

        Raises:
            ValueError: If chain is closed or not found.
        """
        # Fetch chain
        result = await db.execute(
            select(AuditChainModel).where(AuditChainModel.chain_id == chain_id)
        )
        chain_model = result.scalars().first()
        if chain_model is None:
            raise ValueError(f"AuditChain not found: {chain_id}")
        if chain_model.closed_at is not None:
            raise ValueError("Cannot append to a closed AuditChain.")

        # Compute next sequence
        seq_result = await db.execute(
            select(func.count(AuditEntryModel.entry_id))
            .where(AuditEntryModel.chain_id == chain_id)
        )
        sequence: int = seq_result.scalar() or 0

        # Create entry
        prev_hash = chain_model.head_hash or _GENESIS_HASH
        entry = AuditEntry(
            chain_id=chain_id,
            sequence=sequence,
            layer=layer,
            event=event,
            agent_id=agent_id,
            mission_id=mission_id,
            token_id=token_id,
            data=data or {},
            prev_hash=prev_hash,
            entry_hash="",
        )
        entry_hash = _compute_entry_hash(entry)
        entry.entry_hash = entry_hash

        # Persist entry
        entry_model = AuditEntryModel(
            entry_id=entry.entry_id,
            chain_id=entry.chain_id,
            sequence=entry.sequence,
            layer=entry.layer.value,
            event=entry.event,
            agent_id=entry.agent_id,
            mission_id=entry.mission_id,
            token_id=entry.token_id,
            timestamp=entry.timestamp,
            data_json=_serialize_json(entry.data),
            prev_hash=entry.prev_hash,
            entry_hash=entry.entry_hash,
        )
        db.add(entry_model)

        # Update chain head_hash
        chain_model.head_hash = entry_hash

        await db.flush()
        return entry

    async def close(self, db: AsyncSession, chain_id: str) -> AuditChain:
        """
        Close an AuditChain and write the terminal entry.

        Args:
            db: AsyncSession.
            chain_id: Chain to close.

        Returns:
            The closed AuditChain with all entries.

        Raises:
            ValueError: If chain is already closed or not found.
        """
        result = await db.execute(
            select(AuditChainModel).where(AuditChainModel.chain_id == chain_id)
        )
        chain_model = result.scalars().first()
        if chain_model is None:
            raise ValueError(f"AuditChain not found: {chain_id}")

        if chain_model.closed_at is not None:
            raise ValueError("AuditChain is already closed.")

        # Append terminal entry
        await self.append(
            db=db,
            chain_id=chain_id,
            layer=AuditLayer.EXECUTION,
            event="EXECUTION_chain_closed",
            agent_id=chain_model.agent_id,
            mission_id=chain_model.mission_id,
            data={"chain_id": chain_id},
        )

        # Mark chain as closed
        chain_model.closed_at = _now_utc()
        await db.flush()

        # Return full chain
        return await self.get_by_chain_id(db, chain_id)

    async def get_by_chain_id(self, db: AsyncSession, chain_id: str) -> AuditChain | None:
        """Get a full AuditChain by chain_id."""
        result = await db.execute(
            select(AuditChainModel).where(AuditChainModel.chain_id == chain_id)
        )
        chain_model = result.scalars().first()
        if chain_model is None:
            return None

        entries_result = await db.execute(
            select(AuditEntryModel).where(AuditEntryModel.chain_id == chain_id)
        )
        entries = list(entries_result.scalars().all())

        return _model_chain_to_pydantic(chain_model, entries)

    async def get_by_mission(self, db: AsyncSession, mission_id: str) -> AuditChain | None:
        """Get an AuditChain by mission_id (one chain per mission)."""
        result = await db.execute(
            select(AuditChainModel).where(AuditChainModel.mission_id == mission_id)
        )
        chain_model = result.scalars().first()
        if chain_model is None:
            return None

        entries_result = await db.execute(
            select(AuditEntryModel).where(AuditEntryModel.chain_id == chain_model.chain_id)
        )
        entries = list(entries_result.scalars().all())

        return _model_chain_to_pydantic(chain_model, entries)

    async def verify_integrity(self, db: AsyncSession, chain_id: str) -> bool:
        """
        Verify the integrity of an AuditChain from the database.

        Checks:
            1. Each entry's entry_hash is consistent with its content.
            2. Each entry's prev_hash matches the previous entry's entry_hash.
            3. Sequence numbers are contiguous.
            4. head_hash matches the last entry's entry_hash.

        Args:
            db: AsyncSession.
            chain_id: Chain to verify.

        Returns:
            True if integrity check passes, False otherwise.
        """
        result = await db.execute(
            select(AuditChainModel).where(AuditChainModel.chain_id == chain_id)
        )
        chain_model = result.scalars().first()
        if chain_model is None:
            return False

        entries_result = await db.execute(
            select(AuditEntryModel)
            .where(AuditEntryModel.chain_id == chain_id)
            .order_by(AuditEntryModel.sequence)
        )
        entries = list(entries_result.scalars().all())

        if not entries:
            return True

        prev_hash = _GENESIS_HASH
        for i, entry_model in enumerate(entries):
            if entry_model.sequence != i:
                return False
            if entry_model.prev_hash != prev_hash:
                return False
            # Recompute entry hash
            pydantic_entry = _model_entry_to_pydantic(entry_model)
            recomputed = _compute_entry_hash(pydantic_entry)
            if recomputed != entry_model.entry_hash:
                return False
            prev_hash = entry_model.entry_hash

        return chain_model.head_hash == entries[-1].entry_hash

    async def list_by_agent(
        self,
        db: AsyncSession,
        agent_id: str,
        page_no: int = 1,
        page_size: int = 20,
    ) -> dict:
        """
        List AuditChains for an agent with SQL-level pagination.

        Args:
            db: AsyncSession.
            agent_id: Agent identifier.
            page_no: 1-based page number.
            page_size: Items per page.

        Returns:
            Dict with page_no, page_size, total, has_next, items (chain metadata only).
        """
        conditions = [AuditChainModel.agent_id == agent_id]

        count_sql = select(func.count(AuditChainModel.chain_id)).where(*conditions)
        total_result = await db.execute(count_sql)
        total = total_result.scalar() or 0

        offset = (page_no - 1) * page_size
        query = (
            select(AuditChainModel)
            .where(*conditions)
            .order_by(AuditChainModel.initialized_at.desc())
            .offset(offset)
            .limit(page_size)
        )
        result = await db.execute(query)
        chains = result.scalars().all()

        return {
            "page_no": page_no,
            "page_size": page_size,
            "total": total,
            "has_next": offset + page_size < total,
            "items": [
                {
                    "chain_id": c.chain_id,
                    "mission_id": c.mission_id,
                    "agent_id": c.agent_id,
                    "initialized_at": c.initialized_at,
                    "closed_at": c.closed_at,
                    "head_hash": c.head_hash,
                }
                for c in chains
            ],
        }


def _new_id() -> str:
    from uuid import uuid4
    return uuid4().hex[:12]
