"""
ExecutionToken service layer: minting with cryptographic signature, validation, invalidation.

Cryptographic attestation:
    - Every ExecutionToken is signed by the Org CA (Ed25519) during minting
    - Token signature covers: token_id, agent_id, mission_id, scope, params, expiry
    - Tool Gateway verifies signature on every tool call
    - This prevents Token Grafting: a token for Agent A cannot be used by Agent B
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

from sqlalchemy import asc, desc, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from orgkernel.crypto_utils import (
    get_org_ca_public_key_bytes,
    sign_payload,
    verify_signature,
)
from orgkernel.models import ExecutionTokenModel
from orgkernel.schemas.execution_token import (
    BoundedParam,
    ExecutionToken,
    ExecutionTokenCreate,
    ExecutionTokenOut,
    ScopeCheckRequest,
    ScopeCheckResponse,
)


def _serialize_json(v: dict[str, Any] | list | None) -> str | None:
    if v is None:
        return None
    return json.dumps(v, separators=(",", ":"), ensure_ascii=False)


def _deserialize_json(v: str | None) -> dict[str, Any] | list | None:
    if v is None:
        return None
    return json.loads(v)


def _bounded_params_from_json(v: str | None) -> list[BoundedParam]:
    if not v:
        return []
    raw = json.loads(v)
    return [BoundedParam(**item) for item in raw]


def _model_to_pydantic(model: ExecutionTokenModel) -> ExecutionToken:
    """Convert SQLAlchemy model to Pydantic ExecutionToken."""
    scope_raw = _deserialize_json(model.execution_scope_json) or []
    immutable_raw = _deserialize_json(model.immutable_params_json) or {}
    bounded_raw = _bounded_params_from_json(model.bounded_params_json)

    return ExecutionToken(
        token_id=model.token_id,
        agent_id=model.agent_id,
        mission_id=model.mission_id,
        execution_scope=scope_raw,
        immutable_params=immutable_raw,
        bounded_params=bounded_raw,
        issued_at=model.issued_at,
        expires_at=model.expires_at,
        boundary_snapshot_id=model.boundary_snapshot_id,
        token_signature=model.token_signature,
        used=model.used,
        invalidated_at=model.invalidated_at,
        invalidation_reason=model.invalidation_reason,
    )


def _model_to_out(model: ExecutionTokenModel) -> ExecutionTokenOut:
    """Convert SQLAlchemy model to ExecutionTokenOut response schema."""
    token = _model_to_pydantic(model)
    return ExecutionTokenOut(
        token_id=token.token_id,
        agent_id=token.agent_id,
        mission_id=token.mission_id,
        execution_scope=token.execution_scope,
        immutable_params=token.immutable_params,
        bounded_params=token.bounded_params,
        issued_at=token.issued_at,
        expires_at=token.expires_at,
        boundary_snapshot_id=token.boundary_snapshot_id,
        token_signature=token.token_signature,
        used=token.used,
        is_valid=token.is_valid,
        invalidated_at=token.invalidated_at,
        invalidation_reason=token.invalidation_reason,
    )


def _pydantic_to_model_data(token: ExecutionToken) -> dict[str, Any]:
    """Convert Pydantic ExecutionToken to dict suitable for model creation."""
    return {
        "token_id": token.token_id,
        "agent_id": token.agent_id,
        "mission_id": token.mission_id,
        "execution_scope_json": _serialize_json(token.execution_scope),
        "immutable_params_json": _serialize_json(token.immutable_params),
        "bounded_params_json": _serialize_json(
            [bp.model_dump() for bp in token.bounded_params]
        ),
        "issued_at": token.issued_at,
        "expires_at": token.expires_at,
        "boundary_snapshot_id": token.boundary_snapshot_id,
        "token_signature": token.token_signature,
        "used": token.used,
        "invalidated_at": token.invalidated_at,
        "invalidation_reason": token.invalidation_reason,
    }


class ExecutionTokenService:
    """
    Service for ExecutionToken lifecycle management.

    Usage::

        svc = ExecutionTokenService(db=db_session)
        token = await svc.mint(mint_request)
        result = await svc.check_scope(scope_request)
    """

    def __init__(self, db: AsyncSession) -> None:
        self._db = db

    async def mint(self, data: ExecutionTokenCreate) -> ExecutionTokenOut:
        """
        Mint (create) a new ExecutionToken.

        The token is scoped to a specific agent + mission and cryptographically
        signed by the Org CA. The signature prevents Token Grafting:
        a token minted for Agent A cannot be used by Agent B.

        Args:
            data: Token minting request with scope, bounds, and expiry.

        Returns:
            Signed ExecutionTokenOut with token_signature.
        """
        token_id = "tok_" + uuid4().hex[:12]
        issued_at = datetime.now(timezone.utc)

        # Build token payload
        token_payload = {
            "token_id": token_id,
            "agent_id": data.agent_id,
            "mission_id": data.mission_id,
            "execution_scope": sorted(data.execution_scope),
            "immutable_params": data.immutable_params,
            "bounded_params": [bp.model_dump() for bp in data.bounded_params],
            "issued_at": issued_at.isoformat(),
            "expires_at": data.expires_at.isoformat(),
            "boundary_snapshot_id": data.boundary_snapshot_id,
        }

        # Sign with Org CA
        from orgkernel.crypto_utils import _ensure_ca_keypair
        ca_private_key, _ = _ensure_ca_keypair()
        from cryptography.hazmat.primitives import serialization
        pem_bytes = ca_private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        canonical_payload = json.dumps(token_payload, separators=(",", ":"), sort_keys=True)
        ca_signature_b64url = sign_payload(pem_bytes.decode("utf-8"), canonical_payload)

        # Create token with signature
        token = ExecutionToken(
            token_id=token_id,
            agent_id=data.agent_id,
            mission_id=data.mission_id,
            execution_scope=data.execution_scope,
            immutable_params=data.immutable_params,
            bounded_params=data.bounded_params,
            issued_at=issued_at,
            expires_at=data.expires_at,
            boundary_snapshot_id=data.boundary_snapshot_id,
            token_signature=ca_signature_b64url,
            used=False,
        )

        # Persist
        model_data = _pydantic_to_model_data(token)
        model = ExecutionTokenModel(**model_data)
        self._db.add(model)
        await self._db.flush()
        await self._db.refresh(model)

        return _model_to_out(model)

    async def get_by_id(self, token_id: str) -> ExecutionToken | None:
        """Get an ExecutionToken by token_id."""
        result = await self._db.execute(
            select(ExecutionTokenModel).where(ExecutionTokenModel.token_id == token_id)
        )
        model = result.scalars().first()
        if model is None:
            return None
        return _model_to_pydantic(model)

    async def get_valid_token(self, token_id: str) -> ExecutionToken | None:
        """Get an ExecutionToken only if it is currently valid."""
        token = await self.get_by_id(token_id)
        if token is None:
            return None
        if not token.is_valid:
            return None
        return token

    async def get_active_token(self, mission_id: str) -> ExecutionToken | None:
        """
        Get the active ExecutionToken for a mission.
        Returns the most recently issued non-expired, non-used, non-invalidated token.
        """
        now = datetime.now(timezone.utc)
        result = await self._db.execute(
            select(ExecutionTokenModel)
            .where(
                ExecutionTokenModel.mission_id == mission_id,
                ExecutionTokenModel.expires_at > now,
                ExecutionTokenModel.used.is_(False),
                ExecutionTokenModel.invalidated_at.is_(None),
            )
            .order_by(ExecutionTokenModel.issued_at.desc())
            .limit(1)
        )
        model = result.scalars().first()
        if model is None:
            return None
        return _model_to_pydantic(model)

    async def get_active_token_by_agent(self, agent_id: str) -> ExecutionToken | None:
        """
        Get the most recently issued active ExecutionToken for an agent.

        Unlike ``get_active_token(mission_id)`` which requires a mission_id,
        this method finds the latest non-expired, non-used, non-invalidated
        token for a given agent — useful when an AgentTalk instance needs
        to enforce scope without a mission context.
        """
        now = datetime.now(timezone.utc)
        result = await self._db.execute(
            select(ExecutionTokenModel)
            .where(
                ExecutionTokenModel.agent_id == agent_id,
                ExecutionTokenModel.expires_at > now,
                ExecutionTokenModel.used.is_(False),
                ExecutionTokenModel.invalidated_at.is_(None),
            )
            .order_by(ExecutionTokenModel.issued_at.desc())
            .limit(1)
        )
        model = result.scalars().first()
        if model is None:
            return None
        return _model_to_pydantic(model)

    async def check_scope(
        self,
        data: ScopeCheckRequest,
    ) -> ScopeCheckResponse:
        """
        Validate a tool call against an ExecutionToken's scope.
        Returns the check result — does not raise on violation.
        """
        token = await self.get_valid_token(data.token_id)
        if token is None:
            return ScopeCheckResponse(
                token_id=data.token_id,
                tool_name=data.tool_name,
                passed=False,
                blocked=True,
                violations=["token_invalid_or_expired"],
            )

        result = token.check_scope(data.tool_name, data.params)
        return ScopeCheckResponse(
            token_id=data.token_id,
            tool_name=data.tool_name,
            passed=result.passed,
            blocked=result.blocked,
            violations=result.violations,
        )

    async def mark_used(self, token_id: str) -> ExecutionTokenOut:
        """Mark a token as consumed (used=True)."""
        result = await self._db.execute(
            select(ExecutionTokenModel).where(ExecutionTokenModel.token_id == token_id)
        )
        model = result.scalars().first()
        if model is None:
            raise ValueError(f"ExecutionToken not found: {token_id}")

        model.used = True
        await self._db.flush()
        await self._db.refresh(model)

        return _model_to_out(model)

    async def invalidate(self, token_id: str, reason: str) -> ExecutionTokenOut:
        """Invalidate a token early."""
        result = await self._db.execute(
            select(ExecutionTokenModel).where(ExecutionTokenModel.token_id == token_id)
        )
        model = result.scalars().first()
        if model is None:
            raise ValueError(f"ExecutionToken not found: {token_id}")

        model.invalidated_at = datetime.now(timezone.utc)
        model.invalidation_reason = reason

        await self._db.flush()
        await self._db.refresh(model)

        return _model_to_out(model)

    async def list_by_mission(self, mission_id: str) -> list[ExecutionToken]:
        """List all ExecutionTokens for a mission."""
        result = await self._db.execute(
            select(ExecutionTokenModel)
            .where(ExecutionTokenModel.mission_id == mission_id)
            .order_by(ExecutionTokenModel.issued_at.desc())
        )
        models = result.scalars().all()
        return [_model_to_pydantic(m) for m in models]

    async def list_by_agent(self, agent_id: str) -> list[ExecutionToken]:
        """List all ExecutionTokens for an agent."""
        result = await self._db.execute(
            select(ExecutionTokenModel)
            .where(ExecutionTokenModel.agent_id == agent_id)
            .order_by(ExecutionTokenModel.issued_at.desc())
        )
        models = result.scalars().all()
        return [_model_to_pydantic(m) for m in models]

    async def page_by_mission(
        self,
        mission_id: str,
        page_no: int,
        page_size: int,
        order_by: list[dict[str, str]] | None = None,
    ) -> dict:
        """
        List ExecutionTokens for a mission with SQL-level pagination.

        Args:
            mission_id: Mission identifier.
            page_no: 1-based page number.
            page_size: Items per page.
            order_by: Sorting, e.g. [{"issued_at": "desc"}].

        Returns:
            Dict with page_no, page_size, total, has_next, items.
        """
        conditions = [ExecutionTokenModel.mission_id == mission_id]

        count_sql = select(func.count(ExecutionTokenModel.token_id)).where(*conditions)
        total_result = await self._db.execute(count_sql)
        total = total_result.scalar() or 0

        if order_by:
            order_cols: list[Any] = []
            for item in order_by:
                for field, direction in item.items():
                    col = getattr(ExecutionTokenModel, field, None)
                    if col is not None:
                        order_cols.append(desc(col) if direction.lower() == "desc" else asc(col))
        else:
            order_cols = [desc(ExecutionTokenModel.issued_at)]

        offset = (page_no - 1) * page_size
        query = (
            select(ExecutionTokenModel)
            .where(*conditions)
            .order_by(*order_cols)
            .offset(offset)
            .limit(page_size)
        )
        result = await self._db.execute(query)
        models = result.scalars().all()

        return {
            "page_no": page_no,
            "page_size": page_size,
            "total": total,
            "has_next": offset + page_size < total,
            "items": [_model_to_out(m) for m in models],
        }

    async def page_by_agent(
        self,
        agent_id: str,
        page_no: int,
        page_size: int,
        order_by: list[dict[str, str]] | None = None,
    ) -> dict:
        """
        List ExecutionTokens for an agent with SQL-level pagination.

        Args:
            agent_id: Agent identifier.
            page_no: 1-based page number.
            page_size: Items per page.
            order_by: Sorting, e.g. [{"issued_at": "desc"}].

        Returns:
            Dict with page_no, page_size, total, has_next, items.
        """
        conditions = [ExecutionTokenModel.agent_id == agent_id]

        count_sql = select(func.count(ExecutionTokenModel.token_id)).where(*conditions)
        total_result = await self._db.execute(count_sql)
        total = total_result.scalar() or 0

        if order_by:
            order_cols: list[Any] = []
            for item in order_by:
                for field, direction in item.items():
                    col = getattr(ExecutionTokenModel, field, None)
                    if col is not None:
                        order_cols.append(desc(col) if direction.lower() == "desc" else asc(col))
        else:
            order_cols = [desc(ExecutionTokenModel.issued_at)]

        offset = (page_no - 1) * page_size
        query = (
            select(ExecutionTokenModel)
            .where(*conditions)
            .order_by(*order_cols)
            .offset(offset)
            .limit(page_size)
        )
        result = await self._db.execute(query)
        models = result.scalars().all()

        return {
            "page_no": page_no,
            "page_size": page_size,
            "total": total,
            "has_next": offset + page_size < total,
            "items": [_model_to_out(m) for m in models],
        }
