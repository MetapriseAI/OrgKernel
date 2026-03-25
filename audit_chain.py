"""
FastAPI integration for OrgKernel.

Provides REST API endpoints for AgentIdentity, ExecutionToken, and AuditChain.

Usage with FastAPI::

    from fastapi import FastAPI, Depends
    from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
    from orgkernel.pyapi.router import router
    from orgkernel.database import get_session_factory, init_db

    app = FastAPI(title="Agent Platform")

    engine = create_async_engine("postgresql+asyncpg://user:pass@localhost:5432/orgkernel")

    @app.on_event("startup")
    async def startup():
        await init_db(engine)

    async def get_db():
        factory = get_session_factory(engine)
        async with factory() as session:
            yield session

    app.include_router(router, prefix="/orgkernel", get_db=get_db)

Endpoint groups:
    - /identity     — AgentIdentity CRUD, CSR, challenge-response
    - /token       — ExecutionToken minting and scope checking
    - /audit       — AuditChain initialize, append, query, verify
"""
from __future__ import annotations

from datetime import datetime
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from orgkernel.schemas import (
    AgentCertificate,
    AgentIdentity,
    AgentIdentityCSR,
    AgentIdentityCreate,
    AgentIdentityIssueResult,
    AgentIdentityOut,
    AgentIdentityRevoke,
    AgentIdentityVerify,
    AgentIdentityVerifyResponse,
    AgentIdentityStatus,
    ChallengeRequest,
    ChallengeResponse,
    ChallengeVerificationResult,
    ExecutionToken,
    ExecutionTokenCreate,
    ExecutionTokenOut,
    ScopeCheckRequest,
    ScopeCheckResponse,
    AuditChain,
    AuditEntry,
    AuditLayer,
)
from orgkernel.services import (
    AgentIdentityService,
    ExecutionTokenService,
    AuditChainService,
)


# ── Dependency ─────────────────────────────────────────────────────────────────


async def get_db() -> AsyncSession:
    """Override this with your actual session dependency."""
    raise RuntimeError("get_db dependency must be overridden in FastAPI app.")


# ── Error response ─────────────────────────────────────────────────────────────


class ErrorResponse(BaseModel):
    """Standard error response."""
    detail: str
    code: int | None = None


# ── Router ─────────────────────────────────────────────────────────────────────


router = APIRouter(tags=["OrgKernel"])


# ════════════════════════════════════════════════════════════════════════════════
# AGENT IDENTITY ENDPOINTS
# ════════════════════════════════════════════════════════════════════════════════

_identity = APIRouter(prefix="/identity", tags=["AgentIdentity"])
_router_aggregate = router


@_identity.post(
    "/csr/submit",
    response_model=AgentIdentityCSR,
    summary="Submit CSR",
    description="Step 1 of PKI lifecycle: validate and accept a CSR.",
)
async def submit_csr(
    csr: AgentIdentityCSR,
    db: Annotated[AsyncSession, Depends(get_db)],
) -> AgentIdentityCSR:
    """Submit a Certificate Signing Request for agent identity issuance."""
    svc = AgentIdentityService(db)
    try:
        return await svc.submit_csr(csr)
    except ValueError as e:
        raise HTTPException(status_code=409, detail=str(e))


@_identity.post(
    "/issue",
    response_model=AgentIdentityIssueResult,
    summary="Issue Identity from CSR",
    description="Step 2-3: validate CSR, sign certificate with Org CA, persist identity.",
)
async def issue_from_csr(
    csr: AgentIdentityCSR,
    db: Annotated[AsyncSession, Depends(get_db)],
) -> AgentIdentityIssueResult:
    """
    Issue an AgentIdentity from a validated CSR.

    The agent receives:
        - identity: DB record (server-side only)
        - certificate: proof of identity (agent stores this)
        - ca_fingerprint: for verification
        - private_key_pem: agent's private key (agent stores this — NEVER sent again)
    """
    svc = AgentIdentityService(db)
    try:
        return await svc.issue_from_csr(csr)
    except ValueError as e:
        raise HTTPException(status_code=409, detail=str(e))


@_identity.post(
    "/",
    response_model=AgentIdentityOut,
    summary="Issue Identity (Legacy)",
    description="Legacy endpoint — generates keypair internally. Prefer /csr/submit + /issue.",
)
async def issue_identity(
    data: AgentIdentityCreate,
    db: Annotated[AsyncSession, Depends(get_db)],
) -> AgentIdentityOut:
    """Issue a new AgentIdentity (legacy method)."""
    svc = AgentIdentityService(db)
    return await svc.issue(data)


@_identity.get(
    "/{agent_id}",
    response_model=AgentIdentityOut,
    summary="Get AgentIdentity",
    description="Retrieve an AgentIdentity by agent_id.",
)
async def get_identity(
    agent_id: str,
    db: Annotated[AsyncSession, Depends(get_db)],
) -> AgentIdentityOut:
    """Get an AgentIdentity by agent_id."""
    svc = AgentIdentityService(db)
    identity = await svc.get_by_id(agent_id)
    if identity is None:
        raise HTTPException(status_code=404, detail=f"AgentIdentity not found: {agent_id}")
    return AgentIdentityOut(
        agent_id=identity.agent_id,
        agent_name=identity.agent_name,
        org_id=identity.org_id,
        issued_by=identity.issued_by,
        public_key=identity.public_key,
        org_ca_fingerprint=identity.org_ca_fingerprint,
        issued_at=identity.issued_at,
        valid_until=identity.valid_until,
        status=identity.status,
        is_active=identity.is_active,
        revoked_at=identity.revoked_at,
        revoked_by=identity.revoked_by,
        revocation_reason=identity.revocation_reason,
        metadata=identity.metadata,
    )


@_identity.get(
    "/{agent_id}/certificate",
    response_model=AgentCertificate,
    summary="Get AgentCertificate",
    description="Retrieve the signed certificate for an agent.",
)
async def get_certificate(
    agent_id: str,
    db: Annotated[AsyncSession, Depends(get_db)],
) -> AgentCertificate:
    """
    Get the AgentCertificate for an identity.

    Note: The certificate is issued at creation time. This endpoint reconstructs
    the certificate from the stored identity record and the Org CA signature.
    """
    svc = AgentIdentityService(db)
    identity = await svc.get_by_id(agent_id)
    if identity is None:
        raise HTTPException(status_code=404, detail=f"AgentIdentity not found: {agent_id}")

    # Reconstruct certificate from identity
    # In production, the certificate should be stored separately
    issued_at = identity.issued_at
    valid_until = identity.valid_until
    ca_fingerprint = identity.org_ca_fingerprint
    public_key = identity.public_key

    # Build certificate payload and sign
    cert_payload = {
        "certificate_id": identity.agent_id,
        "agent_id": identity.agent_id,
        "agent_name": identity.agent_name,
        "org_id": identity.org_id,
        "issued_by": identity.issued_by,
        "public_key": public_key,
        "ca_fingerprint": ca_fingerprint,
        "issued_at": issued_at.isoformat() if issued_at else None,
        "valid_until": valid_until.isoformat() if valid_until else None,
    }

    # Sign certificate payload using the public crypto_utils API
    from orgkernel.crypto_utils import sign_agent_certificate
    from orgkernel.crypto_utils import _ensure_ca_keypair
    from cryptography.hazmat.primitives import serialization

    ca_private_key, _ = _ensure_ca_keypair()
    pem_bytes = ca_private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    ca_signature = sign_agent_certificate(pem_bytes.decode("utf-8"), cert_payload)

    return AgentCertificate(
        certificate_id=identity.agent_id,
        agent_id=identity.agent_id,
        agent_name=identity.agent_name,
        org_id=identity.org_id,
        issued_by=identity.issued_by,
        public_key=public_key,
        ca_fingerprint=ca_fingerprint,
        ca_signature=ca_signature,
        issued_at=issued_at,
        valid_until=valid_until,
        status=identity.status,
    )


@_identity.post(
    "/verify",
    response_model=AgentIdentityVerifyResponse,
    summary="Verify Identity (Static)",
    description="Perform static verification: status + expiry. For cryptographic verification use /challenge endpoints.",
)
async def verify_identity(
    data: AgentIdentityVerify,
    db: Annotated[AsyncSession, Depends(get_db)],
) -> AgentIdentityVerifyResponse:
    """Static verification of an AgentIdentity (status + expiry)."""
    svc = AgentIdentityService(db)
    return await svc.verify(data)


@_identity.post(
    "/challenge/request",
    response_model=ChallengeRequest,
    summary="Request Challenge",
    description="Step 4 of PKI: verifier requests a cryptographic challenge for an agent.",
)
async def request_challenge(
    agent_id: str,
    issued_by: str,
    db: Annotated[AsyncSession, Depends(get_db)],
    nonce: str | None = None,
    ttl_seconds: int = Query(default=300, ge=60, le=3600),
) -> ChallengeRequest:
    """
    Generate and store a cryptographic challenge for an agent.

    The returned ChallengeRequest.nonce must be sent to the agent.
    The agent signs the nonce with its private key and calls /challenge/verify.
    """
    svc = AgentIdentityService(db)
    identity = await svc.get_by_id(agent_id)
    if identity is None:
        raise HTTPException(status_code=404, detail=f"AgentIdentity not found: {agent_id}")
    return await svc.request_challenge(agent_id, issued_by, nonce=nonce, ttl_seconds=ttl_seconds)


@_identity.post(
    "/challenge/verify",
    response_model=ChallengeVerificationResult,
    summary="Verify Challenge-Response",
    description="Step 5-6: verify agent's signed challenge to confirm key possession.",
)
async def verify_challenge(
    response: ChallengeResponse,
    db: Annotated[AsyncSession, Depends(get_db)],
) -> ChallengeVerificationResult:
    """
    Full challenge-response verification.

    Verifies:
        1. Challenge exists, not expired, and not already used
        2. Agent's signature over the nonce is valid
        3. Certificate is ACTIVE and not expired
    """
    svc = AgentIdentityService(db)
    return await svc.verify_challenge(response)


@_identity.post(
    "/{agent_id}/suspend",
    response_model=AgentIdentityOut,
    summary="Suspend Identity",
    description="Suspend an AgentIdentity (recoverable via /reactivate).",
)
async def suspend_identity(
    agent_id: str,
    db: Annotated[AsyncSession, Depends(get_db)],
) -> AgentIdentityOut:
    """Suspend an AgentIdentity (recoverable)."""
    svc = AgentIdentityService(db)
    try:
        return await svc.suspend(agent_id)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


@_identity.post(
    "/{agent_id}/reactivate",
    response_model=AgentIdentityOut,
    summary="Reactivate Identity",
    description="Reactivate a suspended AgentIdentity. REVOKED identities cannot be reactivated.",
)
async def reactivate_identity(
    agent_id: str,
    db: Annotated[AsyncSession, Depends(get_db)],
) -> AgentIdentityOut:
    """Reactivate a suspended AgentIdentity."""
    svc = AgentIdentityService(db)
    try:
        return await svc.reactivate(agent_id)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@_identity.post(
    "/{agent_id}/revoke",
    response_model=AgentIdentityOut,
    summary="Revoke Identity",
    description="Permanently revoke an AgentIdentity. This cannot be undone.",
)
async def revoke_identity(
    agent_id: str,
    data: AgentIdentityRevoke,
    db: Annotated[AsyncSession, Depends(get_db)],
) -> AgentIdentityOut:
    """Permanently revoke an AgentIdentity."""
    svc = AgentIdentityService(db)
    try:
        return await svc.revoke(agent_id, data)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@_identity.get(
    "/org/{org_id}",
    response_model=list[AgentIdentityOut],
    summary="List Identities by Org",
    description="List all AgentIdentities for an organization.",
)
async def list_identities_by_org(
    org_id: str,
    db: Annotated[AsyncSession, Depends(get_db)],
    status: AgentIdentityStatus | None = None,
) -> list[AgentIdentityOut]:
    """List all AgentIdentities for an organization."""
    svc = AgentIdentityService(db)
    identities = await svc.list_by_org(org_id, status=status.value if status else None)
    return [
        AgentIdentityOut(
            agent_id=i.agent_id,
            agent_name=i.agent_name,
            org_id=i.org_id,
            issued_by=i.issued_by,
            public_key=i.public_key,
            org_ca_fingerprint=i.org_ca_fingerprint,
            issued_at=i.issued_at,
            valid_until=i.valid_until,
            status=i.status,
            is_active=i.is_active,
            revoked_at=i.revoked_at,
            revoked_by=i.revoked_by,
            revocation_reason=i.revocation_reason,
            metadata=i.metadata,
        )
        for i in identities
    ]


@_identity.get(
    "/org/{org_id}/page",
    response_model=dict,
    summary="Paginated Identities by Org",
    description="Paginated list of AgentIdentities for an organization.",
)
async def page_identities_by_org(
    org_id: str,
    db: Annotated[AsyncSession, Depends(get_db)],
    page_no: int = Query(default=1, ge=1),
    page_size: int = Query(default=20, ge=1, le=100),
    status: AgentIdentityStatus | None = None,
) -> dict:
    """Paginated list of AgentIdentities for an organization."""
    svc = AgentIdentityService(db)
    return await svc.page_by_org(
        org_id,
        page_no=page_no,
        page_size=page_size,
        status=status.value if status else None,
    )


router.include_router(_identity)


# ════════════════════════════════════════════════════════════════════════════════
# EXECUTION TOKEN ENDPOINTS
# ════════════════════════════════════════════════════════════════════════════════

_token = APIRouter(prefix="/token", tags=["ExecutionToken"])


@_token.post(
    "/mint",
    response_model=ExecutionTokenOut,
    summary="Mint ExecutionToken",
    description="Create and sign a new ExecutionToken scoped to an agent + mission.",
)
async def mint_token(
    data: ExecutionTokenCreate,
    db: Annotated[AsyncSession, Depends(get_db)],
) -> ExecutionTokenOut:
    """
    Mint a new ExecutionToken.

    The token is:
        - Scoped to agent_id + mission_id
        - Signed by the Org CA (prevents Token Grafting)
        - Time-bounded by expires_at
        - Scope-restricted by execution_scope
    """
    svc = ExecutionTokenService(db)
    return await svc.mint(data)


@_token.get(
    "/{token_id}",
    response_model=ExecutionTokenOut,
    summary="Get ExecutionToken",
    description="Retrieve an ExecutionToken by token_id.",
)
async def get_token(
    token_id: str,
    db: Annotated[AsyncSession, Depends(get_db)],
) -> ExecutionTokenOut:
    """Get an ExecutionToken by token_id."""
    svc = ExecutionTokenService(db)
    token = await svc.get_by_id(token_id)
    if token is None:
        raise HTTPException(status_code=404, detail=f"ExecutionToken not found: {token_id}")
    out = ExecutionTokenOut(
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
    return out


@_token.post(
    "/scope/check",
    response_model=ScopeCheckResponse,
    summary="Check Scope",
    description="Validate a proposed tool call against an ExecutionToken's scope.",
)
async def check_scope(
    data: ScopeCheckRequest,
    db: Annotated[AsyncSession, Depends(get_db)],
) -> ScopeCheckResponse:
    """
    Validate a tool call against an ExecutionToken's scope.

    Called by the Tool Gateway before every external tool call.
    Returns whether the call is allowed or blocked with violation details.
    """
    svc = ExecutionTokenService(db)
    return await svc.check_scope(data)


@_token.post(
    "/{token_id}/use",
    response_model=ExecutionTokenOut,
    summary="Mark Token Used",
    description="Mark an ExecutionToken as consumed.",
)
async def mark_token_used(
    token_id: str,
    db: Annotated[AsyncSession, Depends(get_db)],
) -> ExecutionTokenOut:
    """Mark a token as consumed (used=True)."""
    svc = ExecutionTokenService(db)
    try:
        return await svc.mark_used(token_id)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


@_token.post(
    "/{token_id}/invalidate",
    response_model=ExecutionTokenOut,
    summary="Invalidate Token",
    description="Invalidate an ExecutionToken early.",
)
async def invalidate_token(
    token_id: str,
    reason: str,
    db: Annotated[AsyncSession, Depends(get_db)],
) -> ExecutionTokenOut:
    """Invalidate a token early with a reason."""
    svc = ExecutionTokenService(db)
    try:
        return await svc.invalidate(token_id, reason)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


@_token.get(
    "/mission/{mission_id}/active",
    response_model=ExecutionTokenOut | None,
    summary="Get Active Token for Mission",
    description="Get the currently active ExecutionToken for a mission.",
)
async def get_active_token_by_mission(
    mission_id: str,
    db: Annotated[AsyncSession, Depends(get_db)],
) -> ExecutionTokenOut | None:
    """Get the active ExecutionToken for a mission."""
    svc = ExecutionTokenService(db)
    token = await svc.get_active_token(mission_id)
    if token is None:
        return None
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


@_token.get(
    "/mission/{mission_id}/page",
    response_model=dict,
    summary="Paginated Tokens by Mission",
    description="Paginated list of ExecutionTokens for a mission.",
)
async def page_tokens_by_mission(
    mission_id: str,
    db: Annotated[AsyncSession, Depends(get_db)],
    page_no: int = Query(default=1, ge=1),
    page_size: int = Query(default=20, ge=1, le=100),
) -> dict:
    """Paginated list of ExecutionTokens for a mission."""
    svc = ExecutionTokenService(db)
    return await svc.page_by_mission(mission_id, page_no=page_no, page_size=page_size)


@_token.get(
    "/agent/{agent_id}/page",
    response_model=dict,
    summary="Paginated Tokens by Agent",
    description="Paginated list of ExecutionTokens for an agent.",
)
async def page_tokens_by_agent(
    agent_id: str,
    db: Annotated[AsyncSession, Depends(get_db)],
    page_no: int = Query(default=1, ge=1),
    page_size: int = Query(default=20, ge=1, le=100),
) -> dict:
    """Paginated list of ExecutionTokens for an agent."""
    svc = ExecutionTokenService(db)
    return await svc.page_by_agent(agent_id, page_no=page_no, page_size=page_size)


router.include_router(_token)


# ════════════════════════════════════════════════════════════════════════════════
# AUDIT CHAIN ENDPOINTS
# ════════════════════════════════════════════════════════════════════════════════

_audit = APIRouter(prefix="/audit", tags=["AuditChain"])


class AuditChainInitRequest(BaseModel):
    """Request to initialize an AuditChain."""
    mission_id: str
    agent_id: str


class AuditChainAppendRequest(BaseModel):
    """Request to append an entry to an AuditChain."""
    layer: AuditLayer
    event: str
    agent_id: str
    mission_id: str
    data: dict[str, Any] | None = None
    token_id: str | None = None


class AuditChainVerifyResponse(BaseModel):
    """Response from AuditChain integrity verification."""
    chain_id: str
    valid: bool
    message: str


@_audit.post(
    "/initialize",
    summary="Initialize AuditChain",
    description="Create a new AuditChain and write the genesis IDENTITY entry.",
)
async def initialize_chain(
    request: AuditChainInitRequest,
    db: Annotated[AsyncSession, Depends(get_db)],
) -> dict:
    """
    Initialize a new AuditChain for a mission.

    Creates the chain header and writes the genesis IDENTITY entry.
    Call this when a mission enters the CREATED state.
    """
    svc = AuditChainService()
    chain_id = await svc.initialize(
        db,
        mission_id=request.mission_id,
        agent_id=request.agent_id,
    )
    return {"chain_id": chain_id, "message": "AuditChain initialized"}


@_audit.post(
    "/{chain_id}/append",
    summary="Append Entry",
    description="Append a new entry to an AuditChain.",
)
async def append_entry(
    chain_id: str,
    request: AuditChainAppendRequest,
    db: Annotated[AsyncSession, Depends(get_db)],
) -> dict:
    """
    Append an entry to an AuditChain.

    The chain must not be closed. Call /audit/{chain_id}/close when done.
    """
    svc = AuditChainService()
    try:
        entry = await svc.append(
            db,
            chain_id=chain_id,
            layer=request.layer,
            event=request.event,
            agent_id=request.agent_id,
            mission_id=request.mission_id,
            data=request.data,
            token_id=request.token_id,
        )
        return {
            "entry_id": entry.entry_id,
            "chain_id": entry.chain_id,
            "sequence": entry.sequence,
            "entry_hash": entry.entry_hash,
            "message": "Entry appended",
        }
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@_audit.post(
    "/{chain_id}/close",
    summary="Close AuditChain",
    description="Close an AuditChain (no further entries may be appended).",
)
async def close_chain(
    chain_id: str,
    db: Annotated[AsyncSession, Depends(get_db)],
) -> dict:
    """
    Close an AuditChain.

    Writes the terminal entry and marks the chain as closed.
    Call this when a mission enters the CLOSED state.
    """
    svc = AuditChainService()
    try:
        chain = await svc.close(db, chain_id)
        return {
            "chain_id": chain.chain_id,
            "mission_id": chain.mission_id,
            "agent_id": chain.agent_id,
            "entry_count": len(chain.entries),
            "head_hash": chain.head_hash,
            "closed_at": chain.closed_at.isoformat() if chain.closed_at else None,
            "message": "AuditChain closed",
        }
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@_audit.get(
    "/mission/{mission_id}",
    response_model=dict,
    summary="Get AuditChain by Mission",
    description="Retrieve the full AuditChain for a mission.",
)
async def get_chain_by_mission(
    mission_id: str,
    db: Annotated[AsyncSession, Depends(get_db)],
) -> dict:
    """Get the AuditChain for a mission."""
    svc = AuditChainService()
    chain = await svc.get_by_mission(db, mission_id)
    if chain is None:
        raise HTTPException(status_code=404, detail=f"AuditChain not found for mission: {mission_id}")
    return _chain_to_dict(chain)


@_audit.get(
    "/{chain_id}",
    response_model=dict,
    summary="Get AuditChain by ID",
    description="Retrieve an AuditChain by chain_id.",
)
async def get_chain(
    chain_id: str,
    db: Annotated[AsyncSession, Depends(get_db)],
) -> dict:
    """Get an AuditChain by chain_id."""
    svc = AuditChainService()
    chain = await svc.get_by_chain_id(db, chain_id)
    if chain is None:
        raise HTTPException(status_code=404, detail=f"AuditChain not found: {chain_id}")
    return _chain_to_dict(chain)


@_audit.get(
    "/{chain_id}/verify",
    response_model=AuditChainVerifyResponse,
    summary="Verify Integrity",
    description="Verify the integrity of an AuditChain from the database.",
)
async def verify_chain(
    chain_id: str,
    db: Annotated[AsyncSession, Depends(get_db)],
) -> AuditChainVerifyResponse:
    """
    Verify the integrity of an AuditChain.

    Checks:
        1. Each entry's entry_hash is consistent
        2. Each entry's prev_hash links to the prior entry
        3. Sequence numbers are contiguous
        4. head_hash matches the last entry's entry_hash
    """
    svc = AuditChainService()
    valid = await svc.verify_integrity(db, chain_id)
    return AuditChainVerifyResponse(
        chain_id=chain_id,
        valid=valid,
        message="Integrity check passed" if valid else "Integrity check FAILED — tampering detected",
    )


@_audit.get(
    "/agent/{agent_id}/page",
    response_model=dict,
    summary="Paginated Chains by Agent",
    description="Paginated list of AuditChains for an agent.",
)
async def page_chains_by_agent(
    agent_id: str,
    db: Annotated[AsyncSession, Depends(get_db)],
    page_no: int = Query(default=1, ge=1),
    page_size: int = Query(default=20, ge=1, le=100),
) -> dict:
    """Paginated list of AuditChains for an agent (chain metadata only)."""
    svc = AuditChainService()
    return await svc.list_by_agent(db, agent_id, page_no=page_no, page_size=page_size)


router.include_router(_audit)


# ── Helpers ───────────────────────────────────────────────────────────────────


def _chain_to_dict(chain: AuditChain) -> dict:
    """Serialize an AuditChain to a JSON-serializable dict."""
    return {
        "chain_id": chain.chain_id,
        "mission_id": chain.mission_id,
        "agent_id": chain.agent_id,
        "initialized_at": chain.initialized_at.isoformat() if chain.initialized_at else None,
        "closed_at": chain.closed_at.isoformat() if chain.closed_at else None,
        "head_hash": chain.head_hash,
        "entries": [
            {
                "entry_id": e.entry_id,
                "chain_id": e.chain_id,
                "sequence": e.sequence,
                "layer": e.layer.value,
                "event": e.event,
                "agent_id": e.agent_id,
                "mission_id": e.mission_id,
                "token_id": e.token_id,
                "timestamp": e.timestamp.isoformat() if e.timestamp else None,
                "data": e.data,
                "prev_hash": e.prev_hash,
                "entry_hash": e.entry_hash,
            }
            for e in chain.entries
        ],
        "entry_count": len(chain.entries),
    }
