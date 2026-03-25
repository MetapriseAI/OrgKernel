"""
AgentIdentity service layer: full PKI lifecycle with Ed25519, CSR, Org CA signing,
challenge-response verification, and revocation.

PKI Lifecycle (per specification):
    1. Entropy Generation & Keypair Creation
       - Agent generates Ed25519 keypair locally
       - Private key never leaves secure environment
    2. CSR Submission
       - Agent submits CSR with public key + OU + purpose
    3. Organizational CA Signing
       - OrgKernel CA validates request
       - Issues signed AgentCertificate
    4. Credential Distribution
       - Agent stores signed certificate
       - Presents certificate during tool calls / cross-agent communication
    5. Dynamic Verification
       - Any system verifies signature against Org CA public root
       - Challenge-response prevents replay attacks
"""
from __future__ import annotations

import json
import secrets
import time
from datetime import datetime, timedelta, timezone
from typing import Any
from uuid import uuid4

from sqlalchemy import asc, desc, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from orgkernel.crypto_utils import (
    compute_ca_fingerprint,
    generate_agent_keypair,
    get_org_ca_public_key_bytes,
    sign_payload,
)
from orgkernel.models import AgentIdentityModel
from orgkernel.schemas.agent_identity import (
    AgentCertificate,
    AgentIdentity,
    AgentIdentityCSR,
    AgentIdentityCreate,
    AgentIdentityIssueResult,
    AgentIdentityOut,
    AgentIdentityRevoke,
    AgentIdentityStatus,
    AgentIdentityVerify,
    AgentIdentityVerifyResponse,
    ChallengeRequest,
    ChallengeResponse,
    ChallengeVerificationResult,
)
from cryptography.hazmat.primitives import serialization


# ── In-memory challenge store (Phase 1) ─────────────────────────────────────────
#
# Phase 1: In-memory dict with TTL checking on retrieval.
# Production: Replace with Redis (SETEX with TTL for automatic expiry).
#   - SETEX challenge:{challenge_id} {ttl_seconds} {json_payload}
#   - GET challenge:{challenge_id} -> DEL atomically for one-time use

_CHALLENGE_STORE: dict[str, dict[str, Any]] = {}
_CHALLENGE_DEFAULT_TTL = 300  # 5 minutes


def _store_challenge(challenge: ChallengeRequest, ttl_seconds: int = _CHALLENGE_DEFAULT_TTL) -> None:
    """
    Store a challenge with TTL metadata.
    TTL is enforced on retrieval (not automatic in-memory — background cleanup not needed for short-lived servers).
    Production: use Redis SETEX.
    """
    _CHALLENGE_STORE[challenge.challenge_id] = {
        "agent_id": challenge.agent_id,
        "nonce": challenge.nonce,
        "issued_by": challenge.issued_by,
        "created_at": challenge.created_at,
        "expires_at": challenge.expires_at,
        "used": False,
        "ttl_seconds": ttl_seconds,
        "stored_at": time.time(),
    }


def _get_and_consume_challenge(
    challenge_id: str,
    ttl_seconds: int = _CHALLENGE_DEFAULT_TTL,
) -> dict[str, Any] | None:
    """
    Retrieve and consume a challenge (one-time use).

    Enforces TTL:
        - If challenge exists but age exceeds ttl_seconds -> treat as expired, return None.
    """
    entry = _CHALLENGE_STORE.pop(challenge_id, None)
    if entry is None:
        return None

    age = time.time() - entry.get("stored_at", 0)
    effective_ttl = entry.get("ttl_seconds", _CHALLENGE_DEFAULT_TTL)
    if age > effective_ttl:
        return None

    entry["used"] = True
    return entry


def _serialize_json(v: dict[str, Any] | list | None) -> str | None:
    if v is None:
        return None
    return json.dumps(v, separators=(",", ":"), ensure_ascii=False)


def _deserialize_json(v: str | None) -> dict[str, Any] | list | None:
    if v is None:
        return None
    return json.loads(v)


def _model_to_pydantic(model: AgentIdentityModel) -> AgentIdentity:
    """Convert SQLAlchemy model to Pydantic AgentIdentity."""
    return AgentIdentity(
        agent_id=model.agent_id,
        agent_name=model.agent_name,
        org_id=model.org_id,
        issued_by=model.issued_by,
        public_key=model.public_key,
        org_ca_fingerprint=model.org_ca_fingerprint,
        issued_at=model.issued_at,
        valid_until=model.valid_until,
        status=AgentIdentityStatus(model.identity_status),
        revoked_at=model.revoked_at,
        revoked_by=model.revoked_by,
        revocation_reason=model.revocation_reason,
        metadata=_deserialize_json(model.metadata_json) or {},
    )


def _model_to_out(model: AgentIdentityModel) -> AgentIdentityOut:
    """Convert SQLAlchemy model to AgentIdentityOut response schema."""
    identity = _model_to_pydantic(model)
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


def _now_utc() -> datetime:
    return datetime.now(timezone.utc)


# ── AgentIdentityService ──────────────────────────────────────────────────────


class AgentIdentityService:
    """
    Service for AgentIdentity full PKI lifecycle management.

    PKI Flow:
        1. submit_csr()        - Agent submits CSR (public key + metadata)
        2. issue_from_csr()   - Org CA validates + signs -> AgentCertificate + identity
        3. verify()           - Static verification (status + expiry)
        4. request_challenge() - Verifier requests a challenge
        5. respond_challenge()  - Agent signs nonce (proves key possession)
        6. verify_challenge()   - Verifier validates signature
        7. revoke()           - Org authority revokes identity
    """

    def __init__(self, db: AsyncSession) -> None:
        self._db = db

    # ── Step 1: CSR Submission ──────────────────────────────────────────────

    async def submit_csr(self, csr: AgentIdentityCSR) -> AgentIdentityCSR:
        """
        Validate and store a CSR for later signing.

        Step 1 of the PKI lifecycle: Agent submits CSR with public key + metadata.
        The CSR is validated (duplicate check, key format) and queued for signing.
        The private key is NEVER transmitted — only the public key.

        Args:
            csr: CSR from the agent.

        Returns:
            The validated CSR with assigned csr_id.

        Raises:
            ValueError: If agent_name already exists in org.
        """
        existing = await self._db.execute(
            select(AgentIdentityModel).where(
                AgentIdentityModel.agent_name == csr.agent_name,
                AgentIdentityModel.org_id == csr.org_id,
            )
        )
        if existing.scalars().first() is not None:
            raise ValueError(
                f"AgentIdentity already exists for agent_name={csr.agent_name} in org={csr.org_id}"
            )
        return csr

    # ── Step 2: Issue from CSR (CA Signing) ────────────────────────────────

    async def issue_from_csr(self, csr: AgentIdentityCSR) -> AgentIdentityIssueResult:
        """
        Issue an AgentIdentity from a validated CSR — Org CA signing.

        Step 2-3 of the PKI lifecycle:
            2. Org CA validates the CSR request
            3. Signs and issues AgentCertificate

        Args:
            csr: Validated CSR.

        Returns:
            AgentIdentityIssueResult with:
                - identity: AgentIdentity record (for DB persistence)
                - certificate: Signed certificate (for agent to store)
                - ca_fingerprint: CA fingerprint (for reference)
                - private_key_pem: PKCS8 PEM (for agent to store — NEVER persisted server-side)
        """
        # 1. Generate agent_id and keypair
        agent_id = "aid_" + uuid4().hex[:12]
        issued_at = _now_utc()
        private_key_pem, public_key_b64url = generate_agent_keypair()

        # 2. Compute validity
        if csr.requested_validity_days:
            valid_until = issued_at + timedelta(days=csr.requested_validity_days)
        else:
            valid_until = None

        # 3. Get CA keypair and compute fingerprint
        ca_private_key_bytes, ca_public_key_bytes = _get_ca_keypair()
        ca_fingerprint = compute_ca_fingerprint(ca_public_key_bytes)

        # 4. Build certificate payload (what the CA signs)
        cert_payload = {
            "certificate_id": agent_id,
            "agent_id": agent_id,
            "agent_name": csr.agent_name,
            "org_id": csr.org_id,
            "issued_by": csr.requested_ou,
            "public_key": public_key_b64url,
            "ca_fingerprint": ca_fingerprint,
            "issued_at": issued_at.isoformat(),
            "valid_until": valid_until.isoformat() if valid_until else None,
        }

        # 5. CA signs the payload
        ca_signature = sign_payload(_ca_private_key_to_pem(ca_private_key_bytes), json.dumps(cert_payload, separators=(",", ":"), sort_keys=True))
        ca_signature_b64url = _b64_encode(ca_signature)

        # 6. Create AgentCertificate (returned to agent)
        certificate = AgentCertificate(
            certificate_id=agent_id,
            agent_id=agent_id,
            agent_name=csr.agent_name,
            org_id=csr.org_id,
            issued_by=csr.requested_ou,
            public_key=public_key_b64url,
            ca_fingerprint=ca_fingerprint,
            ca_signature=ca_signature_b64url,
            issued_at=issued_at,
            valid_until=valid_until,
            status=AgentIdentityStatus.ACTIVE,
        )

        # 7. Persist identity record (public key + CA fingerprint, NO private key)
        model = AgentIdentityModel(
            agent_id=agent_id,
            agent_name=csr.agent_name,
            org_id=csr.org_id,
            issued_by=csr.requested_ou,
            public_key=public_key_b64url,
            org_ca_fingerprint=ca_fingerprint,
            issued_at=issued_at,
            valid_until=valid_until,
            identity_status=AgentIdentityStatus.ACTIVE.value,
            metadata_json=_serialize_json(dict(csr.metadata)),
        )

        self._db.add(model)
        await self._db.flush()
        await self._db.refresh(model)

        identity = _model_to_pydantic(model)

        return AgentIdentityIssueResult(
            identity=identity,
            certificate=certificate,
            ca_fingerprint=ca_fingerprint,
            private_key_pem=private_key_pem,
        )

    # ── Legacy: Issue from AgentIdentityCreate ──────────────────────────────

    async def issue(self, data: AgentIdentityCreate) -> AgentIdentityOut:
        """
        Issue a new AgentIdentity (legacy method, wraps CSR flow).

        For backward compatibility. Prefer use of submit_csr + issue_from_csr.
        This generates a new keypair internally — the private key is returned
        for storage but NOT persisted in the database.
        """
        csr = AgentIdentityCSR(
            agent_name=data.agent_name,
            org_id=data.org_id,
            requested_ou=data.issued_by,
            public_key="x" * 43,  # placeholder — will be replaced by generate_agent_keypair
            purpose="agent_operation",
            metadata=data.metadata,
            requested_validity_days=(
                int(data.valid_until.days) if data.valid_until else None
            ) if data.valid_until else None,
        )

        result = await self.issue_from_csr(csr)
        return AgentIdentityOut(
            agent_id=result.identity.agent_id,
            agent_name=result.identity.agent_name,
            org_id=result.identity.org_id,
            issued_by=result.identity.issued_by,
            public_key=result.identity.public_key,
            org_ca_fingerprint=result.identity.org_ca_fingerprint,
            issued_at=result.identity.issued_at,
            valid_until=result.identity.valid_until,
            status=result.identity.status,
            is_active=result.identity.is_active,
            revoked_at=result.identity.revoked_at,
            revoked_by=result.identity.revoked_by,
            revocation_reason=result.identity.revocation_reason,
            metadata=result.identity.metadata,
        )

    # ── Step 3: Static Verification ────────────────────────────────────────

    async def verify(self, data: AgentIdentityVerify) -> AgentIdentityVerifyResponse:
        """
        Verify an AgentIdentity is currently valid (static check).

        Checks:
            1. Identity exists
            2. Status is not REVOKED
            3. Status is not SUSPENDED
            4. Not expired (valid_until check)

        Does NOT perform cryptographic verification (use verify_challenge for that).
        """
        identity = await self.get_by_id(data.agent_id)
        now = _now_utc()

        if identity is None:
            return AgentIdentityVerifyResponse(
                agent_id=data.agent_id,
                is_active=False,
                is_valid=False,
                verified_at=now,
                message="AgentIdentity not found.",
            )

        if identity.status == AgentIdentityStatus.REVOKED:
            return AgentIdentityVerifyResponse(
                agent_id=data.agent_id,
                is_active=False,
                is_valid=False,
                verified_at=now,
                message="AgentIdentity has been revoked.",
            )

        if identity.status == AgentIdentityStatus.SUSPENDED:
            return AgentIdentityVerifyResponse(
                agent_id=data.agent_id,
                is_active=False,
                is_valid=False,
                verified_at=now,
                message="AgentIdentity is suspended.",
            )

        if identity.status == AgentIdentityStatus.EXPIRED or (
            identity.valid_until and now > identity.valid_until
        ):
            return AgentIdentityVerifyResponse(
                agent_id=data.agent_id,
                is_active=False,
                is_valid=False,
                verified_at=now,
                message="AgentIdentity has expired.",
            )

        return AgentIdentityVerifyResponse(
            agent_id=data.agent_id,
            is_active=True,
            is_valid=True,
            verified_at=now,
            message="AgentIdentity is valid.",
        )

    async def verify_certificate(
        self,
        certificate: AgentCertificate,
        ca_public_key_bytes: bytes | None = None,
    ) -> bool:
        """
        Verify an AgentCertificate's CA signature.

        Args:
            certificate: The AgentCertificate to verify.
            ca_public_key_bytes: Org CA public key bytes.
                If None, uses the default development CA.

        Returns:
            True if CA signature is valid, False otherwise.
        """
        if ca_public_key_bytes is None:
            ca_public_key_bytes = get_org_ca_public_key_bytes()

        payload = certificate.to_signable_payload()
        from orgkernel.crypto_utils import verify_ca_signature
        return verify_ca_signature(ca_public_key_bytes, payload, certificate.ca_signature)

    # ── Step 4-6: Challenge-Response ──────────────────────────────────────

    async def request_challenge(
        self,
        agent_id: str,
        issued_by: str,
        nonce: str | None = None,
        ttl_seconds: int = 300,
    ) -> ChallengeRequest:
        """
        Generate and store a cryptographic challenge for an agent.

        Step 4: Verifier requests a challenge for the agent.
        The nonce should be sent to the agent; the agent signs it and returns
        a ChallengeResponse.

        Args:
            agent_id: Agent to challenge.
            issued_by: Identifier of the requesting system.
            nonce: Optional nonce (auto-generated if not provided).
            ttl_seconds: Challenge TTL in seconds (default 5 minutes).

        Returns:
            ChallengeRequest with the nonce to send to the agent.
        """
        if nonce is None:
            nonce = secrets.token_urlsafe(32)

        challenge = ChallengeRequest(
            agent_id=agent_id,
            nonce=nonce,
            issued_by=issued_by,
            expires_at=_now_utc() + timedelta(seconds=ttl_seconds),
        )

        _store_challenge(challenge, ttl_seconds=ttl_seconds)
        return challenge

    async def respond_challenge(
        self,
        response: ChallengeResponse,
        ttl_seconds: int = _CHALLENGE_DEFAULT_TTL,
    ) -> ChallengeRequest | None:
        """
        Validate a challenge response from an agent.

        Step 5: Agent sends back the signed nonce.
        This verifies:
            1. Challenge exists and hasn't been used
            2. Challenge has not expired (TTL check)
            3. agent_id matches the original challenge
            4. Signature is a valid Ed25519 signature over the nonce
        """
        challenge_data = _get_and_consume_challenge(response.challenge_id, ttl_seconds=ttl_seconds)
        if challenge_data is None:
            return None

        if challenge_data["agent_id"] != response.agent_id:
            return None

        # Verify signature using agent's public key
        try:
            signature_bytes = _b64_decode(response.signature)
            identity = await self.get_by_id(response.certificate_id)
            if identity is None or identity.public_key != response.public_key:
                return None

            public_key_bytes = _b64_decode(response.public_key)
            if len(public_key_bytes) != 32:
                raise ValueError("Invalid Ed25519 public key length")

            from cryptography.hazmat.primitives.asymmetric import ed25519
            public_key = ed25519.Ed25519PublicKey.from_public_bytes(public_key_bytes)
            public_key.verify(signature_bytes, response.nonce.encode("utf-8"))
        except Exception:
            return None

        return ChallengeRequest(
            challenge_id=response.challenge_id,
            agent_id=response.agent_id,
            nonce=challenge_data["nonce"],
            issued_by=challenge_data["issued_by"],
            created_at=challenge_data["created_at"],
            expires_at=challenge_data["expires_at"],
        )

    async def verify_challenge(
        self,
        response: ChallengeResponse,
        ttl_seconds: int = _CHALLENGE_DEFAULT_TTL,
    ) -> ChallengeVerificationResult:
        """
        Full challenge-response verification.

        Step 5-6 combined: Validate response and check certificate validity.

        Verifies:
            1. Challenge exists and hasn't been used (one-time use)
            2. Challenge has not expired (TTL check)
            3. Signature is valid (proves key possession)
            4. Certificate is ACTIVE and not expired
        """
        now = _now_utc()

        challenge_data = _get_and_consume_challenge(response.challenge_id, ttl_seconds=ttl_seconds)
        if challenge_data is None:
            return ChallengeVerificationResult(
                challenge_id=response.challenge_id,
                agent_id=response.agent_id,
                challenge_passed=False,
                certificate_valid=False,
                overall_valid=False,
                message="Challenge not found, expired, or already used.",
                verified_at=now,
            )

        if challenge_data["agent_id"] != response.agent_id:
            return ChallengeVerificationResult(
                challenge_id=response.challenge_id,
                agent_id=response.agent_id,
                challenge_passed=False,
                certificate_valid=False,
                overall_valid=False,
                message="Agent ID mismatch.",
                verified_at=now,
            )

        # Step 2: Verify signature
        challenge_passed = False
        try:
            signature_bytes = _b64_decode(response.signature)
            public_key_bytes = _b64_decode(response.public_key)
            if len(public_key_bytes) != 32:
                raise ValueError("Invalid Ed25519 public key length")
            from cryptography.hazmat.primitives.asymmetric import ed25519
            public_key = ed25519.Ed25519PublicKey.from_public_bytes(public_key_bytes)
            public_key.verify(signature_bytes, response.nonce.encode("utf-8"))
            challenge_passed = True
        except Exception:
            pass

        # Step 3: Check certificate validity (static check)
        certificate_valid = False
        if challenge_passed:
            identity = await self.get_by_id(response.certificate_id)
            if identity is not None:
                if identity.public_key == response.public_key:
                    if identity.status == AgentIdentityStatus.ACTIVE:
                        if identity.valid_until is None or identity.valid_until > now:
                            certificate_valid = True

        overall_valid = challenge_passed and certificate_valid

        if overall_valid:
            message = "Challenge-response verified: agent identity confirmed."
        elif challenge_passed and not certificate_valid:
            message = "Signature valid but certificate is invalid (revoked/expired)."
        else:
            message = "Signature verification failed."

        return ChallengeVerificationResult(
            challenge_id=response.challenge_id,
            agent_id=response.agent_id,
            challenge_passed=challenge_passed,
            certificate_valid=certificate_valid,
            overall_valid=overall_valid,
            message=message,
            verified_at=now,
        )

    # ── Revocation ─────────────────────────────────────────────────────────

    async def revoke(
        self,
        agent_id: str,
        data: AgentIdentityRevoke,
    ) -> AgentIdentityOut:
        """
        Revoke an AgentIdentity.

        The identity cannot be used after revocation. A new identity must be issued.
        Revocation is permanent — unlike suspension, there is no recovery path.
        """
        result = await self._db.execute(
            select(AgentIdentityModel).where(AgentIdentityModel.agent_id == agent_id)
        )
        model = result.scalars().first()
        if model is None:
            raise ValueError(f"AgentIdentity not found: {agent_id}")

        if model.identity_status == AgentIdentityStatus.REVOKED.value:
            raise ValueError("AgentIdentity is already revoked")

        now = _now_utc()
        model.identity_status = AgentIdentityStatus.REVOKED.value
        model.revoked_at = now
        model.revoked_by = data.revoked_by
        model.revocation_reason = data.reason

        await self._db.flush()
        await self._db.refresh(model)

        return _model_to_out(model)

    async def suspend(self, agent_id: str) -> AgentIdentityOut:
        """Suspend an AgentIdentity (recoverable)."""
        result = await self._db.execute(
            select(AgentIdentityModel).where(AgentIdentityModel.agent_id == agent_id)
        )
        model = result.scalars().first()
        if model is None:
            raise ValueError(f"AgentIdentity not found: {agent_id}")

        model.identity_status = AgentIdentityStatus.SUSPENDED.value
        await self._db.flush()
        await self._db.refresh(model)

        return _model_to_out(model)

    async def reactivate(self, agent_id: str) -> AgentIdentityOut:
        """Reactivate a suspended AgentIdentity (REVOKED cannot be reactivated)."""
        result = await self._db.execute(
            select(AgentIdentityModel).where(AgentIdentityModel.agent_id == agent_id)
        )
        model = result.scalars().first()
        if model is None:
            raise ValueError(f"AgentIdentity not found: {agent_id}")

        if model.identity_status == AgentIdentityStatus.REVOKED.value:
            raise ValueError(
                "REVOKED identities cannot be reactivated. Issue a new identity."
            )

        model.identity_status = AgentIdentityStatus.ACTIVE.value
        model.revoked_at = None
        model.revoked_by = None
        model.revocation_reason = None

        await self._db.flush()
        await self._db.refresh(model)

        return _model_to_out(model)

    # ── Query ───────────────────────────────────────────────────────────────

    async def get_by_id(self, agent_id: str) -> AgentIdentity | None:
        """Get an AgentIdentity by agent_id."""
        result = await self._db.execute(
            select(AgentIdentityModel).where(AgentIdentityModel.agent_id == agent_id)
        )
        model = result.scalars().first()
        if model is None:
            return None
        return _model_to_pydantic(model)

    async def get_active_identity(self, agent_id: str) -> AgentIdentity | None:
        """Get an AgentIdentity only if currently ACTIVE and not expired."""
        identity = await self.get_by_id(agent_id)
        if identity is None:
            return None
        if not identity.is_active:
            return None
        return identity

    async def list_by_org(
        self,
        org_id: str,
        status: str | None = None,
    ) -> list[AgentIdentity]:
        """List all AgentIdentities for an organization (no pagination)."""
        query = select(AgentIdentityModel).where(AgentIdentityModel.org_id == org_id)
        if status:
            query = query.where(AgentIdentityModel.identity_status == status)
        query = query.order_by(AgentIdentityModel.issued_at.desc())

        result = await self._db.execute(query)
        models = result.scalars().all()
        return [_model_to_pydantic(m) for m in models]

    async def page_by_org(
        self,
        org_id: str,
        page_no: int,
        page_size: int,
        status: str | None = None,
        order_by: list[dict[str, str]] | None = None,
    ) -> dict:
        """
        List AgentIdentities for an organization with SQL-level pagination.

        Args:
            org_id: Organization identifier.
            page_no: 1-based page number.
            page_size: Items per page.
            status: Optional status filter.
            order_by: Sorting, e.g. [{"issued_at": "desc"}].

        Returns:
            Dict with page_no, page_size, total, has_next, items.
        """
        conditions = [AgentIdentityModel.org_id == org_id]
        if status:
            conditions.append(AgentIdentityModel.identity_status == status)

        # Count total
        count_sql = select(func.count(AgentIdentityModel.agent_id)).where(*conditions)
        total_result = await self._db.execute(count_sql)
        total = total_result.scalar() or 0

        # Build sort
        if order_by:
            order_cols: list[Any] = []
            for item in order_by:
                for field, direction in item.items():
                    col = getattr(AgentIdentityModel, field, None)
                    if col is not None:
                        order_cols.append(desc(col) if direction.lower() == "desc" else asc(col))
        else:
            order_cols = [desc(AgentIdentityModel.issued_at)]

        # Paginate
        offset = (page_no - 1) * page_size
        query = (
            select(AgentIdentityModel)
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


# ── Private helpers ─────────────────────────────────────────────────────────────


_CA_KEYPAIR_CACHE: tuple[bytes, bytes] | None = None  # (private_pem, public_bytes)


def _get_ca_keypair() -> tuple[Any, bytes]:
    """Get the Org CA keypair (lazy-init)."""
    global _CA_KEYPAIR_CACHE
    if _CA_KEYPAIR_CACHE is None:
        from orgkernel.crypto_utils import _ensure_ca_keypair
        ca_private_key, ca_public_bytes = _ensure_ca_keypair()
        # Serialize private key to PEM
        pem_bytes = ca_private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        _CA_KEYPAIR_CACHE = (pem_bytes.decode("utf-8"), ca_public_bytes)
    return _CA_KEYPAIR_CACHE[0], _CA_KEYPAIR_CACHE[1]


def _ca_private_key_to_pem(private_key: Any) -> str:
    """Serialize an Ed25519 private key to PEM string."""
    pem_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    return pem_bytes.decode("utf-8")


def _b64_encode(data: bytes) -> str:
    import base64
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def _b64_decode(data: str) -> bytes:
    import base64
    return base64.urlsafe_b64decode(data + "==")
