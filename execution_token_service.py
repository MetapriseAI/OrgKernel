"""
Pydantic schemas for ExecutionToken.

ExecutionToken implements the OrgKernel execution guardrail:

    1. Scope Definition
       - Developer/parent system defines restrictive policy (allow/deny per tool)

    2. Token Minting
       - OrgKernel mint() generates a short-lived, cryptographically signed token
       - Token contains: scope, expiration, mission_id, agent_id, and Org CA signature

    3. Injection
       - Token is injected into the Agent's runtime via OrgKernel.wrap()

    4. Interception & Verification
       - Every tool call is intercepted by the Tool Gateway
       - Gateway verifies token signature (proving it was minted by OrgKernel)
       - Gateway checks tool is within permitted scope
       - Out-of-scope calls are blocked before reaching external systems

    5. Attestation Linkage
       - Every ExecutionToken is cryptographically signed by the Org CA
       - This prevents Token Grafting: a token for Agent A cannot be used by Agent B
       - Any tampering with token fields invalidates the signature
"""
from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from uuid import uuid4

from pydantic import BaseModel, Field, field_validator, model_validator


_TOKEN_ID_RE    = re.compile(r"^tok_[a-z0-9]+$")
_AGENT_ID_RE    = re.compile(r"^aid_[a-z0-9]+$")
_MISSION_ID_RE  = re.compile(r"^msn_[a-z0-9]+$")
_TOOL_ID_RE     = re.compile(r"^[a-z][a-z0-9_]*$")


def _new_token_id() -> str:
    return "tok_" + uuid4().hex[:12]


def _now_utc() -> datetime:
    return datetime.now(timezone.utc)


class BoundedParam(BaseModel):
    """
    A named tool call parameter with numeric bounds.
    Calls exceeding bounds are blocked at the Tool Gateway.
    """
    model_config = {"frozen": True}

    param_name: str
    upper_bound: float | None = None
    lower_bound: float | None = None
    unit: str | None = None

    @model_validator(mode="after")
    def _validate_bounds(self) -> BoundedParam:
        if (
            self.upper_bound is not None
            and self.lower_bound is not None
            and self.upper_bound < self.lower_bound
        ):
            raise ValueError(
                f"upper_bound ({self.upper_bound}) must be >= lower_bound ({self.lower_bound})."
            )
        return self

    def check(self, value: float) -> bool:
        """Return True if value is within bounds."""
        if self.upper_bound is not None and value > self.upper_bound:
            return False
        if self.lower_bound is not None and value < self.lower_bound:
            return False
        return True


class ScopeCheckResult(BaseModel):
    """Result of a Tool Gateway scope check against an ExecutionToken."""
    passed: bool
    violations: list[str] = Field(default_factory=list)

    @property
    def blocked(self) -> bool:
        return not self.passed


class ExecutionToken(BaseModel):
    """
    Scoped, time-bounded permission token for a specific Mission execution.
    Issued at Mission APPROVED state.
    Enforced at the Tool Gateway — out-of-scope calls are blocked
    before reaching any external system.
    """
    model_config = {"frozen": True}

    token_id: str = Field(default_factory=_new_token_id)
    agent_id: str
    mission_id: str
    execution_scope: list[str] = Field(
        min_length=1,
        description="Whitelist of permitted tool call identifiers.",
    )
    immutable_params: dict = Field(
        default_factory=dict,
        description="Tool call params that must match exactly.",
    )
    bounded_params: list[BoundedParam] = Field(
        default_factory=list,
        description="Params with numeric bounds.",
    )
    issued_at: datetime = Field(default_factory=_now_utc)
    expires_at: datetime
    boundary_snapshot_id: str | None = None
    token_signature: str | None = Field(
        default=None,
        description="Ed25519 signature by Org CA over canonical token payload. Prevents token tampering and Token Grafting.",
    )
    used: bool = False
    invalidated_at: datetime | None = None
    invalidation_reason: str | None = None

    @field_validator("token_id")
    @classmethod
    def _validate_token_id(cls, v: str) -> str:
        if not _TOKEN_ID_RE.match(v):
            raise ValueError(f"token_id '{v}' must match ^tok_[a-z0-9]+$")
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

    @field_validator("execution_scope")
    @classmethod
    def _validate_scope_unique(cls, v: list[str]) -> list[str]:
        for tool in v:
            if not _TOOL_ID_RE.match(tool):
                raise ValueError(
                    f"Tool identifier '{tool}' must match ^[a-z][a-z0-9_]*$"
                )
        if len(v) != len(set(v)):
            raise ValueError("execution_scope identifiers must be unique.")
        return v

    @model_validator(mode="after")
    def _validate_expiry(self) -> ExecutionToken:
        if self.expires_at <= self.issued_at:
            raise ValueError("expires_at must be after issued_at.")
        return self

    def to_signable_payload(self) -> str:
        """
        Return canonical JSON for signing / verification.
        This payload is what the Org CA signs to issue the token.
        Any field tampering invalidates the signature.
        """
        scope_sorted = sorted(self.execution_scope)
        payload = {
            "token_id": self.token_id,
            "agent_id": self.agent_id,
            "mission_id": self.mission_id,
            "execution_scope": scope_sorted,
            "immutable_params": self.immutable_params,
            "bounded_params": [bp.model_dump() for bp in self.bounded_params],
            "issued_at": self.issued_at.isoformat(),
            "expires_at": self.expires_at.isoformat(),
            "boundary_snapshot_id": self.boundary_snapshot_id,
        }
        return json.dumps(payload, separators=(",", ":"), sort_keys=True)

    @property
    def is_expired(self) -> bool:
        """True if token has passed its expires_at timestamp."""
        return _now_utc() > self.expires_at

    @property
    def is_valid(self) -> bool:
        """True if token is not expired, not used, and not invalidated."""
        if self.used:
            return False
        if self.invalidated_at is not None:
            return False
        if self.is_expired:
            return False
        return True

    def check_scope(self, tool: str, params: dict) -> ScopeCheckResult:
        """
        Validate a proposed tool call against this token's scope.
        Called by Tool Gateway before every external call.
        Returns ScopeCheckResult — never raises.
        """
        violations: list[str] = []

        if tool not in self.execution_scope:
            violations.append(f"tool_not_in_scope: {tool}")

        for key, expected in self.immutable_params.items():
            actual = params.get(key)
            if actual != expected:
                violations.append(
                    f"immutable_param_mismatch: {key} "
                    f"(expected={expected!r}, got={actual!r})"
                )

        for bp in self.bounded_params:
            actual = params.get(bp.param_name)
            if actual is not None and not bp.check(float(actual)):
                violations.append(
                    f"bounded_param_violation: {bp.param_name}={actual} "
                    f"(bounds: [{bp.lower_bound}, {bp.upper_bound}])"
                )

        return ScopeCheckResult(passed=len(violations) == 0, violations=violations)

    def invalidate(self, reason: str) -> ExecutionToken:
        """Return a new invalidated token."""
        return self.model_copy(update={
            "invalidated_at": _now_utc(),
            "invalidation_reason": reason,
        })

    def mark_used(self) -> ExecutionToken:
        """Return a new token marked as consumed."""
        return self.model_copy(update={"used": True})


# ── Request / Response Schemas ────────────────────────────────────────────────


class ExecutionTokenCreate(BaseModel):
    """Request to mint a new ExecutionToken."""
    agent_id: str = Field(min_length=10, max_length=32)
    mission_id: str = Field(min_length=10, max_length=32)
    execution_scope: list[str] = Field(min_length=1)
    immutable_params: dict = Field(default_factory=dict)
    bounded_params: list[BoundedParam] = Field(default_factory=list)
    expires_at: datetime
    boundary_snapshot_id: str | None = Field(default=None, max_length=32)


class ExecutionTokenOut(BaseModel):
    """Response schema for ExecutionToken queries."""
    token_id: str
    agent_id: str
    mission_id: str
    execution_scope: list[str]
    immutable_params: dict
    bounded_params: list[BoundedParam]
    issued_at: datetime
    expires_at: datetime
    boundary_snapshot_id: str | None
    token_signature: str | None
    used: bool
    is_valid: bool
    invalidated_at: datetime | None
    invalidation_reason: str | None

    model_config = {"from_attributes": True}


class ScopeCheckRequest(BaseModel):
    """Request to validate a tool call against an ExecutionToken."""
    token_id: str = Field(min_length=10, max_length=32)
    tool_name: str = Field(min_length=1, max_length=64)
    params: dict = Field(default_factory=dict)


class ScopeCheckResponse(BaseModel):
    """Response from a scope check."""
    token_id: str
    tool_name: str
    passed: bool
    blocked: bool
    violations: list[str]
