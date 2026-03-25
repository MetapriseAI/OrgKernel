"""
Cryptographic utilities for OrgKernel PKI operations.

Provides:
    - Ed25519 keypair generation for agents and Org CA
    - CA fingerprint computation (SHA-256)
    - Signature generation and verification
    - Challenge-response helpers

All private keys must be stored securely by the caller.
This module never persists or logs private key material.
"""
from __future__ import annotations

import base64
import hashlib
import json
from typing import Any

from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization


# ── Default Org CA (Phase 1 development only) ──────────────────────────────────
#
# In production, load the CA keypair from a secure vault:
#   - HashiCorp Vault (Transit Secrets Engine)
#   - AWS KMS (Asymmetric signing)
#   - Azure Key Vault
#   - Google Cloud KMS
#
# The module-level singleton below is lazy-initialized for convenience only.
# Replace with a production-grade key management solution.

_DEFAULT_ORG_CA_PRIVATE_KEY: ed25519.Ed25519PrivateKey | None = None
_DEFAULT_ORG_CA_PUBLIC_KEY_BYTES: bytes | None = None


def _ensure_ca_keypair() -> tuple[ed25519.Ed25519PrivateKey, bytes]:
    """Lazily initialize the default Org CA Ed25519 keypair (Phase 1 only)."""
    global _DEFAULT_ORG_CA_PRIVATE_KEY, _DEFAULT_ORG_CA_PUBLIC_KEY_BYTES
    if _DEFAULT_ORG_CA_PRIVATE_KEY is None:
        _DEFAULT_ORG_CA_PRIVATE_KEY = ed25519.Ed25519PrivateKey.generate()
        _DEFAULT_ORG_CA_PUBLIC_KEY_BYTES = (
            _DEFAULT_ORG_CA_PRIVATE_KEY.public_key().public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw,
            )
        )
    return _DEFAULT_ORG_CA_PRIVATE_KEY, _DEFAULT_ORG_CA_PUBLIC_KEY_BYTES


def get_org_ca_public_key_bytes() -> bytes:
    """Return the raw 32-byte Ed25519 public key of the Org CA."""
    _, public_bytes = _ensure_ca_keypair()
    return public_bytes


def compute_ca_fingerprint(public_key_bytes: bytes | None = None) -> str:
    """
    Compute the SHA-256 fingerprint of the Org CA public key.

    Args:
        public_key_bytes: Raw CA public key bytes. If None, uses the default CA.

    Returns:
        64-char lowercase hex string.
    """
    if public_key_bytes is None:
        _, public_key_bytes = _ensure_ca_keypair()
    return hashlib.sha256(public_key_bytes).hexdigest()


# ── Agent Keypair Generation ──────────────────────────────────────────────────


def generate_agent_keypair() -> tuple[str, str]:
    """
    Generate a new Ed25519 keypair for an agent.

    Returns:
        Tuple of (private_key_pem, public_key_base64url).
        The private key MUST be stored securely by the agent — never sent to the server.
    """
    private_key = ed25519.Ed25519PrivateKey.generate()
    public_key = private_key.public_key()

    private_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    # 32 bytes -> base64url encode (no padding)
    public_key_b64url = base64.urlsafe_b64encode(public_bytes).decode().rstrip("=")
    return private_bytes.decode("utf-8"), public_key_b64url


# ── Signing & Verification ─────────────────────────────────────────────────────


def sign_payload(private_key_pem: str, payload: str) -> str:
    """
    Sign a canonical JSON payload with an Ed25519 private key.

    Args:
        private_key_pem: PKCS8 PEM-encoded private key.
        payload: Canonical JSON string to sign.

    Returns:
        Base64url-encoded Ed25519 signature (no padding).
    """
    private_key = serialization.load_pem_private_key(
        private_key_pem.encode("utf-8"),
        password=None,
    )
    if not isinstance(private_key, ed25519.Ed25519PrivateKey):
        raise TypeError("Private key must be Ed25519.")
    signature = private_key.sign(payload.encode("utf-8"))
    return base64.urlsafe_b64encode(signature).decode().rstrip("=")


def verify_signature(
    public_key_bytes: bytes,
    payload: str,
    signature_b64url: str,
) -> bool:
    """
    Verify an Ed25519 signature over a payload.

    Args:
        public_key_bytes: Raw 32-byte Ed25519 public key.
        payload: The signed payload string.
        signature_b64url: Base64url-encoded Ed25519 signature.

    Returns:
        True if signature is valid, False otherwise.
    """
    try:
        signature_bytes = base64.urlsafe_b64decode(signature_b64url + "==")
        public_key = ed25519.Ed25519PublicKey.from_public_bytes(public_key_bytes)
        public_key.verify(signature_bytes, payload.encode("utf-8"))
        return True
    except Exception:
        return False


def verify_ca_signature(
    ca_public_key_bytes: bytes,
    payload: str,
    signature_b64url: str,
) -> bool:
    """
    Verify an Org CA signature over a payload.

    Shorthand for verify_signature() with the Org CA public key.
    """
    return verify_signature(ca_public_key_bytes, payload, signature_b64url)


# ── Canonical JSON ────────────────────────────────────────────────────────────


def canonical_json(data: dict[str, Any]) -> str:
    """
    Return deterministic JSON serialization of a dict.
    Keys are sorted, no extra whitespace, ASCII-safe.
    """
    return json.dumps(data, separators=(",", ":"), sort_keys=True, ensure_ascii=False)


# ── Agent Certificate Signing ──────────────────────────────────────────────────


def sign_agent_certificate(
    private_key_pem: str,
    certificate_data: dict[str, Any],
) -> str:
    """
    Sign agent certificate data with the Org CA private key.

    Args:
        private_key_pem: Org CA PKCS8 PEM private key.
        certificate_data: Dict of certificate fields (as passed to AgentCertificate).

    Returns:
        Base64url-encoded Ed25519 CA signature.
    """
    payload = canonical_json(certificate_data)
    return sign_payload(private_key_pem, payload)


def sign_token_payload(
    private_key_pem: str,
    token_data: dict[str, Any],
) -> str:
    """
    Sign ExecutionToken payload with the Org CA private key.

    Args:
        private_key_pem: Org CA PKCS8 PEM private key.
        token_data: Dict of token fields (as passed to ExecutionToken.to_signable_payload()).

    Returns:
        Base64url-encoded Ed25519 CA signature.
    """
    payload = canonical_json(token_data)
    return sign_payload(private_key_pem, payload)
