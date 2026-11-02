"""Short-lived scoped agent identity tokens for the local reference implementation."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time
import uuid
from dataclasses import dataclass
from typing import Callable


class IdentityError(ValueError):
    """Raised when an agent identity cannot be authenticated or authorized."""


@dataclass(frozen=True)
class AgentIdentity:
    issuer: str
    subject: str
    audience: str
    scopes: frozenset[str]
    roles: frozenset[str]
    issued_at: int
    expires_at: int
    token_id: str


def _b64encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _b64decode(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


class IdentityBroker:
    """Issue and verify HMAC tokens; use KMS-backed asymmetric signing in production."""

    def __init__(
        self,
        secret: bytes,
        *,
        issuer: str = "secure-agent-identity-broker",
        max_ttl_seconds: int = 900,
        clock: Callable[[], float] = time.time,
    ) -> None:
        if len(secret) < 32:
            raise ValueError("Identity signing secret must contain at least 32 bytes")
        if max_ttl_seconds < 1:
            raise ValueError("max_ttl_seconds must be positive")
        self._secret = secret
        self.issuer = issuer
        self.max_ttl_seconds = max_ttl_seconds
        self._clock = clock
        self._revoked: set[str] = set()

    def issue(
        self,
        subject: str,
        *,
        audience: str,
        scopes: set[str] | frozenset[str],
        roles: set[str] | frozenset[str],
        ttl_seconds: int = 300,
    ) -> str:
        if not subject or not audience:
            raise ValueError("subject and audience are required")
        if ttl_seconds < 1 or ttl_seconds > self.max_ttl_seconds:
            raise ValueError("Requested token lifetime is outside the allowed range")
        if not scopes or not all(isinstance(item, str) and item for item in scopes):
            raise ValueError("At least one valid scope is required")
        if not roles or not all(isinstance(item, str) and item for item in roles):
            raise ValueError("At least one valid role is required")

        now = int(self._clock())
        header = {"alg": "HS256", "typ": "SAT"}
        payload = {
            "iss": self.issuer,
            "sub": subject,
            "aud": audience,
            "scope": sorted(scopes),
            "roles": sorted(roles),
            "iat": now,
            "exp": now + ttl_seconds,
            "jti": str(uuid.uuid4()),
        }
        header_part = _b64encode(json.dumps(header, sort_keys=True).encode())
        payload_part = _b64encode(json.dumps(payload, sort_keys=True).encode())
        signing_input = f"{header_part}.{payload_part}"
        signature = hmac.new(self._secret, signing_input.encode(), hashlib.sha256).digest()
        return f"{signing_input}.{_b64encode(signature)}"

    def verify(
        self,
        token: str,
        *,
        audience: str,
        required_scopes: set[str] | frozenset[str] = frozenset(),
    ) -> AgentIdentity:
        try:
            header_part, payload_part, signature_part = token.split(".")
            signing_input = f"{header_part}.{payload_part}"
            supplied_signature = _b64decode(signature_part)
            expected_signature = hmac.new(
                self._secret, signing_input.encode(), hashlib.sha256
            ).digest()
            if not hmac.compare_digest(supplied_signature, expected_signature):
                raise IdentityError("Invalid token signature")
            header = json.loads(_b64decode(header_part))
            payload = json.loads(_b64decode(payload_part))
        except IdentityError:
            raise
        except (ValueError, TypeError, json.JSONDecodeError) as exc:
            raise IdentityError("Malformed agent identity token") from exc

        if header != {"alg": "HS256", "typ": "SAT"}:
            raise IdentityError("Unsupported identity token header")
        if payload.get("iss") != self.issuer:
            raise IdentityError("Untrusted identity issuer")
        if payload.get("aud") != audience:
            raise IdentityError("Identity audience mismatch")

        now = int(self._clock())
        issued_at = payload.get("iat")
        expires_at = payload.get("exp")
        subject = payload.get("sub")
        token_id = payload.get("jti")
        if not isinstance(issued_at, int) or not isinstance(expires_at, int):
            raise IdentityError("Invalid token time claims")
        if not isinstance(subject, str) or not subject or not isinstance(token_id, str):
            raise IdentityError("Invalid token subject or token identifier")
        if issued_at > now + 30:
            raise IdentityError("Token was issued in the future")
        if expires_at <= now:
            raise IdentityError("Agent identity token has expired")
        if expires_at - issued_at > self.max_ttl_seconds:
            raise IdentityError("Token lifetime exceeds the configured maximum")
        if token_id in self._revoked:
            raise IdentityError("Agent identity token has been revoked")

        scopes = payload.get("scope")
        roles = payload.get("roles")
        if not isinstance(scopes, list) or not all(isinstance(x, str) for x in scopes):
            raise IdentityError("Invalid identity scopes")
        if not isinstance(roles, list) or not all(isinstance(x, str) for x in roles):
            raise IdentityError("Invalid identity roles")
        if not set(required_scopes).issubset(scopes):
            raise IdentityError("Agent identity lacks required scope")

        return AgentIdentity(
            issuer=self.issuer,
            subject=subject,
            audience=audience,
            scopes=frozenset(scopes),
            roles=frozenset(roles),
            issued_at=issued_at,
            expires_at=expires_at,
            token_id=token_id,
        )

    def revoke(self, token: str, *, audience: str) -> None:
        identity = self.verify(token, audience=audience)
        self._revoked.add(identity.token_id)
