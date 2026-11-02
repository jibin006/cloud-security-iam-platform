from __future__ import annotations

import base64
import json

import pytest

from secure_agent.identity import IdentityBroker, IdentityError


def test_identity_round_trip_and_scope_claims(broker):
    token = broker.issue(
        "worker-a",
        audience="gateway",
        scopes={"workspace:read", "runtime:read"},
        roles={"agent"},
        ttl_seconds=120,
    )
    identity = broker.verify(token, audience="gateway", required_scopes={"workspace:read"})
    assert identity.subject == "worker-a"
    assert identity.roles == {"agent"}
    assert "workspace:read" in identity.scopes


def test_wrong_audience_is_rejected(broker):
    token = broker.issue("worker-a", audience="gateway", scopes={"a"}, roles={"agent"})
    with pytest.raises(IdentityError, match="audience"):
        broker.verify(token, audience="other")


def test_missing_scope_is_rejected(broker):
    token = broker.issue("worker-a", audience="gateway", scopes={"workspace:read"}, roles={"agent"})
    with pytest.raises(IdentityError, match="scope"):
        broker.verify(token, audience="gateway", required_scopes={"workspace:write"})


def test_tampered_signature_is_rejected(broker):
    token = broker.issue("worker-a", audience="gateway", scopes={"a"}, roles={"agent"})
    parts = token.split(".")
    parts[2] = base64.urlsafe_b64encode(b"forged-signature").decode().rstrip("=")
    with pytest.raises(IdentityError, match="signature"):
        broker.verify(".".join(parts), audience="gateway")


def test_wrong_signing_key_is_rejected():
    issuer = IdentityBroker(b"a" * 32)
    verifier = IdentityBroker(b"b" * 32)
    token = issuer.issue("worker-a", audience="gateway", scopes={"a"}, roles={"agent"})
    with pytest.raises(IdentityError, match="signature"):
        verifier.verify(token, audience="gateway")


def test_expired_token_is_rejected():
    now = [1_800_000_000.0]
    broker = IdentityBroker(b"c" * 32, clock=lambda: now[0])
    token = broker.issue("worker-a", audience="gateway", scopes={"a"}, roles={"agent"}, ttl_seconds=30)
    now[0] += 31
    with pytest.raises(IdentityError, match="expired"):
        broker.verify(token, audience="gateway")


def test_token_lifetime_cannot_exceed_maximum(broker):
    with pytest.raises(ValueError, match="lifetime"):
        broker.issue("worker-a", audience="gateway", scopes={"a"}, roles={"agent"}, ttl_seconds=901)


def test_revoked_token_is_rejected(broker):
    token = broker.issue("worker-a", audience="gateway", scopes={"a"}, roles={"agent"})
    broker.revoke(token, audience="gateway")
    with pytest.raises(IdentityError, match="revoked"):
        broker.verify(token, audience="gateway")


def test_non_string_token_is_rejected(broker):
    with pytest.raises(IdentityError, match="Malformed"):
        broker.verify(None, audience="gateway")


def test_algorithm_confusion_header_is_rejected(broker):
    token = broker.issue("worker-a", audience="gateway", scopes={"a"}, roles={"agent"})
    header, payload, signature = token.split(".")
    raw = json.dumps({"alg": "none", "typ": "SAT"}).encode()
    encoded = base64.urlsafe_b64encode(raw).decode().rstrip("=")
    # The signature no longer matches, so either signature or header validation must reject.
    with pytest.raises(IdentityError):
        broker.verify(f"{encoded}.{payload}.{signature}", audience="gateway")
