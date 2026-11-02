from __future__ import annotations

from fastapi.testclient import TestClient

from secure_agent.audit import AuditLog
from secure_agent.budget import BudgetGuard
from secure_agent.containment import ContainmentController
from secure_agent.identity import IdentityBroker
from secure_agent.inference_router_service import AUDIENCE, MAX_OUTPUT_TOKENS, create_app


class FakeBedrock:
    def __init__(self):
        self.calls = []

    def converse(self, **kwargs):
        self.calls.append(kwargs)
        return {
            "output": {"message": {"content": [{"text": "model response"}]}},
            "usage": {"inputTokens": 12, "outputTokens": 7},
            "stopReason": "end_turn",
        }


def make_client(tmp_path, *, model_id="approved-model", budget=None):
    secret = b"test-inference-secret-material-at-least-32-bytes"
    broker = IdentityBroker(secret)
    audit = AuditLog(tmp_path / "router.jsonl")
    containment = ContainmentController(audit)
    bedrock = FakeBedrock()
    app = create_app(
        bedrock_client=bedrock,
        broker=broker,
        budget=budget or BudgetGuard(
            max_requests_per_day=5,
            max_tokens_per_day=5_000,
            max_calls_per_minute=5,
        ),
        containment=containment,
        audit=audit,
        model_id=model_id,
    )
    return TestClient(app), broker, bedrock, containment, audit


def token_for(broker, *, roles=None, scopes=None):
    return broker.issue(
        "orchestrator-1",
        audience=AUDIENCE,
        roles=roles or {"orchestrator"},
        scopes=scopes or {"model:invoke"},
        ttl_seconds=120,
    )


def test_router_invokes_only_server_selected_model_and_caps_output(tmp_path):
    client, broker, bedrock, _, audit = make_client(tmp_path)
    token = token_for(broker)
    response = client.post(
        "/v1/invoke",
        headers={"Authorization": f"Bearer {token}"},
        json={"prompt": "Summarise this untrusted request."},
    )
    assert response.status_code == 200
    assert response.json()["model"] == "approved-model"
    assert bedrock.calls[0]["modelId"] == "approved-model"
    assert bedrock.calls[0]["inferenceConfig"]["maxTokens"] == MAX_OUTPUT_TOKENS
    assert audit.verify()[0]["decision"] == "allow"


def test_caller_cannot_select_model_or_raise_output_budget(tmp_path):
    client, broker, bedrock, _, _ = make_client(tmp_path)
    token = token_for(broker)
    response = client.post(
        "/v1/invoke",
        headers={"Authorization": f"Bearer {token}"},
        json={
            "prompt": "hello",
            "modelId": "attacker-selected-model",
            "maxTokens": 1000000,
        },
    )
    assert response.status_code == 422
    assert bedrock.calls == []


def test_router_requires_model_invoke_scope(tmp_path):
    client, broker, _, _, _ = make_client(tmp_path)
    token = token_for(broker, scopes={"workspace:read"})
    response = client.post(
        "/v1/invoke",
        headers={"Authorization": f"Bearer {token}"},
        json={"prompt": "hello"},
    )
    assert response.status_code == 403


def test_router_requires_orchestrator_role(tmp_path):
    client, broker, _, _, _ = make_client(tmp_path)
    token = token_for(broker, roles={"agent"})
    response = client.post(
        "/v1/invoke",
        headers={"Authorization": f"Bearer {token}"},
        json={"prompt": "hello"},
    )
    assert response.status_code == 403


def test_router_denies_contained_identity(tmp_path):
    client, broker, _, containment, _ = make_client(tmp_path)
    token = token_for(broker)
    containment.suspend("orchestrator-1", "policy abuse", "contain-1")
    response = client.post(
        "/v1/invoke",
        headers={"Authorization": f"Bearer {token}"},
        json={"prompt": "hello"},
    )
    assert response.status_code == 403


def test_router_rejects_oversized_prompt_before_provider_call(tmp_path):
    client, broker, bedrock, _, _ = make_client(tmp_path)
    token = token_for(broker)
    response = client.post(
        "/v1/invoke",
        headers={"Authorization": f"Bearer {token}"},
        json={"prompt": "x" * 16_001},
    )
    assert response.status_code == 422
    assert bedrock.calls == []


def test_router_requires_bearer_identity(tmp_path):
    client, _, bedrock, _, _ = make_client(tmp_path)
    response = client.post("/v1/invoke", json={"prompt": "hello"})
    assert response.status_code == 401
    assert bedrock.calls == []
