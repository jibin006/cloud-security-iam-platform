"""Bedrock inference router with server-owned model selection and workload identity.

The model identifier and output-token ceiling are deployment configuration;
callers cannot select another model or raise the output budget. The upstream
agent receives only the response and a short-lived identity, not AWS credentials.
"""

from __future__ import annotations

import os
import uuid
from typing import Any

from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel, ConfigDict, Field

from .audit import AuditLog
from .budget import BudgetGuard, BudgetExceeded
from .containment import ContainmentController
from .identity import IdentityBroker, IdentityError

AUDIENCE = "secure-agent-inference-router"
MAX_PROMPT_CHARS = 16_000
MAX_OUTPUT_TOKENS = 1024


class InferenceRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    prompt: str = Field(min_length=1, max_length=MAX_PROMPT_CHARS)


def create_app(
    *,
    bedrock_client: Any | None = None,
    broker: IdentityBroker | None = None,
    budget: BudgetGuard | None = None,
    containment: ContainmentController | None = None,
    audit: AuditLog | None = None,
    model_id: str | None = None,
) -> FastAPI:
    app = FastAPI(
        title="Secure Agent Inference Router",
        version="0.1.0",
        docs_url=None,
        redoc_url=None,
    )
    state: dict[str, Any] = {
        "client": bedrock_client,
        "broker": broker,
        "budget": budget,
        "containment": containment,
        "audit": audit,
        "model_id": model_id,
    }

    def dependencies() -> tuple[Any, IdentityBroker, BudgetGuard, ContainmentController, AuditLog, str]:
        if state["broker"] is None:
            secret = os.environ.get("AGENT_BROKER_SECRET", "")
            if len(secret.encode()) < 32:
                raise RuntimeError("AGENT_BROKER_SECRET must contain at least 32 bytes")
            state["broker"] = IdentityBroker(secret.encode())
        if state["client"] is None:
            import boto3

            state["client"] = boto3.client(
                "bedrock-runtime",
                region_name=os.environ.get("AWS_REGION", "us-east-1"),
            )
        if state["budget"] is None:
            state["budget"] = BudgetGuard(
                max_requests_per_day=100,
                max_tokens_per_day=100_000,
                max_calls_per_minute=10,
            )
        if state["audit"] is None:
            state["audit"] = AuditLog(os.environ.get("ROUTER_AUDIT_PATH", "./audit/router.jsonl"))
        if state["containment"] is None:
            state["containment"] = ContainmentController(state["audit"])
        selected_model = state["model_id"] or os.environ.get("BEDROCK_MODEL_ID", "")
        if not selected_model:
            raise RuntimeError("BEDROCK_MODEL_ID must be configured by the platform operator")
        return (
            state["client"],
            state["broker"],
            state["budget"],
            state["containment"],
            state["audit"],
            selected_model,
        )

    @app.get("/healthz")
    async def health() -> dict[str, str]:
        return {"status": "ok"}

    @app.post("/v1/invoke")
    async def invoke(
        request: InferenceRequest,
        authorization: str = Header(default=""),
    ) -> dict[str, Any]:
        request_id = str(uuid.uuid4())
        scheme, _, token = authorization.partition(" ")
        if scheme.lower() != "bearer" or not token:
            raise HTTPException(status_code=401, detail="Short-lived agent identity required")

        try:
            client, token_broker, request_budget, kill_switch, event_log, selected_model = dependencies()
            identity = token_broker.verify(
                token,
                audience=AUDIENCE,
                required_scopes={"model:invoke"},
            )
            if "orchestrator" not in identity.roles:
                raise IdentityError("Identity is not authorized as an inference orchestrator")
            if kill_switch.is_suspended(identity.subject):
                raise IdentityError("Inference identity is suspended")

            # Reserve the server-estimated input and maximum output budget before
            # making the provider call. The caller cannot set a model or token cap.
            estimated_input = max(1, (len(request.prompt.encode("utf-8")) + 3) // 4)
            request_budget.reserve(
                identity.subject,
                estimated_tokens=estimated_input + MAX_OUTPUT_TOKENS,
            )

            response = client.converse(
                modelId=selected_model,
                messages=[
                    {
                        "role": "user",
                        "content": [{"text": request.prompt}],
                    }
                ],
                inferenceConfig={
                    "maxTokens": MAX_OUTPUT_TOKENS,
                    "temperature": 0.2,
                },
            )
            message = response.get("output", {}).get("message", {})
            content = message.get("content", [])
            usage = response.get("usage", {})
            event_log.append(
                subject=identity.subject,
                action="bedrock.converse",
                decision="allow",
                detail=(
                    f"model={selected_model};input_tokens={usage.get('inputTokens', 0)};"
                    f"output_tokens={usage.get('outputTokens', 0)}"
                ),
                request_id=request_id,
            )
            return {
                "request_id": request_id,
                "model": selected_model,
                "content": content,
                "usage": usage,
                "stop_reason": response.get("stopReason"),
            }
        except IdentityError as exc:
            raise HTTPException(status_code=403, detail=str(exc)) from exc
        except BudgetExceeded as exc:
            raise HTTPException(status_code=429, detail=str(exc)) from exc
        except RuntimeError as exc:
            raise HTTPException(status_code=503, detail=str(exc)) from exc
        except Exception as exc:
            # Do not return provider exception contents to the caller; they may
            # contain request IDs, account identifiers or provider metadata.
            try:
                if state["audit"] is not None:
                    state["audit"].append(
                        subject="inference-router",
                        action="bedrock.converse",
                        decision="deny",
                        detail=f"provider_error={type(exc).__name__}",
                        request_id=request_id,
                    )
            finally:
                raise HTTPException(status_code=502, detail="Inference provider request failed") from exc

    return app


app = create_app()
