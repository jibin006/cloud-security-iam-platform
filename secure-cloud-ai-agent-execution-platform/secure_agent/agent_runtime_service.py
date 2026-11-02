"""Untrusted model-runtime adapter.

This service forwards a tool proposal from an upstream model adapter to the
MCP gateway. It does not hold cloud credentials, execute tools, mint identity
tokens, or decide authorization. It forwards the short-lived identity token
supplied by the trusted platform caller.
"""

from __future__ import annotations

import os
import uuid
from typing import Any

import httpx
from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel, ConfigDict, Field

from .stdio_mcp_server import PROTOCOL_VERSION, PROTOCOL_VERSION_META_KEY

GATEWAY_URL = os.environ.get(
    "MCP_GATEWAY_URL",
    "http://mcp-gateway.agent-platform.svc.cluster.local:8080/mcp",
)


class ToolProposal(BaseModel):
    model_config = ConfigDict(extra="forbid")
    tool_name: str = Field(min_length=1, max_length=128)
    arguments: dict[str, Any]


app = FastAPI(
    title="Untrusted Agent Runtime Adapter",
    version="0.1.0",
    docs_url=None,
    redoc_url=None,
)


@app.get("/healthz")
async def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/v1/tools")
async def list_tools(authorization: str = Header(default="")) -> dict[str, Any]:
    return await _forward(
        authorization=authorization,
        method="tools/list",
        params={"_meta": _request_meta()},
    )


@app.post("/v1/proposals")
async def submit_proposal(
    proposal: ToolProposal,
    authorization: str = Header(default=""),
) -> dict[str, Any]:
    return await _forward(
        authorization=authorization,
        method="tools/call",
        params={
            "_meta": _request_meta(),
            "name": proposal.tool_name,
            "arguments": proposal.arguments,
        },
        tool_name=proposal.tool_name,
    )


def _request_meta() -> dict[str, Any]:
    return {
        PROTOCOL_VERSION_META_KEY: PROTOCOL_VERSION,
        "io.modelcontextprotocol/clientInfo": {
            "name": "secure-agent-runtime-adapter",
            "version": "0.1.0",
        },
    }


async def _forward(
    *,
    authorization: str,
    method: str,
    params: dict[str, Any],
    tool_name: str | None = None,
) -> dict[str, Any]:
    scheme, _, token = authorization.partition(" ")
    if scheme.lower() != "bearer" or not token:
        raise HTTPException(status_code=401, detail="Short-lived agent bearer identity required")

    request_id = str(uuid.uuid4())
    headers = {
        "Authorization": authorization,
        "Content-Type": "application/json",
        "MCP-Protocol-Version": PROTOCOL_VERSION,
        "Mcp-Method": method,
    }
    if tool_name:
        headers["Mcp-Name"] = tool_name

    body = {
        "jsonrpc": "2.0",
        "id": request_id,
        "method": method,
        "params": params,
    }

    try:
        async with httpx.AsyncClient(timeout=5.0, follow_redirects=False) as client:
            response = await client.post(GATEWAY_URL, headers=headers, json=body)
    except httpx.TimeoutException as exc:
        raise HTTPException(status_code=504, detail="MCP gateway request timed out") from exc
    except httpx.RequestError as exc:
        raise HTTPException(status_code=502, detail="MCP gateway unavailable") from exc

    if response.status_code in {401, 403}:
        raise HTTPException(status_code=response.status_code, detail="MCP gateway denied identity or operation")
    if response.status_code >= 500:
        raise HTTPException(status_code=502, detail="MCP gateway failed")
    if response.status_code >= 400:
        raise HTTPException(status_code=400, detail="MCP gateway rejected malformed request")
    try:
        envelope = response.json()
    except ValueError as exc:
        raise HTTPException(status_code=502, detail="MCP gateway returned invalid JSON") from exc
    if "error" in envelope:
        raise HTTPException(status_code=502, detail="MCP gateway returned a JSON-RPC error")
    return envelope.get("result", {})
