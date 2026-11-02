"""Subset MCP JSON-RPC stdio adapter for local development.

The bearer token in this adapter's environment is a local test convenience,
not a production isolation pattern. In production, authenticate the router-to-
gateway connection with workload identity / mTLS and keep provider credentials
outside the untrusted agent process.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

from .audit import AuditLog
from .budget import BudgetGuard
from .containment import ContainmentController
from .identity import IdentityBroker
from .mcp_gateway import MCPGateway
from .policy import ToolPolicy
from .workspace import Workspace


def build_gateway() -> tuple[MCPGateway, str]:
    secret = os.environ.get("AGENT_BROKER_SECRET", "")
    token = os.environ.get("AGENT_IDENTITY_TOKEN", "")
    root = os.environ.get("AGENT_WORKSPACE", "./workspace")
    if len(secret.encode()) < 32 or not token:
        raise RuntimeError("Local adapter requires AGENT_BROKER_SECRET and AGENT_IDENTITY_TOKEN")
    audit = AuditLog(os.environ.get("AGENT_AUDIT_PATH", "./audit/events.jsonl"))
    containment = ContainmentController(audit)
    gateway = MCPGateway(
        broker=IdentityBroker(secret.encode()),
        policy=ToolPolicy.from_file(os.environ.get("AGENT_TOOL_POLICY", "policies/tool-policy.json")),
        budget=BudgetGuard(),
        workspace=Workspace(Path(root)),
        audit=audit,
        containment=containment,
    )
    return gateway, token


def serve() -> None:
    gateway, token = build_gateway()
    for line in sys.stdin:
        request: dict = {}
        try:
            request = json.loads(line)
            request_id = request.get("id")
            method = request.get("method")
            if request.get("jsonrpc") != "2.0":
                raise ValueError("JSON-RPC 2.0 is required")
            if method == "notifications/initialized":
                continue
            if method == "initialize":
                result = {
                    "protocolVersion": request.get("params", {}).get("protocolVersion", "2024-11-05"),
                    "capabilities": {"tools": {"listChanged": False}},
                    "serverInfo": {"name": "secure-agent-mcp-gateway", "version": "0.1.0"},
                }
            elif method == "ping":
                result = {}
            elif method == "tools/list":
                result = {"tools": gateway.list_tools()}
            elif method == "tools/call":
                params = request.get("params", {})
                result = gateway.call_tool(
                    token,
                    params.get("name", ""),
                    params.get("arguments", {}),
                    estimated_tokens=int(params.get("estimatedTokens", 0)),
                    request_id=str(request_id),
                )
            else:
                raise ValueError(f"Unsupported MCP method: {method}")
            response = {"jsonrpc": "2.0", "id": request_id, "result": result}
        except Exception as exc:
            response = {
                "jsonrpc": "2.0",
                "id": request.get("id"),
                "error": {"code": -32603, "message": str(exc)},
            }
        sys.stdout.write(json.dumps(response) + "\n")
        sys.stdout.flush()


if __name__ == "__main__":
    serve()
