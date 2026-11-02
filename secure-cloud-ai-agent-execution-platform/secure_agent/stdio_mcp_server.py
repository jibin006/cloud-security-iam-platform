"""MCP stdio development transport for protocol version 2026-07-28.

This is a deliberately small protocol subset: server/discover, tools/list and
tools/call. It does not claim full MCP feature coverage. The bearer token in
this adapter is a local-development convenience, not a production pattern.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Any

from .audit import AuditLog
from .budget import BudgetGuard
from .containment import ContainmentController
from .identity import IdentityBroker
from .mcp_gateway import MCPGateway
from .policy import ToolPolicy
from .workspace import Workspace

PROTOCOL_VERSION = "2026-07-28"
PROTOCOL_VERSION_META_KEY = "io.modelcontextprotocol/protocolVersion"
CLIENT_INFO_META_KEY = "io.modelcontextprotocol/clientInfo"
SERVER_INFO_META_KEY = "io.modelcontextprotocol/serverInfo"


class MCPProtocolError(ValueError):
    """Raised for unsupported protocol versions or malformed MCP messages."""


def build_gateway_core() -> MCPGateway:
    secret = os.environ.get("AGENT_BROKER_SECRET", "")
    root = os.environ.get("AGENT_WORKSPACE", "./workspace")
    if len(secret.encode()) < 32:
        raise RuntimeError("Gateway requires AGENT_BROKER_SECRET with at least 32 bytes")
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
    return gateway


def build_gateway() -> tuple[MCPGateway, str]:
    token = os.environ.get("AGENT_IDENTITY_TOKEN", "")
    if not token:
        raise RuntimeError("Local stdio adapter requires AGENT_IDENTITY_TOKEN")
    return build_gateway_core(), token


def discover_result() -> dict[str, Any]:
    return {
        "resultType": "complete",
        "protocolVersions": [PROTOCOL_VERSION],
        "capabilities": {"tools": {"listChanged": False}},
        "serverInfo": {
            "name": "secure-agent-mcp-gateway",
            "version": "0.1.0",
        },
    }


def _validate_request_meta(params: dict[str, Any]) -> None:
    meta = params.get("_meta")
    if not isinstance(meta, dict):
        raise MCPProtocolError("Every request must include params._meta")
    version = meta.get(PROTOCOL_VERSION_META_KEY)
    if version != PROTOCOL_VERSION:
        raise MCPProtocolError(
            f"Unsupported MCP protocol version: {version!r}; supported: {PROTOCOL_VERSION}"
        )


def handle_request(
    gateway: MCPGateway,
    token: str,
    request: dict[str, Any],
) -> dict[str, Any] | None:
    """Handle one JSON-RPC request. Notifications are not supported by this subset."""
    if not isinstance(request, dict) or request.get("jsonrpc") != "2.0":
        raise MCPProtocolError("JSON-RPC 2.0 request object is required")
    request_id = request.get("id")
    if request_id is None:
        # MCP notifications are not implemented by this minimal tools-only server.
        return None

    method = request.get("method")
    params = request.get("params", {})
    if not isinstance(params, dict):
        raise MCPProtocolError("JSON-RPC params must be an object")

    if method == "server/discover":
        # Discovery may be sent before version selection. If supplied, reject
        # unsupported versions rather than silently negotiating them.
        meta = params.get("_meta", {})
        if meta and meta.get(PROTOCOL_VERSION_META_KEY) != PROTOCOL_VERSION:
            raise MCPProtocolError("Unsupported MCP protocol version")
        result = discover_result()
    else:
        _validate_request_meta(params)
        if method == "tools/list":
            result = {
                "resultType": "complete",
                "tools": gateway.list_tools(token, request_id=str(request_id)),
                "ttlMs": 30_000,
                "cacheScope": "private",
            }
        elif method == "tools/call":
            name = params.get("name")
            arguments = params.get("arguments", {})
            if not isinstance(name, str) or not name:
                raise MCPProtocolError("tools/call requires a tool name")
            if not isinstance(arguments, dict):
                raise MCPProtocolError("tools/call arguments must be an object")
            result = {
                "resultType": "complete",
                **gateway.call_tool(
                    token,
                    name,
                    arguments,
                    request_id=str(request_id),
                ),
            }
        else:
            return {
                "jsonrpc": "2.0",
                "id": request_id,
                "error": {"code": -32601, "message": f"Method not found: {method}"},
            }

    result["_meta"] = {SERVER_INFO_META_KEY: discover_result()["serverInfo"]}
    return {"jsonrpc": "2.0", "id": request_id, "result": result}


def serve() -> None:
    gateway, token = build_gateway()
    for line in sys.stdin:
        request: dict[str, Any] = {}
        try:
            request = json.loads(line)
            response = handle_request(gateway, token, request)
            if response is None:
                continue
        except json.JSONDecodeError:
            response = {
                "jsonrpc": "2.0",
                "id": None,
                "error": {"code": -32700, "message": "Parse error"},
            }
        except MCPProtocolError as exc:
            response = {
                "jsonrpc": "2.0",
                "id": request.get("id"),
                "error": {"code": -32600, "message": str(exc)},
            }
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
