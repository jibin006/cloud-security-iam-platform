"""MCP Streamable HTTP request handler (protocol subset 2026-07-28).

This server implements POST /mcp with required MCP-Protocol-Version and
Mcp-Method headers, plus Mcp-Name for tools/call. It is not a full MCP SDK
implementation: subscriptions, MRTR, OAuth discovery and extensions are out
of scope. The bearer token is a platform-issued short-lived identity token.
"""

from __future__ import annotations

import json
from typing import Any

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from .identity import IdentityError
from .mcp_gateway import MCPGateway
from .policy import AuthorizationError
from .stdio_mcp_server import (
    PROTOCOL_VERSION,
    PROTOCOL_VERSION_META_KEY,
    SERVER_INFO_META_KEY,
    build_gateway_core,
    discover_result,
    handle_request,
)


def create_app(gateway: MCPGateway | None = None) -> FastAPI:
    app = FastAPI(
        title="Secure Agent MCP Gateway",
        version="0.1.0",
        docs_url=None,
        redoc_url=None,
    )
    state: dict[str, MCPGateway | None] = {"gateway": gateway}

    def get_gateway() -> MCPGateway:
        if state["gateway"] is None:
            state["gateway"] = build_gateway_core()
        return state["gateway"]  # type: ignore[return-value]

    @app.get("/healthz")
    async def health() -> dict[str, str]:
        return {"status": "ok"}

    @app.post("/mcp")
    async def mcp(request: Request) -> JSONResponse:
        request_id: Any = None
        try:
            protocol_header = request.headers.get("mcp-protocol-version")
            method_header = request.headers.get("mcp-method")
            if not method_header:
                raise ValueError("Mcp-Method header is required")

            body = await request.json()
            if not isinstance(body, dict) or body.get("jsonrpc") != "2.0":
                raise ValueError("JSON-RPC 2.0 request object is required")
            request_id = body.get("id")
            if request_id is None:
                raise ValueError("Request id is required; notifications are not supported")

            method = body.get("method")
            if method != method_header:
                raise ValueError("Mcp-Method header does not match JSON-RPC method")

            params = body.get("params", {})
            if not isinstance(params, dict):
                raise ValueError("params must be an object")

            if method == "server/discover":
                if protocol_header and protocol_header != PROTOCOL_VERSION:
                    raise ValueError(f"Unsupported protocol version: {protocol_header}")
                result = discover_result()
            else:
                if protocol_header != PROTOCOL_VERSION:
                    raise ValueError(
                        f"MCP-Protocol-Version must be {PROTOCOL_VERSION}"
                    )
                meta = params.get("_meta")
                if not isinstance(meta, dict) or meta.get(PROTOCOL_VERSION_META_KEY) != PROTOCOL_VERSION:
                    raise ValueError("params._meta must identify the supported protocol version")

                if method == "tools/call":
                    name = params.get("name")
                    name_header = request.headers.get("mcp-name")
                    if not name_header or name_header != name:
                        raise ValueError("Mcp-Name header must match params.name")

                auth = request.headers.get("authorization", "")
                scheme, _, token = auth.partition(" ")
                if scheme.lower() != "bearer" or not token:
                    return JSONResponse(
                        status_code=401,
                        content={
                            "jsonrpc": "2.0",
                            "id": request_id,
                            "error": {"code": -32001, "message": "Bearer identity token required"},
                        },
                    )
                result_response = handle_request(get_gateway(), token, body)
                if result_response is None:
                    return JSONResponse(status_code=204, content=None)
                return JSONResponse(status_code=200, content=result_response)

            result["_meta"] = {
                SERVER_INFO_META_KEY: discover_result()["serverInfo"]
            }
            return JSONResponse(
                status_code=200,
                content={"jsonrpc": "2.0", "id": request_id, "result": result},
            )
        except (json.JSONDecodeError, ValueError) as exc:
            return JSONResponse(
                status_code=400,
                content={
                    "jsonrpc": "2.0",
                    "id": request_id,
                    "error": {"code": -32600, "message": str(exc)},
                },
            )
        except IdentityError as exc:
            return JSONResponse(
                status_code=401,
                content={
                    "jsonrpc": "2.0",
                    "id": request_id,
                    "error": {"code": -32001, "message": str(exc)},
                },
            )
        except AuthorizationError as exc:
            return JSONResponse(
                status_code=403,
                content={
                    "jsonrpc": "2.0",
                    "id": request_id,
                    "error": {"code": -32003, "message": str(exc)},
                },
            )

    return app


app = create_app()
