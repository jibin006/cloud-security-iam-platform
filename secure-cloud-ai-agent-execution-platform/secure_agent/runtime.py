"""Minimal agent execution harness; model output never grants authority."""

from __future__ import annotations

from typing import Any

from .mcp_gateway import MCPGateway


class AgentRuntime:
    """Accept proposed tool calls and delegate every action to the policy gateway."""

    def __init__(self, gateway: MCPGateway, identity_token: str) -> None:
        self._gateway = gateway
        self._identity_token = identity_token

    def handle_proposed_tool_call(
        self,
        *,
        tool_name: str,
        arguments: dict[str, Any],
        estimated_tokens: int = 0,
    ) -> dict[str, Any]:
        # The prompt or model response is intentionally not an input to authorization.
        return self._gateway.call_tool(
            self._identity_token,
            tool_name,
            arguments,
            estimated_tokens=estimated_tokens,
        )
