"""MCP tool registry and authorization gateway.

This module implements the security core behind tools/list and tools/call.
The local stdio adapter is for development only; production transport must
authenticate service identity without exposing a reusable credential to the agent.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from typing import Any

from .audit import AuditLog
from .budget import BudgetGuard, BudgetExceeded
from .containment import ContainmentController
from .identity import IdentityBroker, IdentityError
from .policy import AuthorizationError, ToolPolicy
from .workspace import Workspace, WorkspaceDenied

AUDIENCE = "secure-agent-execution-platform"


class MCPGateway:
    def __init__(
        self,
        *,
        broker: IdentityBroker,
        policy: ToolPolicy,
        budget: BudgetGuard,
        workspace: Workspace,
        audit: AuditLog,
        containment: ContainmentController,
    ) -> None:
        self._broker = broker
        self._policy = policy
        self._budget = budget
        self._workspace = workspace
        self._audit = audit
        self._containment = containment

    def list_tools(self) -> list[dict[str, Any]]:
        return [
            {
                "name": "read_workspace_file",
                "description": "Read a UTF-8 file from approved workspace read roots.",
                "inputSchema": {
                    "type": "object",
                    "properties": {"path": {"type": "string"}},
                    "required": ["path"],
                    "additionalProperties": False,
                },
            },
            {
                "name": "propose_patch",
                "description": "Propose a guarded patch to an existing file under src/ only.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "path": {"type": "string"},
                        "content": {"type": "string"},
                        "expected_sha256": {"type": "string", "pattern": "^[a-f0-9]{64}$"},
                    },
                    "required": ["path", "content", "expected_sha256"],
                    "additionalProperties": False,
                },
            },
            {
                "name": "get_runtime_status",
                "description": "Return non-secret runtime budget and containment status.",
                "inputSchema": {"type": "object", "properties": {}, "additionalProperties": False},
            },
        ]

    def call_tool(
        self,
        token: str,
        tool_name: str,
        arguments: dict[str, Any],
        *,
        estimated_tokens: int = 0,
        request_id: str | None = None,
    ) -> dict[str, Any]:
        call_id = request_id or str(uuid.uuid4())
        subject = "unverified"
        try:
            identity = self._broker.verify(token, audience=AUDIENCE)
            subject = identity.subject
            if self._containment.is_suspended(subject):
                raise AuthorizationError("Agent identity is suspended")
            self._policy.authorize(identity, tool_name, arguments)
            self._budget.reserve(subject, estimated_tokens)
            result = self._execute(tool_name, arguments, identity.subject)
            self._audit.append(
                subject=subject,
                action=f"mcp.{tool_name}",
                decision="allow",
                detail="tool invocation completed",
                request_id=call_id,
            )
            return {"content": [{"type": "text", "text": result}], "isError": False}
        except (IdentityError, AuthorizationError, BudgetExceeded, WorkspaceDenied, ValueError) as exc:
            self._audit.append(
                subject=subject,
                action=f"mcp.{tool_name}",
                decision="deny",
                detail=f"{type(exc).__name__}: {exc}",
                request_id=call_id,
            )
            return {
                "content": [{"type": "text", "text": f"Denied: {exc}"}],
                "isError": True,
            }

    def _execute(self, tool_name: str, arguments: dict[str, Any], subject: str) -> str:
        if tool_name == "read_workspace_file":
            return self._workspace.read_file(arguments["path"])
        if tool_name == "propose_patch":
            new_hash = self._workspace.propose_patch(
                arguments["path"],
                arguments["content"],
                arguments["expected_sha256"],
            )
            return json.dumps({"status": "patch_written", "sha256": new_hash})
        if tool_name == "get_runtime_status":
            return json.dumps(
                {
                    "subject": subject,
                    "suspended": self._containment.is_suspended(subject),
                    "budget": self._budget.snapshot(subject),
                },
                sort_keys=True,
            )
        raise AuthorizationError(f"Tool is not implemented: {tool_name}")

    def audit_integrity(self) -> dict[str, Any]:
        records = self._audit.verify()
        digest = records[-1]["hash"] if records else hashlib.sha256(b"").hexdigest()
        return {"valid": True, "events": len(records), "head": digest}
