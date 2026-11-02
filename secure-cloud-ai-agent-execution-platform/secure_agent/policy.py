"""Server-side policy decisions for MCP tool authorization."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .identity import AgentIdentity


class AuthorizationError(PermissionError):
    """Raised when an identity cannot invoke a tool or provide its arguments."""


class ToolPolicy:
    def __init__(self, rules: dict[str, Any]) -> None:
        if rules.get("version") != 1 or not isinstance(rules.get("tools"), dict):
            raise ValueError("Tool policy must contain version=1 and a tools mapping")
        self._rules = rules["tools"]

    @classmethod
    def from_file(cls, path: str | Path) -> ToolPolicy:
        with Path(path).open(encoding="utf-8") as handle:
            return cls(json.load(handle))

    def authorize(self, identity: AgentIdentity, tool_name: str, arguments: dict) -> None:
        if not isinstance(arguments, dict):
            raise AuthorizationError("Tool arguments must be a JSON object")
        rule = self._rules.get(tool_name)
        if not isinstance(rule, dict):
            raise AuthorizationError(f"Tool is not registered: {tool_name}")

        allowed_roles = set(rule.get("roles", []))
        required_scopes = set(rule.get("scopes", []))
        if not identity.roles.intersection(allowed_roles):
            raise AuthorizationError(f"Role is not allowed to invoke {tool_name}")
        if not required_scopes.issubset(identity.scopes):
            raise AuthorizationError(f"Required scopes missing for {tool_name}")

        required_arguments = set(rule.get("required_arguments", []))
        if not required_arguments.issubset(arguments):
            missing = sorted(required_arguments - set(arguments))
            raise AuthorizationError(f"Missing required tool arguments: {missing}")

        allowed_arguments = set(rule.get("allowed_arguments", []))
        unexpected = set(arguments) - allowed_arguments
        if unexpected:
            raise AuthorizationError(f"Unexpected tool arguments: {sorted(unexpected)}")
