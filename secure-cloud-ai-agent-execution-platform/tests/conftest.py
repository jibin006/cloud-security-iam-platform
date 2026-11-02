from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from secure_agent.audit import AuditLog
from secure_agent.budget import BudgetGuard
from secure_agent.containment import ContainmentController
from secure_agent.identity import IdentityBroker
from secure_agent.mcp_gateway import AUDIENCE, MCPGateway
from secure_agent.policy import ToolPolicy
from secure_agent.workspace import Workspace

SIGNING_SECRET = b"unit-test-only-secret-material-at-least-32-bytes"


@pytest.fixture
def broker() -> IdentityBroker:
    return IdentityBroker(SIGNING_SECRET)


@pytest.fixture
def workspace(tmp_path: Path) -> Workspace:
    (tmp_path / "src").mkdir()
    (tmp_path / "docs").mkdir()
    (tmp_path / "tests").mkdir()
    (tmp_path / "policies").mkdir()
    (tmp_path / "src" / "hello.py").write_text("print('hello')\n", encoding="utf-8")
    (tmp_path / "docs" / "design.md").write_text("design notes\n", encoding="utf-8")
    (tmp_path / "policies" / "tool-policy.json").write_text("{}", encoding="utf-8")
    return Workspace(tmp_path)


@pytest.fixture
def audit(tmp_path: Path) -> AuditLog:
    return AuditLog(tmp_path / "audit" / "events.jsonl")


@pytest.fixture
def containment(audit: AuditLog) -> ContainmentController:
    return ContainmentController(audit)


@pytest.fixture
def policy() -> ToolPolicy:
    return ToolPolicy(
        {
            "version": 1,
            "tools": {
                "read_workspace_file": {
                    "roles": ["agent", "reviewer"],
                    "scopes": ["workspace:read"],
                    "required_arguments": ["path"],
                    "allowed_arguments": ["path"],
                },
                "propose_patch": {
                    "roles": ["engineer"],
                    "scopes": ["workspace:write"],
                    "required_arguments": ["path", "content", "expected_sha256"],
                    "allowed_arguments": ["path", "content", "expected_sha256"],
                },
                "get_runtime_status": {
                    "roles": ["agent", "reviewer", "engineer"],
                    "scopes": ["runtime:read"],
                    "required_arguments": [],
                    "allowed_arguments": [],
                },
            },
        }
    )


@pytest.fixture
def gateway(broker, policy, workspace, audit, containment) -> MCPGateway:
    return MCPGateway(
        broker=broker,
        policy=policy,
        budget=BudgetGuard(max_requests_per_day=5, max_tokens_per_day=100, max_calls_per_minute=3),
        workspace=workspace,
        audit=audit,
        containment=containment,
    )


@pytest.fixture
def issue_agent_token(broker):
    def issue(
        subject: str = "agent-123",
        *,
        roles: set[str] | None = None,
        scopes: set[str] | None = None,
        ttl_seconds: int = 300,
    ) -> str:
        return broker.issue(
            subject,
            audience=AUDIENCE,
            scopes=scopes or {"workspace:read", "runtime:read"},
            roles=roles or {"agent"},
            ttl_seconds=ttl_seconds,
        )
    return issue


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


@pytest.fixture
def json_policy_file(tmp_path: Path) -> Path:
    path = tmp_path / "policy.json"
    path.write_text(json.dumps({"version": 1, "tools": {}}), encoding="utf-8")
    return path
