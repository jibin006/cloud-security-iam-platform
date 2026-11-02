from __future__ import annotations

import hashlib


def text(result: dict) -> str:
    return result["content"][0]["text"]


def test_gateway_allows_scoped_workspace_read(gateway, issue_agent_token):
    token = issue_agent_token()
    result = gateway.call_tool(token, "read_workspace_file", {"path": "src/hello.py"})
    assert result["isError"] is False
    assert "print('hello')" in text(result)


def test_gateway_denies_unapproved_tool(gateway, issue_agent_token):
    result = gateway.call_tool(issue_agent_token(), "run_shell", {"command": "id"})
    assert result["isError"] is True
    assert "not registered" in text(result)


def test_gateway_denies_unknown_argument(gateway, issue_agent_token):
    result = gateway.call_tool(
        issue_agent_token(),
        "read_workspace_file",
        {"path": "src/hello.py", "shell": "true"},
    )
    assert result["isError"] is True
    assert "Unexpected" in text(result)


def test_gateway_denies_write_to_identity_without_engineer_role(gateway, issue_agent_token):
    result = gateway.call_tool(
        issue_agent_token(),
        "propose_patch",
        {"path": "src/hello.py", "content": "print('bad')", "expected_sha256": "0" * 64},
    )
    assert result["isError"] is True
    assert "Role" in text(result)


def test_gateway_denies_after_containment(gateway, issue_agent_token, containment):
    token = issue_agent_token()
    containment.suspend("agent-123", "suspected prompt injection", "contain-1")
    result = gateway.call_tool(token, "read_workspace_file", {"path": "src/hello.py"})
    assert result["isError"] is True
    assert "suspended" in text(result)


def test_gateway_denies_revoked_identity(gateway, broker, issue_agent_token):
    token = issue_agent_token()
    broker.revoke(token, audience="secure-agent-execution-platform")
    result = gateway.call_tool(token, "read_workspace_file", {"path": "src/hello.py"})
    assert result["isError"] is True
    assert "revoked" in text(result)


def test_gateway_records_allow_and_deny_decisions(gateway, issue_agent_token, audit):
    token = issue_agent_token()
    gateway.call_tool(token, "read_workspace_file", {"path": "src/hello.py"})
    gateway.call_tool(token, "run_shell", {"command": "id"})
    records = audit.verify()
    assert [r["decision"] for r in records] == ["allow", "deny"]
    assert records[1]["action"] == "mcp.run_shell"


def test_gateway_audit_integrity_is_reported(gateway, issue_agent_token):
    result = gateway.call_tool(issue_agent_token(), "read_workspace_file", {"path": "src/hello.py"})
    assert result["isError"] is False
    status = gateway.audit_integrity()
    assert status["valid"] is True
    assert status["events"] == 1


def test_gateway_budget_exhaustion_is_a_denial(gateway, issue_agent_token):
    token = issue_agent_token()
    first = gateway.call_tool(token, "read_workspace_file", {"path": "src/hello.py"}, estimated_tokens=90)
    second = gateway.call_tool(token, "read_workspace_file", {"path": "src/hello.py"}, estimated_tokens=20)
    assert first["isError"] is False
    assert second["isError"] is True
    assert "budget" in text(second).lower()
