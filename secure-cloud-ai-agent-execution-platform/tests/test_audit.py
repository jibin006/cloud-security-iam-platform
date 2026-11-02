import json

import pytest

from secure_agent.audit import AuditIntegrityError, AuditLog


def test_audit_chain_verifies_multiple_events(audit):
    audit.append(subject="agent-a", action="tool.read", decision="allow", detail="ok", request_id="1")
    audit.append(subject="agent-a", action="tool.write", decision="deny", detail="out of scope", request_id="2")
    records = audit.verify()
    assert len(records) == 2
    assert records[1]["previous_hash"] == records[0]["hash"]


def test_audit_tampering_is_detected(audit):
    audit.append(subject="agent-a", action="tool.read", decision="allow", detail="ok", request_id="1")
    raw = audit.path.read_text(encoding="utf-8")
    record = json.loads(raw)
    record["decision"] = "deny"
    audit.path.write_text(json.dumps(record) + "\n", encoding="utf-8")
    with pytest.raises(AuditIntegrityError, match="hash mismatch"):
        audit.verify()


def test_audit_reordering_or_missing_sequence_is_detected(audit):
    audit.append(subject="agent-a", action="one", decision="allow", detail="", request_id="1")
    audit.append(subject="agent-a", action="two", decision="allow", detail="", request_id="2")
    lines = audit.path.read_text(encoding="utf-8").splitlines()
    audit.path.write_text(lines[1] + "\n" + lines[0] + "\n", encoding="utf-8")
    with pytest.raises(AuditIntegrityError):
        audit.verify()
