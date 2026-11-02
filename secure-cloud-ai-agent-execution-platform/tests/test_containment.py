def test_suspend_and_resume_are_audited(containment, audit):
    containment.suspend("agent-1", "exfiltration attempt", "r1")
    assert containment.is_suspended("agent-1")
    assert containment.reason("agent-1") == "exfiltration attempt"

    containment.resume("agent-1", approver="security-oncall", request_id="r2")
    assert not containment.is_suspended("agent-1")
    records = audit.verify()
    assert [event["action"] for event in records] == ["agent.suspend", "agent.resume"]
