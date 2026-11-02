import pytest

from secure_agent.budget import BudgetExceeded, BudgetGuard


def test_request_budget_blocks_before_increment():
    budget = BudgetGuard(max_requests_per_day=1)
    budget.reserve("agent-1")
    with pytest.raises(BudgetExceeded, match="request"):
        budget.reserve("agent-1")
    assert budget.snapshot("agent-1")["requests_today"] == 1


def test_token_budget_blocks_before_increment():
    budget = BudgetGuard(max_tokens_per_day=10)
    budget.reserve("agent-1", estimated_tokens=8)
    with pytest.raises(BudgetExceeded, match="token"):
        budget.reserve("agent-1", estimated_tokens=3)
    assert budget.snapshot("agent-1")["tokens_today"] == 8


def test_per_minute_rate_limit():
    budget = BudgetGuard(max_calls_per_minute=1)
    budget.reserve("agent-1")
    with pytest.raises(BudgetExceeded, match="rate"):
        budget.reserve("agent-1")


def test_budgets_are_isolated_per_subject():
    budget = BudgetGuard(max_requests_per_day=1)
    budget.reserve("agent-a")
    budget.reserve("agent-b")
    assert budget.snapshot("agent-b")["requests_today"] == 1
