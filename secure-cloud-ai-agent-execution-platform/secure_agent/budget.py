"""Thread-safe in-memory per-agent budgets for local testing."""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Callable


class BudgetExceeded(PermissionError):
    """Raised when an agent exceeds its request, token, or rate budget."""


@dataclass
class Usage:
    request_count: int = 0
    token_count: int = 0
    minute_count: int = 0
    minute_window: int = 0
    day_window: str = ""


class BudgetGuard:
    def __init__(
        self,
        *,
        max_requests_per_day: int = 100,
        max_tokens_per_day: int = 10_000,
        max_calls_per_minute: int = 20,
        clock: Callable[[], float] = time.time,
    ) -> None:
        if min(max_requests_per_day, max_tokens_per_day, max_calls_per_minute) < 1:
            raise ValueError("All budget limits must be positive")
        self.max_requests_per_day = max_requests_per_day
        self.max_tokens_per_day = max_tokens_per_day
        self.max_calls_per_minute = max_calls_per_minute
        self._clock = clock
        self._usage: dict[str, Usage] = {}
        self._lock = threading.Lock()

    def reserve(self, subject: str, estimated_tokens: int = 0) -> None:
        if estimated_tokens < 0:
            raise ValueError("estimated_tokens cannot be negative")
        now = self._clock()
        day = datetime.fromtimestamp(now, tz=timezone.utc).date().isoformat()
        minute = int(now // 60)
        with self._lock:
            usage = self._usage.setdefault(subject, Usage())
            if usage.day_window != day:
                usage.request_count = 0
                usage.token_count = 0
                usage.day_window = day
            if usage.minute_window != minute:
                usage.minute_count = 0
                usage.minute_window = minute

            if usage.request_count + 1 > self.max_requests_per_day:
                raise BudgetExceeded("Daily request budget exceeded")
            if usage.token_count + estimated_tokens > self.max_tokens_per_day:
                raise BudgetExceeded("Daily token budget exceeded")
            if usage.minute_count + 1 > self.max_calls_per_minute:
                raise BudgetExceeded("Per-minute tool-call rate exceeded")

            usage.request_count += 1
            usage.token_count += estimated_tokens
            usage.minute_count += 1

    def snapshot(self, subject: str) -> dict[str, int]:
        with self._lock:
            usage = self._usage.get(subject, Usage())
            return {
                "requests_today": usage.request_count,
                "tokens_today": usage.token_count,
                "calls_this_minute": usage.minute_count,
            }
