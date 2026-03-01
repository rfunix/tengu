"""Additional rate limiter tests — covers rate_limited context manager and missed branches."""

from __future__ import annotations

import time

import pytest

from tengu.exceptions import RateLimitError
from tengu.security.rate_limiter import SlidingWindowRateLimiter, rate_limited

# ---------------------------------------------------------------------------
# TestSlidingWindowCleanup
# ---------------------------------------------------------------------------


class TestSlidingWindowCleanup:
    @pytest.mark.asyncio
    async def test_expired_calls_not_counted(self):
        """Old timestamps (> window seconds) should be cleaned up and not block new calls."""
        limiter = SlidingWindowRateLimiter(max_per_minute=2, max_concurrent=5)

        # Manually inject two expired timestamps
        limiter._call_times["tool"] = __import__("collections").deque(
            [time.monotonic() - 120, time.monotonic() - 90]  # both > 60s ago
        )

        # Should NOT raise — expired calls cleaned up, window is empty
        await limiter.acquire("tool")

    @pytest.mark.asyncio
    async def test_old_calls_cleaned_from_window_on_get_stats(self):
        """get_stats should trigger cleanup of expired timestamps."""
        limiter = SlidingWindowRateLimiter(max_per_minute=3, max_concurrent=5)

        # Manually inject expired timestamps
        import collections

        limiter._call_times["tool"] = collections.deque([time.monotonic() - 120])

        stats = limiter.get_stats("tool")
        # After cleanup, window should be empty
        assert stats["calls_in_window"] == 0


# ---------------------------------------------------------------------------
# TestRateLimitedContextManager
# ---------------------------------------------------------------------------


class TestRateLimitedContextManager:
    @pytest.mark.asyncio
    async def test_context_manager_acquires_and_releases(self):
        """rate_limited should increment active count then decrement after block."""
        rl = object.__new__(rate_limited)
        rl._tool = "test_acquire"
        rl._limiter = SlidingWindowRateLimiter(max_per_minute=10, max_concurrent=5)

        async with rl:
            pass  # just verify it doesn't raise

    @pytest.mark.asyncio
    async def test_context_manager_releases_on_exception(self):
        """rate_limited must release the slot even when body raises."""
        limiter = SlidingWindowRateLimiter(max_per_minute=10, max_concurrent=5)
        rl = object.__new__(rate_limited)
        rl._tool = "test_tool"
        rl._limiter = limiter

        with pytest.raises(ValueError):
            async with rl:
                raise ValueError("inner error")

        # After exception, active count should be back to 0
        stats = limiter.get_stats("test_tool")
        assert stats["active_concurrent"] == 0

    @pytest.mark.asyncio
    async def test_context_manager_happy_path(self):
        """rate_limited completes normally and releases slot."""
        limiter = SlidingWindowRateLimiter(max_per_minute=10, max_concurrent=5)
        rl = object.__new__(rate_limited)
        rl._tool = "test_tool"
        rl._limiter = limiter

        result = []
        async with rl:
            result.append("ran")

        assert result == ["ran"]
        stats = limiter.get_stats("test_tool")
        assert stats["active_concurrent"] == 0

    @pytest.mark.asyncio
    async def test_context_manager_counts_calls(self):
        """rate_limited increments the sliding window call count."""
        limiter = SlidingWindowRateLimiter(max_per_minute=10, max_concurrent=5)
        rl = object.__new__(rate_limited)
        rl._tool = "my_tool"
        rl._limiter = limiter

        async with rl:
            pass

        stats = limiter.get_stats("my_tool")
        assert stats["calls_in_window"] == 1


# ---------------------------------------------------------------------------
# TestSlidingWindowRateLimiterExtra
# ---------------------------------------------------------------------------


class TestSlidingWindowRateLimiterExtra:
    @pytest.mark.asyncio
    async def test_get_stats_empty_tool(self):
        limiter = SlidingWindowRateLimiter(max_per_minute=5, max_concurrent=2)
        stats = limiter.get_stats("brand_new_tool")
        assert stats["calls_in_window"] == 0
        assert stats["active_concurrent"] == 0
        assert stats["max_per_minute"] == 5
        assert stats["max_concurrent"] == 2

    @pytest.mark.asyncio
    async def test_acquire_increments_active_count(self):
        limiter = SlidingWindowRateLimiter(max_per_minute=10, max_concurrent=5)
        await limiter.acquire("tool_a")
        stats = limiter.get_stats("tool_a")
        assert stats["active_concurrent"] == 1

    @pytest.mark.asyncio
    async def test_release_decrements_active_count(self):
        limiter = SlidingWindowRateLimiter(max_per_minute=10, max_concurrent=5)
        await limiter.acquire("tool_b")
        await limiter.release("tool_b")
        stats = limiter.get_stats("tool_b")
        assert stats["active_concurrent"] == 0

    @pytest.mark.asyncio
    async def test_release_never_goes_below_zero(self):
        limiter = SlidingWindowRateLimiter(max_per_minute=10, max_concurrent=5)
        # Release without acquire — should clamp at 0
        await limiter.release("tool_c")
        stats = limiter.get_stats("tool_c")
        assert stats["active_concurrent"] == 0

    @pytest.mark.asyncio
    async def test_per_minute_limit_raised(self):
        limiter = SlidingWindowRateLimiter(max_per_minute=2, max_concurrent=10)
        await limiter.acquire("fast_tool")
        await limiter.acquire("fast_tool")
        with pytest.raises(RateLimitError, match="Rate limit"):
            await limiter.acquire("fast_tool")

    @pytest.mark.asyncio
    async def test_concurrent_limit_raised(self):
        limiter = SlidingWindowRateLimiter(max_per_minute=100, max_concurrent=2)
        await limiter.acquire("parallel_tool")
        await limiter.acquire("parallel_tool")
        with pytest.raises(RateLimitError, match="concurrent"):
            await limiter.acquire("parallel_tool")
