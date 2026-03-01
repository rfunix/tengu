"""Unit tests for stealth user agent rotator."""

from __future__ import annotations

from tengu.stealth.user_agents import _USER_AGENTS, UserAgentRotator

# ---------------------------------------------------------------------------
# TestUserAgentsData
# ---------------------------------------------------------------------------


class TestUserAgentsData:
    def test_chrome_present(self):
        assert "chrome" in _USER_AGENTS

    def test_firefox_present(self):
        assert "firefox" in _USER_AGENTS

    def test_safari_present(self):
        assert "safari" in _USER_AGENTS

    def test_edge_present(self):
        assert "edge" in _USER_AGENTS

    def test_each_browser_has_multiple_agents(self):
        for browser, agents in _USER_AGENTS.items():
            assert len(agents) >= 3, f"{browser} has too few UAs"

    def test_all_agents_start_with_mozilla(self):
        for browser, agents in _USER_AGENTS.items():
            for ua in agents:
                assert ua.startswith("Mozilla/"), f"{browser} UA doesn't start with Mozilla"

    def test_total_count_at_least_20(self):
        total = sum(len(v) for v in _USER_AGENTS.values())
        assert total >= 20


# ---------------------------------------------------------------------------
# TestUserAgentRotator
# ---------------------------------------------------------------------------


class TestUserAgentRotator:
    def test_get_returns_string(self):
        rotator = UserAgentRotator()
        ua = rotator.get()
        assert isinstance(ua, str)
        assert len(ua) > 0

    def test_get_returns_mozilla_ua(self):
        rotator = UserAgentRotator()
        ua = rotator.get()
        assert "Mozilla" in ua

    def test_chrome_browser_type(self):
        rotator = UserAgentRotator(browser_type="chrome")
        ua = rotator.get()
        assert "Chrome" in ua

    def test_firefox_browser_type(self):
        rotator = UserAgentRotator(browser_type="firefox")
        ua = rotator.get()
        assert "Firefox" in ua

    def test_random_browser_type(self):
        rotator = UserAgentRotator(browser_type="random")
        ua = rotator.get()
        assert isinstance(ua, str)
        assert len(ua) > 0

    def test_total_count_matches_data(self):
        rotator = UserAgentRotator()
        expected = sum(len(v) for v in _USER_AGENTS.values())
        assert rotator.total_count == expected

    def test_all_user_agents_is_dict(self):
        rotator = UserAgentRotator()
        result = rotator.all_user_agents
        assert isinstance(result, dict)
        assert "chrome" in result

    def test_rotation_after_interval(self):
        rotator = UserAgentRotator(rotate_every=3)
        # Get UA multiple times; internal counter should trigger rotation
        for _ in range(5):
            ua = rotator.get()
            assert isinstance(ua, str)

    def test_unknown_browser_type_falls_back_to_chrome(self):
        rotator = UserAgentRotator(browser_type="nonexistent_browser")
        ua = rotator.get()
        # Should fall back to chrome pool
        assert "Mozilla" in ua

    def test_thread_safety_multiple_gets(self):
        import threading

        rotator = UserAgentRotator(rotate_every=2)
        results = []
        errors = []

        def worker():
            try:
                for _ in range(10):
                    ua = rotator.get()
                    results.append(ua)
            except Exception as exc:
                errors.append(exc)

        threads = [threading.Thread(target=worker) for _ in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert not errors
        assert len(results) == 50
        for ua in results:
            assert isinstance(ua, str)
