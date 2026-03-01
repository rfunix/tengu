"""Unit tests for tengu.tools.stealth.rotate_identity."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from tengu.stealth.config import StealthConfig
from tengu.stealth.layer import StealthLayer, reset_stealth_layer

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _disabled_stealth() -> StealthLayer:
    return StealthLayer(StealthConfig(enabled=False))


def _ua_stealth(ua: str = "Mozilla/5.0 TestBrowser") -> StealthLayer:
    layer = MagicMock(spec=StealthLayer)
    layer.get_user_agent = MagicMock(return_value=ua)
    return layer


def _no_ua_stealth() -> StealthLayer:
    layer = MagicMock(spec=StealthLayer)
    layer.get_user_agent = MagicMock(return_value=None)
    return layer


# ---------------------------------------------------------------------------
# TestRotateIdentity
# ---------------------------------------------------------------------------


class TestRotateIdentity:
    @pytest.mark.asyncio
    async def test_tor_rotated_true_when_tor_success(self):
        """tor_rotated=True when tor_new_identity returns success=True."""
        reset_stealth_layer()
        tor_result = {"success": True, "message": "New identity requested", "response": "250 OK"}

        with (
            patch(
                "tengu.tools.stealth.rotate_identity.tor_new_identity",
                AsyncMock(return_value=tor_result),
            ),
            patch(
                "tengu.tools.stealth.rotate_identity.get_stealth_layer", return_value=_ua_stealth()
            ),
        ):
            from tengu.tools.stealth.rotate_identity import rotate_identity

            result = await rotate_identity()

        assert result["tor_rotated"] is True

    @pytest.mark.asyncio
    async def test_status_success_when_tor_rotated(self):
        """status='success' when tor_new_identity returns success=True."""
        reset_stealth_layer()
        tor_result = {"success": True, "message": "New identity requested", "response": "250 OK"}

        with (
            patch(
                "tengu.tools.stealth.rotate_identity.tor_new_identity",
                AsyncMock(return_value=tor_result),
            ),
            patch(
                "tengu.tools.stealth.rotate_identity.get_stealth_layer", return_value=_ua_stealth()
            ),
        ):
            from tengu.tools.stealth.rotate_identity import rotate_identity

            result = await rotate_identity()

        assert result["status"] == "success"

    @pytest.mark.asyncio
    async def test_status_partial_when_tor_failed(self):
        """status='partial' when tor_new_identity returns success=False."""
        reset_stealth_layer()
        tor_result = {"success": False, "message": "Authentication failed", "response": "515 Error"}

        with (
            patch(
                "tengu.tools.stealth.rotate_identity.tor_new_identity",
                AsyncMock(return_value=tor_result),
            ),
            patch(
                "tengu.tools.stealth.rotate_identity.get_stealth_layer", return_value=_ua_stealth()
            ),
        ):
            from tengu.tools.stealth.rotate_identity import rotate_identity

            result = await rotate_identity()

        assert result["status"] == "partial"
        assert result["tor_rotated"] is False

    @pytest.mark.asyncio
    async def test_new_user_agent_from_stealth(self):
        """new_user_agent is populated from stealth.get_user_agent()."""
        reset_stealth_layer()
        tor_result = {"success": True, "message": "New identity requested"}
        expected_ua = "Mozilla/5.0 (X11; Linux x86_64) TestAgent"

        with (
            patch(
                "tengu.tools.stealth.rotate_identity.tor_new_identity",
                AsyncMock(return_value=tor_result),
            ),
            patch(
                "tengu.tools.stealth.rotate_identity.get_stealth_layer",
                return_value=_ua_stealth(expected_ua),
            ),
        ):
            from tengu.tools.stealth.rotate_identity import rotate_identity

            result = await rotate_identity()

        assert result["new_user_agent"] == expected_ua

    @pytest.mark.asyncio
    async def test_new_user_agent_fallback_when_none(self):
        """new_user_agent contains fallback message when stealth UA returns None."""
        reset_stealth_layer()
        tor_result = {"success": True, "message": "New identity requested"}

        with (
            patch(
                "tengu.tools.stealth.rotate_identity.tor_new_identity",
                AsyncMock(return_value=tor_result),
            ),
            patch(
                "tengu.tools.stealth.rotate_identity.get_stealth_layer",
                return_value=_no_ua_stealth(),
            ),
        ):
            from tengu.tools.stealth.rotate_identity import rotate_identity

            result = await rotate_identity()

        assert "UA rotation not enabled" in result["new_user_agent"]

    @pytest.mark.asyncio
    async def test_tor_message_passed_through(self):
        """tor_message is the message from tor_new_identity result."""
        reset_stealth_layer()
        tor_result = {"success": False, "message": "Tor control port 9051 is not accessible"}

        with (
            patch(
                "tengu.tools.stealth.rotate_identity.tor_new_identity",
                AsyncMock(return_value=tor_result),
            ),
            patch(
                "tengu.tools.stealth.rotate_identity.get_stealth_layer",
                return_value=_no_ua_stealth(),
            ),
        ):
            from tengu.tools.stealth.rotate_identity import rotate_identity

            result = await rotate_identity()

        assert "not accessible" in result["tor_message"]

    @pytest.mark.asyncio
    async def test_result_has_expected_keys(self):
        """Result always contains tor_rotated, tor_message, new_user_agent, status."""
        reset_stealth_layer()
        tor_result = {"success": True, "message": "OK"}

        with (
            patch(
                "tengu.tools.stealth.rotate_identity.tor_new_identity",
                AsyncMock(return_value=tor_result),
            ),
            patch(
                "tengu.tools.stealth.rotate_identity.get_stealth_layer", return_value=_ua_stealth()
            ),
        ):
            from tengu.tools.stealth.rotate_identity import rotate_identity

            result = await rotate_identity()

        assert "tor_rotated" in result
        assert "tor_message" in result
        assert "new_user_agent" in result
        assert "status" in result
