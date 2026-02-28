"""Unit tests for tengu.tools.stealth.tor_new_identity."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from tengu.tools.stealth.tor_new_identity import tor_new_identity

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_reader_writer(auth_response: bytes = b"250 OK\r\n", newnym_response: bytes = b"250 OK\r\n"):
    """Build mocked reader/writer pair for asyncio.open_connection."""
    mock_reader = AsyncMock()
    mock_writer = MagicMock()
    mock_writer.write = MagicMock()
    mock_writer.drain = AsyncMock()
    mock_writer.close = MagicMock()

    # Alternate reads: first for auth, second for newnym
    responses = iter([auth_response, newnym_response])
    mock_reader.read = AsyncMock(side_effect=lambda n: next(responses))
    return mock_reader, mock_writer


async def _fake_wait_for(coro, timeout):
    return await coro


# ---------------------------------------------------------------------------
# TestTorNewIdentitySuccess
# ---------------------------------------------------------------------------


class TestTorNewIdentitySuccess:
    @pytest.mark.asyncio
    async def test_successful_newnym_with_password(self):
        """Returns success=True when auth+newnym both return 250 OK, with password."""
        reader, writer = _make_reader_writer()

        with patch("tengu.tools.stealth.tor_new_identity.asyncio.open_connection", AsyncMock(return_value=(reader, writer))), \
             patch("tengu.tools.stealth.tor_new_identity.asyncio.wait_for", new=_fake_wait_for):
            result = await tor_new_identity(control_port=9051, control_password="s3cr3t")

        assert result["success"] is True
        assert "New identity" in result["message"]
        # Ensure AUTHENTICATE with password was written
        written_calls = [call.args[0] for call in writer.write.call_args_list]
        assert any(b"s3cr3t" in data for data in written_calls)

    @pytest.mark.asyncio
    async def test_successful_newnym_without_password(self):
        """Returns success=True when no password — uses plain AUTHENTICATE."""
        reader, writer = _make_reader_writer()

        with patch("tengu.tools.stealth.tor_new_identity.asyncio.open_connection", AsyncMock(return_value=(reader, writer))), \
             patch("tengu.tools.stealth.tor_new_identity.asyncio.wait_for", new=_fake_wait_for):
            result = await tor_new_identity(control_port=9051, control_password="")

        assert result["success"] is True
        written_calls = [call.args[0] for call in writer.write.call_args_list]
        # Without password: b"AUTHENTICATE\r\n"
        assert any(data == b"AUTHENTICATE\r\n" for data in written_calls)

    @pytest.mark.asyncio
    async def test_response_included_in_result(self):
        """The decoded response is included in the result dict."""
        reader, writer = _make_reader_writer(newnym_response=b"250 OK\r\n")

        with patch("tengu.tools.stealth.tor_new_identity.asyncio.open_connection", AsyncMock(return_value=(reader, writer))), \
             patch("tengu.tools.stealth.tor_new_identity.asyncio.wait_for", new=_fake_wait_for):
            result = await tor_new_identity()

        assert "response" in result
        assert isinstance(result["response"], str)
        assert "250" in result["response"]


# ---------------------------------------------------------------------------
# TestTorNewIdentityAuthFailure
# ---------------------------------------------------------------------------


class TestTorNewIdentityAuthFailure:
    @pytest.mark.asyncio
    async def test_auth_failure_returns_failure(self):
        """Authentication failure (non-250) returns success=False with message."""
        reader, writer = _make_reader_writer(auth_response=b"515 Authentication failed\r\n")

        with patch("tengu.tools.stealth.tor_new_identity.asyncio.open_connection", AsyncMock(return_value=(reader, writer))), \
             patch("tengu.tools.stealth.tor_new_identity.asyncio.wait_for", new=_fake_wait_for):
            result = await tor_new_identity()

        assert result["success"] is False
        assert "Authentication failed" in result["message"]
        assert "response" in result

    @pytest.mark.asyncio
    async def test_newnym_signal_failure_returns_false(self):
        """NEWNYM command failure (non-250 on second read) returns success=False."""
        reader, writer = _make_reader_writer(
            auth_response=b"250 OK\r\n",
            newnym_response=b"552 Unrecognized signal\r\n",
        )

        with patch("tengu.tools.stealth.tor_new_identity.asyncio.open_connection", AsyncMock(return_value=(reader, writer))), \
             patch("tengu.tools.stealth.tor_new_identity.asyncio.wait_for", new=_fake_wait_for):
            result = await tor_new_identity()

        assert result["success"] is False
        assert "NEWNYM signal failed" in result["message"]


# ---------------------------------------------------------------------------
# TestTorNewIdentityConnectionErrors
# ---------------------------------------------------------------------------


class TestTorNewIdentityConnectionErrors:
    @pytest.mark.asyncio
    async def test_connection_refused_returns_error(self):
        """ConnectionRefusedError returns success=False with informative message."""
        with patch(
            "tengu.tools.stealth.tor_new_identity.asyncio.open_connection",
            AsyncMock(side_effect=ConnectionRefusedError()),
        ):
            result = await tor_new_identity(control_port=9051)

        assert result["success"] is False
        assert "9051" in result["message"]
        assert "not accessible" in result["message"]

    @pytest.mark.asyncio
    async def test_general_exception_returns_error(self):
        """Generic exceptions return success=False with the exception message."""
        with patch(
            "tengu.tools.stealth.tor_new_identity.asyncio.open_connection",
            AsyncMock(side_effect=OSError("Network unreachable")),
        ):
            result = await tor_new_identity()

        assert result["success"] is False
        assert "Network unreachable" in result["message"]

    @pytest.mark.asyncio
    async def test_timeout_exception_returns_error(self):
        """TimeoutError returns success=False."""
        with patch(
            "tengu.tools.stealth.tor_new_identity.asyncio.open_connection",
            AsyncMock(side_effect=TimeoutError("timed out")),
        ):
            result = await tor_new_identity()

        assert result["success"] is False
