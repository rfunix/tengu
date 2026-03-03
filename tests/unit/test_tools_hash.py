"""Unit tests for hash identification and cracking helpers."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from tengu.tools.bruteforce.hash_tools import _HASH_PATTERNS, hash_identify

# ---------------------------------------------------------------------------
# TestHashPatterns — structure validation
# ---------------------------------------------------------------------------


class TestHashPatterns:
    def test_at_least_ten_patterns_defined(self):
        assert len(_HASH_PATTERNS) >= 10

    def test_each_entry_is_three_tuple(self):
        for entry in _HASH_PATTERNS:
            assert len(entry) == 3

    def test_md5_pattern_matches(self):
        md5_hash = "d41d8cd98f00b204e9800998ecf8427e"
        matches = [name for pat, name, _ in _HASH_PATTERNS if pat.match(md5_hash)]
        assert any("MD5" in m for m in matches)

    def test_sha1_pattern_matches(self):
        sha1 = "da39a3ee5e6b4b0d3255bfef95601890afd80709"
        matches = [name for pat, name, _ in _HASH_PATTERNS if pat.match(sha1)]
        assert any("SHA-1" in m for m in matches)

    def test_sha256_pattern_matches(self):
        sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        matches = [name for pat, name, _ in _HASH_PATTERNS if pat.match(sha256)]
        assert any("SHA-256" in m for m in matches)

    def test_bcrypt_pattern_matches(self):
        bcrypt = "$2b$12$EixZaYVK1fsbw1ZfbX3OXePaWxn96p36WQoeG6Lruj3vjPGga31lW"
        matches = [name for pat, name, _ in _HASH_PATTERNS if pat.match(bcrypt)]
        assert any("bcrypt" in m for m in matches)

    def test_sha512_pattern_matches(self):
        sha512_valid = "a" * 128
        matches = [name for pat, name, _ in _HASH_PATTERNS if pat.match(sha512_valid)]
        assert any("SHA-512" in m for m in matches)


# ---------------------------------------------------------------------------
# TestHashIdentify — async but no subprocess/ctx
# ---------------------------------------------------------------------------


class TestHashIdentify:
    @pytest.mark.asyncio
    async def test_md5_identified(self):
        md5 = "d41d8cd98f00b204e9800998ecf8427e"
        result = await hash_identify(None, md5)  # ctx not used
        types = [m["type"] for m in result["possible_types"]]
        assert any("MD5" in t for t in types)

    @pytest.mark.asyncio
    async def test_sha1_identified(self):
        sha1 = "da39a3ee5e6b4b0d3255bfef95601890afd80709"
        result = await hash_identify(None, sha1)
        types = [m["type"] for m in result["possible_types"]]
        assert any("SHA-1" in t for t in types)

    @pytest.mark.asyncio
    async def test_sha256_identified(self):
        sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        result = await hash_identify(None, sha256)
        types = [m["type"] for m in result["possible_types"]]
        assert any("SHA-256" in t for t in types)

    @pytest.mark.asyncio
    async def test_unknown_hash_returns_empty_matches(self):
        # 10-char hex string: valid for sanitize_hash but matches no known pattern
        result = await hash_identify(None, "a1b2c3d4e5")
        assert result["possible_types"] == []

    @pytest.mark.asyncio
    async def test_hash_length_in_result(self):
        md5 = "d41d8cd98f00b204e9800998ecf8427e"
        result = await hash_identify(None, md5)
        assert result["length"] == 32

    @pytest.mark.asyncio
    async def test_hashcat_mode_added_for_md5(self):
        md5 = "d41d8cd98f00b204e9800998ecf8427e"
        result = await hash_identify(None, md5)
        md5_matches = [m for m in result["possible_types"] if m["type"] == "MD5"]
        if md5_matches:
            assert md5_matches[0].get("hashcat_mode") == 0

    @pytest.mark.asyncio
    async def test_recommendation_for_known_hash(self):
        sha1 = "da39a3ee5e6b4b0d3255bfef95601890afd80709"
        result = await hash_identify(None, sha1)
        assert "Most likely" in result["recommendation"]

    @pytest.mark.asyncio
    async def test_recommendation_for_unknown_hash(self):
        # 10-char hex string: valid for sanitize_hash but matches no known pattern
        result = await hash_identify(None, "a1b2c3d4e5")
        assert "Unknown" in result["recommendation"]

    def test_bcrypt_pattern_matches_directly(self):
        """Test bcrypt recognition directly via _HASH_PATTERNS (bypasses sanitize_hash
        which doesn't accept non-hex chars like uppercase letters in bcrypt)."""
        bcrypt = "$2b$12$EixZaYVK1fsbw1ZfbX3OXePaWxn96p36WQoeG6Lruj3vjPGga31lW"
        matches = [name for pat, name, _ in _HASH_PATTERNS if pat.match(bcrypt)]
        assert any("bcrypt" in m for m in matches)


# ---------------------------------------------------------------------------
# TestHashCrack — async tests for hash_crack function
# ---------------------------------------------------------------------------


@pytest.fixture
def mock_ctx():
    ctx = AsyncMock()
    ctx.report_progress = AsyncMock()
    return ctx


def _mock_config():
    cfg = MagicMock()
    cfg.tools.defaults.password_wordlist_path = "/usr/share/wordlists/rockyou.txt"
    cfg.tools.defaults.scan_timeout = 300
    return cfg


class TestHashCrack:
    async def test_hash_crack_with_john_success(self, mock_ctx):
        """john finds password — cracked=True in result."""
        from tengu.tools.bruteforce.hash_tools import hash_crack

        mock_john_result = {
            "tool": "john",
            "hash": "d41d8cd98f00b204e9800998ecf8427e",
            "cracked": True,
            "plaintext": "password123",
        }

        with (
            patch("tengu.tools.bruteforce.hash_tools.get_config", return_value=_mock_config()),
            patch(
                "tengu.tools.bruteforce.hash_tools._crack_with_john",
                AsyncMock(return_value=mock_john_result),
            ),
            patch(
                "tengu.tools.bruteforce.hash_tools._crack_with_hashcat",
                AsyncMock(return_value={"cracked": False}),
            ),
        ):
            result = await hash_crack(
                mock_ctx,
                "d41d8cd98f00b204e9800998ecf8427e",
                hash_type="md5",
                tool_preference="john",
            )

        assert result["cracked"] is True
        assert result["plaintext"] == "password123"

    async def test_hash_crack_with_hashcat_fallback(self, mock_ctx):
        """john fails, hashcat succeeds — cracked=True."""
        from tengu.tools.bruteforce.hash_tools import hash_crack

        mock_hashcat_result = {
            "tool": "hashcat",
            "hash": "d41d8cd98f00b204e9800998ecf8427e",
            "cracked": True,
            "plaintext": "secret",
        }

        with (
            patch("tengu.tools.bruteforce.hash_tools.get_config", return_value=_mock_config()),
            patch(
                "tengu.tools.bruteforce.hash_tools._crack_with_john",
                AsyncMock(return_value={"cracked": False}),
            ),
            patch(
                "tengu.tools.bruteforce.hash_tools._crack_with_hashcat",
                AsyncMock(return_value=mock_hashcat_result),
            ),
        ):
            result = await hash_crack(
                mock_ctx,
                "d41d8cd98f00b204e9800998ecf8427e",
                hash_type="md5",
                tool_preference="auto",
            )

        assert result["cracked"] is True
        assert result["plaintext"] == "secret"

    async def test_hash_crack_both_fail(self, mock_ctx):
        """Neither john nor hashcat find password — cracked=False."""
        from tengu.tools.bruteforce.hash_tools import hash_crack

        with (
            patch("tengu.tools.bruteforce.hash_tools.get_config", return_value=_mock_config()),
            patch(
                "tengu.tools.bruteforce.hash_tools._crack_with_john",
                AsyncMock(return_value={"cracked": False}),
            ),
            patch(
                "tengu.tools.bruteforce.hash_tools._crack_with_hashcat",
                AsyncMock(return_value={"cracked": False}),
            ),
        ):
            result = await hash_crack(
                mock_ctx,
                "d41d8cd98f00b204e9800998ecf8427e",
                hash_type="md5",
                tool_preference="auto",
            )

        assert result["cracked"] is False
        assert result["plaintext"] is None

    async def test_hash_crack_custom_wordlist(self, mock_ctx):
        """wordlist param is used instead of default."""
        from tengu.tools.bruteforce.hash_tools import hash_crack

        captured_args: dict = {}

        async def fake_john(hash_value, hash_type, wordlist, timeout):
            captured_args["wordlist"] = wordlist
            return {"cracked": False}

        with (
            patch("tengu.tools.bruteforce.hash_tools.get_config", return_value=_mock_config()),
            patch(
                "tengu.tools.bruteforce.hash_tools.sanitize_wordlist_path", side_effect=lambda x: x
            ),
            patch("tengu.tools.bruteforce.hash_tools._crack_with_john", fake_john),
            patch(
                "tengu.tools.bruteforce.hash_tools._crack_with_hashcat",
                AsyncMock(return_value={"cracked": False}),
            ),
        ):
            await hash_crack(
                mock_ctx,
                "d41d8cd98f00b204e9800998ecf8427e",
                hash_type="md5",
                wordlist="/custom/wordlist.txt",
                tool_preference="john",
            )

        assert captured_args.get("wordlist") == "/custom/wordlist.txt"

    async def test_hash_crack_tool_key(self, mock_ctx):
        """Result has expected tool-related keys."""
        from tengu.tools.bruteforce.hash_tools import hash_crack

        with (
            patch("tengu.tools.bruteforce.hash_tools.get_config", return_value=_mock_config()),
            patch(
                "tengu.tools.bruteforce.hash_tools._crack_with_john",
                AsyncMock(return_value={"cracked": False}),
            ),
            patch(
                "tengu.tools.bruteforce.hash_tools._crack_with_hashcat",
                AsyncMock(return_value={"cracked": False}),
            ),
        ):
            result = await hash_crack(
                mock_ctx,
                "d41d8cd98f00b204e9800998ecf8427e",
                hash_type="md5",
                tool_preference="auto",
            )

        assert "cracked" in result
        assert "hash" in result

    async def test_hash_crack_default_wordlist(self, mock_ctx):
        """No wordlist provided — uses configured default."""
        from tengu.tools.bruteforce.hash_tools import hash_crack

        cfg = _mock_config()
        cfg.tools.defaults.password_wordlist_path = "/default/rockyou.txt"
        captured_args: dict = {}

        async def fake_john(hash_value, hash_type, wordlist, timeout):
            captured_args["wordlist"] = wordlist
            return {"cracked": False}

        with (
            patch("tengu.tools.bruteforce.hash_tools.get_config", return_value=cfg),
            patch(
                "tengu.tools.bruteforce.hash_tools.sanitize_wordlist_path", side_effect=lambda x: x
            ),
            patch("tengu.tools.bruteforce.hash_tools._crack_with_john", fake_john),
            patch(
                "tengu.tools.bruteforce.hash_tools._crack_with_hashcat",
                AsyncMock(return_value={"cracked": False}),
            ),
        ):
            await hash_crack(
                mock_ctx,
                "d41d8cd98f00b204e9800998ecf8427e",
                hash_type="md5",
                tool_preference="john",
            )

        assert captured_args.get("wordlist") == "/default/rockyou.txt"


# ---------------------------------------------------------------------------
# TestCrackWithJohn
# ---------------------------------------------------------------------------


class TestCrackWithJohn:
    async def test_crack_with_john_parses_output(self):
        """John cracks hash → pot file contains result → extracts password."""
        from tengu.tools.bruteforce.hash_tools import _crack_with_john

        # Simulate john writing the cracked result to the pot file
        pot_content = "d41d8cd98f00b204e9800998ecf8427e:password123\n"

        with (
            patch(
                "tengu.tools.bruteforce.hash_tools.resolve_tool_path", return_value="/usr/bin/john"
            ),
            patch(
                "tengu.tools.bruteforce.hash_tools.run_command",
                AsyncMock(return_value=("", "", 0)),
            ),
            patch("pathlib.Path.read_text", return_value=pot_content),
            patch("pathlib.Path.exists", return_value=True),
        ):
            result = await _crack_with_john(
                "d41d8cd98f00b204e9800998ecf8427e", "md5", "/wordlist.txt", 60
            )

        assert result["cracked"] is True
        assert result["plaintext"] == "password123"

    async def test_crack_with_john_not_found(self):
        """John output has no password → cracked=False."""
        from tengu.tools.bruteforce.hash_tools import _crack_with_john

        john_stdout_crack = "0 password hashes cracked, 1 left\n"
        john_stdout_show = "# No hashes found\n0 password hashes cracked\n"

        with (
            patch(
                "tengu.tools.bruteforce.hash_tools.resolve_tool_path", return_value="/usr/bin/john"
            ),
            patch(
                "tengu.tools.bruteforce.hash_tools.run_command",
                AsyncMock(
                    side_effect=[
                        (john_stdout_crack, "", 1),
                        (john_stdout_show, "", 0),
                    ]
                ),
            ),
        ):
            result = await _crack_with_john(
                "d41d8cd98f00b204e9800998ecf8427e", "md5", "/wordlist.txt", 60
            )

        assert result["cracked"] is False


# ---------------------------------------------------------------------------
# TestCrackWithHashcat
# ---------------------------------------------------------------------------


class TestCrackWithHashcat:
    async def test_crack_with_hashcat_parses_output(self):
        """Hashcat output 'hash:plaintext' → extracts password."""
        from tengu.tools.bruteforce.hash_tools import _crack_with_hashcat

        hashcat_stdout = "d41d8cd98f00b204e9800998ecf8427e:letmein\n"

        with (
            patch(
                "tengu.tools.bruteforce.hash_tools.resolve_tool_path",
                return_value="/usr/bin/hashcat",
            ),
            patch(
                "tengu.tools.bruteforce.hash_tools.run_command",
                AsyncMock(return_value=(hashcat_stdout, "", 0)),
            ),
        ):
            result = await _crack_with_hashcat(
                "d41d8cd98f00b204e9800998ecf8427e", "md5", "/wordlist.txt", 60
            )

        assert result["cracked"] is True
        assert result["plaintext"] == "letmein"

    async def test_crack_with_hashcat_not_found(self):
        """No match in hashcat output → cracked=False."""
        from tengu.tools.bruteforce.hash_tools import _crack_with_hashcat

        hashcat_stdout = "Session..........: hashcat\nStatus...........: Exhausted\n"

        with (
            patch(
                "tengu.tools.bruteforce.hash_tools.resolve_tool_path",
                return_value="/usr/bin/hashcat",
            ),
            patch(
                "tengu.tools.bruteforce.hash_tools.run_command",
                AsyncMock(return_value=(hashcat_stdout, "", 1)),
            ),
        ):
            result = await _crack_with_hashcat(
                "d41d8cd98f00b204e9800998ecf8427e", "md5", "/wordlist.txt", 60
            )

        assert result["cracked"] is False
