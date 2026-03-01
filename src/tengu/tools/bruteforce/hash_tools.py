"""Hash identification and cracking tools."""

from __future__ import annotations

import contextlib
import re
from typing import Literal

import structlog
from fastmcp import Context

from tengu.config import get_config
from tengu.executor.process import run_command
from tengu.executor.registry import resolve_tool_path
from tengu.security.sanitizer import sanitize_hash, sanitize_wordlist_path

logger = structlog.get_logger(__name__)

# Hash identification patterns
_HASH_PATTERNS: list[tuple[re.Pattern, str, int]] = [
    # (pattern, name, length)
    (re.compile(r"^[a-f0-9]{32}$", re.I), "MD5", 32),
    (re.compile(r"^[a-f0-9]{40}$", re.I), "SHA-1", 40),
    (re.compile(r"^[a-f0-9]{64}$", re.I), "SHA-256", 64),
    (re.compile(r"^[a-f0-9]{96}$", re.I), "SHA-384", 96),
    (re.compile(r"^[a-f0-9]{128}$", re.I), "SHA-512", 128),
    (re.compile(r"^\$2[ayb]\$.{56}$"), "bcrypt", 60),
    (re.compile(r"^\$6\$.{43,}$"), "SHA-512-crypt", 0),
    (re.compile(r"^\$1\$.{30}$"), "MD5-crypt", 0),
    (re.compile(r"^\$5\$.{51}$"), "SHA-256-crypt", 0),
    (re.compile(r"^[a-f0-9]{32}:.{0,32}$", re.I), "MD5+Salt", 0),
    (re.compile(r"^[a-f0-9]{40}:.+$", re.I), "SHA1+Salt", 0),
    (re.compile(r"^\*[A-F0-9]{40}$"), "MySQL-4.1+", 41),
    (re.compile(r"^[a-f0-9]{16}$", re.I), "MySQL-3.x / DES", 16),
    (re.compile(r"^[A-Za-z0-9./]{13}$"), "DES-crypt", 13),
    (re.compile(r"^[A-Za-z0-9+/=]{24}$"), "Base64-MD5 (possible)", 0),
    (re.compile(r"^\$apr1\$"), "Apache APR1-MD5", 0),
    (re.compile(r"^{SHA}[A-Za-z0-9+/=]{28}$"), "SSHA (LDAP)", 0),
    (re.compile(r"^[0-9a-f]{32}:[0-9a-f]{32}$", re.I), "NTLM (hash:lm)", 0),
    (re.compile(r"^[0-9a-f]{32}$", re.I), "NTLM or MD5", 32),
]

HashcrackTool = Literal["john", "hashcat", "auto"]


async def hash_identify(
    ctx: Context,  # type: ignore[type-arg]
    hash_value: str,
) -> dict:  # type: ignore[type-arg]
    """Identify the algorithm used to produce a hash value.

    Uses pattern matching to determine the likely hash type(s) based on
    length, character set, and structural patterns.

    Args:
        hash_value: The hash string to identify.

    Returns:
        List of possible hash types with confidence scores and hashcat mode numbers.
    """
    hash_value = sanitize_hash(hash_value)

    matches = []
    for pattern, name, _expected_len in _HASH_PATTERNS:
        if pattern.match(hash_value):
            matches.append(
                {
                    "type": name,
                    "pattern_match": True,
                }
            )

    # Add hashcat modes for common types
    hashcat_modes = {
        "MD5": 0,
        "SHA-1": 100,
        "SHA-256": 1400,
        "SHA-384": 10800,
        "SHA-512": 1700,
        "bcrypt": 3200,
        "NTLM or MD5": 1000,
        "MySQL-4.1+": 300,
    }

    for match in matches:
        mode = hashcat_modes.get(match["type"])
        if mode is not None:
            match["hashcat_mode"] = mode

    return {
        "hash": hash_value,
        "length": len(hash_value),
        "possible_types": matches,
        "recommendation": (
            f"Most likely: {matches[0]['type']}"
            if matches
            else "Unknown hash type. Check for encoding (base64, hex)."
        ),
    }


async def hash_crack(
    ctx: Context,  # type: ignore[type-arg]
    hash_value: str,
    hash_type: str = "",
    wordlist: str | None = None,
    tool_preference: HashcrackTool = "auto",
    timeout: int | None = None,
) -> dict:  # type: ignore[type-arg]
    """Attempt to crack a hash using a dictionary attack.

    Uses John the Ripper or Hashcat to perform a wordlist-based attack
    against the provided hash value.

    Args:
        hash_value: The hash to crack.
        hash_type: Hash format hint for the cracker (e.g. "md5", "sha1", "bcrypt").
                   Leave empty for auto-detection.
        wordlist: Path to wordlist file. Defaults to configured default.
        tool_preference: Preferred cracking tool: 'john', 'hashcat', or 'auto'.
                         'auto' tries john first, then hashcat.
        timeout: Override timeout in seconds.

    Returns:
        Cracking result with plaintext if found.

    Note:
        - Only use for authorized password recovery or testing purposes.
        - Dictionary attacks may not succeed against strong passwords.
        - For GPU-accelerated cracking, hashcat is strongly preferred.
    """
    cfg = get_config()

    hash_value = sanitize_hash(hash_value)
    effective_wordlist = wordlist or cfg.tools.defaults.wordlist_path
    effective_wordlist = sanitize_wordlist_path(effective_wordlist)
    effective_timeout = timeout or cfg.tools.defaults.scan_timeout

    await ctx.report_progress(0, 4, "Identifying hash type...")

    # Auto-identify if no type given
    if not hash_type:
        id_result = await hash_identify(ctx, hash_value)
        possible = id_result.get("possible_types", [])
        if possible:
            hash_type = possible[0].get("type", "").split()[0].lower()

    await ctx.report_progress(1, 4, f"Attempting to crack {hash_type} hash...")

    # Try john first (or as preferred)
    if tool_preference in ("john", "auto"):
        try:
            result = await _crack_with_john(
                hash_value, hash_type, effective_wordlist, effective_timeout
            )
            if result.get("cracked"):
                await ctx.report_progress(4, 4, "Hash cracked!")
                return result
        except Exception as exc:
            logger.debug("John failed", error=str(exc))

    # Try hashcat
    if tool_preference in ("hashcat", "auto"):
        try:
            result = await _crack_with_hashcat(
                hash_value, hash_type, effective_wordlist, effective_timeout
            )
            if result.get("cracked"):
                await ctx.report_progress(4, 4, "Hash cracked!")
                return result
        except Exception as exc:
            logger.debug("Hashcat failed", error=str(exc))

    await ctx.report_progress(4, 4, "Cracking complete")

    return {
        "tool": tool_preference,
        "hash": hash_value,
        "hash_type": hash_type,
        "cracked": False,
        "plaintext": None,
        "message": "Hash was not cracked with the provided wordlist. Consider using a larger wordlist or rule-based attacks.",
    }


async def _crack_with_john(
    hash_value: str,
    hash_type: str,
    wordlist: str,
    timeout: int,
) -> dict:  # type: ignore[type-arg]
    """Attempt cracking with John the Ripper."""
    import tempfile
    from pathlib import Path

    john_path = resolve_tool_path("john")

    # Write hash to temp file
    with tempfile.NamedTemporaryFile(mode="w", suffix=".hash", delete=False) as f:
        f.write(hash_value + "\n")
        hash_file = f.name

    try:
        args = [
            john_path,
            hash_file,
            "--wordlist=" + wordlist,
            "--pot=/dev/null",  # Don't store in pot file
        ]

        if hash_type:
            safe_format = re.sub(r"[^a-zA-Z0-9\-]", "", hash_type)
            if safe_format:
                args.append(f"--format={safe_format}")

        stdout, stderr, returncode = await run_command(args, timeout=timeout)

        # Check if cracked
        if "password hash" in stdout.lower() or "loaded 0" not in stdout:
            # Run --show to get the cracked password
            show_args = [john_path, "--show", hash_file]
            show_stdout, _, _ = await run_command(show_args, timeout=10)

            for line in show_stdout.splitlines():
                if ":" in line and not line.startswith("#"):
                    parts = line.split(":", 1)
                    if len(parts) == 2 and parts[1].strip():
                        return {
                            "tool": "john",
                            "hash": hash_value,
                            "cracked": True,
                            "plaintext": parts[1].strip(),
                        }

    finally:
        with contextlib.suppress(OSError):
            Path(hash_file).unlink()

    return {"tool": "john", "hash": hash_value, "cracked": False}


async def _crack_with_hashcat(
    hash_value: str,
    hash_type: str,
    wordlist: str,
    timeout: int,
) -> dict:  # type: ignore[type-arg]
    """Attempt cracking with Hashcat."""
    hashcat_path = resolve_tool_path("hashcat")

    # Map hash type to hashcat mode
    mode_map = {
        "md5": "0",
        "sha1": "100",
        "sha-1": "100",
        "sha256": "1400",
        "sha-256": "1400",
        "sha512": "1700",
        "sha-512": "1700",
        "bcrypt": "3200",
        "ntlm": "1000",
        "mysql": "300",
    }

    mode = mode_map.get(hash_type.lower(), "0")

    args = [
        hashcat_path,
        "-m",
        mode,
        "-a",
        "0",  # Straight/dictionary attack
        "--quiet",
        "--potfile-disable",
        hash_value,
        wordlist,
    ]

    stdout, stderr, returncode = await run_command(args, timeout=timeout)

    # Parse hashcat output — cracked hash appears as "hash:plaintext"
    for line in stdout.splitlines():
        if ":" in line and hash_value.lower() in line.lower():
            parts = line.split(":", 1)
            if len(parts) == 2:
                return {
                    "tool": "hashcat",
                    "hash": hash_value,
                    "cracked": True,
                    "plaintext": parts[1].strip(),
                }

    return {"tool": "hashcat", "hash": hash_value, "cracked": False}
