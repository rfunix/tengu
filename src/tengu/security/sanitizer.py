"""Input sanitization and validation for all tool parameters.

Prevents command injection, path traversal, and other input-based attacks.
All tool inputs MUST pass through these validators before use.
"""

from __future__ import annotations

import ipaddress
import re
import urllib.parse
from typing import Literal

from tengu.exceptions import InvalidInputError

# Characters that could be used for shell injection or HTTP header injection.
# Defense-in-depth: since we never use shell=True, but we still validate explicitly.
_SHELL_METACHARACTERS = re.compile(r"[;&|`$<>()\{\}\[\]!\\\'\"\r\n]")

# Valid hostname pattern (RFC 1123)
_HOSTNAME_PATTERN = re.compile(
    r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)*"
    r"[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?$"
)

# Wildcard hostname pattern (e.g. *.example.com)
_WILDCARD_HOSTNAME_PATTERN = re.compile(
    r"^\*\.(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)*"
    r"[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?$"
)

# Valid port range
_PORT_SPEC_PATTERN = re.compile(
    r"^(\d{1,5})"  # single port
    r"(-\d{1,5})?"  # optional range end
    r"(,(\d{1,5}(-\d{1,5})?))*$"  # optional additional ports/ranges
)

# Hash pattern — hex characters only
_HASH_PATTERN = re.compile(r"^[a-fA-F0-9$./]+$")

# CVE ID pattern
_CVE_PATTERN = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)

# CIDR notation
_CIDR_PATTERN = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2}$")


def sanitize_target(value: str) -> str:
    """Validate and sanitize a scan target (IP, hostname, CIDR, or URL).

    Returns the sanitized target string.
    Raises InvalidInputError if the value is suspicious.
    """
    value = value.strip()

    if not value:
        raise InvalidInputError("target", value, "target cannot be empty")

    if len(value) > 253:
        raise InvalidInputError("target", value, "target too long (max 253 chars)")

    if _SHELL_METACHARACTERS.search(value):
        raise InvalidInputError("target", value, "contains forbidden shell metacharacters")

    # Accept URLs — extract host for further validation
    if value.startswith(("http://", "https://")):
        return sanitize_url(value)

    # Accept CIDR notation
    if "/" in value:
        return sanitize_cidr(value)

    # Try as IP address first
    try:
        ipaddress.ip_address(value)
        return value
    except ValueError:
        pass

    # Validate as hostname
    if _HOSTNAME_PATTERN.match(value):
        return value.lower()

    raise InvalidInputError("target", value, "not a valid IP, hostname, CIDR, or URL")


def sanitize_url(value: str) -> str:
    """Validate and sanitize a URL target."""
    value = value.strip()

    if _SHELL_METACHARACTERS.search(value):
        raise InvalidInputError("url", value, "contains forbidden shell metacharacters")

    try:
        parsed = urllib.parse.urlparse(value)
    except Exception as exc:
        raise InvalidInputError("url", value, f"invalid URL: {exc}") from exc

    if parsed.scheme not in ("http", "https"):
        raise InvalidInputError("url", value, "only http:// and https:// URLs are allowed")

    if not parsed.netloc:
        raise InvalidInputError("url", value, "URL has no host")

    return value


def sanitize_domain(value: str) -> str:
    """Validate and sanitize a domain name."""
    value = value.strip().lower()

    if not value:
        raise InvalidInputError("domain", value, "domain cannot be empty")

    if _SHELL_METACHARACTERS.search(value):
        raise InvalidInputError("domain", value, "contains forbidden shell metacharacters")

    if _WILDCARD_HOSTNAME_PATTERN.match(value):
        return value

    if _HOSTNAME_PATTERN.match(value):
        return value

    raise InvalidInputError("domain", value, "not a valid domain name")


def sanitize_cidr(value: str) -> str:
    """Validate and sanitize a CIDR network."""
    value = value.strip()

    try:
        network = ipaddress.ip_network(value, strict=False)
        return str(network)
    except ValueError as exc:
        raise InvalidInputError("cidr", value, f"invalid CIDR notation: {exc}") from exc


def sanitize_port_spec(value: str) -> str:
    """Validate and sanitize a port specification.

    Accepts: single port (80), range (80-443), comma-separated list (22,80,443),
    or mixed (22,80-90,443).
    """
    value = value.strip()

    if not value:
        raise InvalidInputError("ports", value, "port specification cannot be empty")

    # Special cases
    if value in ("-", "1-65535", "all", "*"):
        return "1-65535"

    if not _PORT_SPEC_PATTERN.match(value):
        raise InvalidInputError("ports", value, "invalid port specification")

    # Validate each port number is in range
    parts = re.split(r"[,\-]", value)
    for part in parts:
        if part:
            port_num = int(part)
            if not (1 <= port_num <= 65535):
                raise InvalidInputError("ports", value, f"port {port_num} out of range (1-65535)")

    return value


def sanitize_wordlist_path(value: str) -> str:
    """Validate a wordlist file path (no path traversal)."""
    from pathlib import Path

    value = value.strip()

    if not value:
        raise InvalidInputError("wordlist", value, "wordlist path cannot be empty")

    if _SHELL_METACHARACTERS.search(value):
        raise InvalidInputError("wordlist", value, "contains forbidden shell metacharacters")

    path = Path(value).resolve()

    # Prevent path traversal outside expected directories
    allowed_prefixes = [
        Path("/usr/share"),
        Path("/opt"),
        Path.home(),
        Path("/tmp"),
    ]
    if not any(str(path).startswith(str(p)) for p in allowed_prefixes):
        raise InvalidInputError("wordlist", value, "path is outside allowed directories")

    return str(path)


def sanitize_hash(value: str) -> str:
    """Validate a hash value."""
    value = value.strip()

    if not value:
        raise InvalidInputError("hash", value, "hash value cannot be empty")

    if len(value) > 512:
        raise InvalidInputError("hash", value, "hash value too long")

    if not _HASH_PATTERN.match(value):
        raise InvalidInputError("hash", value, "contains invalid characters for a hash")

    return value


def sanitize_cve_id(value: str) -> str:
    """Validate a CVE identifier."""
    value = value.strip().upper()

    if not _CVE_PATTERN.match(value):
        raise InvalidInputError("cve_id", value, "not a valid CVE ID (expected CVE-YYYY-NNNNN)")

    return value


def sanitize_free_text(
    value: str,
    field: str = "query",
    max_length: int = 500,
) -> str:
    """Sanitize a free-text search query.

    Strips shell metacharacters and enforces length limits.
    Used for search queries where we can't be more restrictive.
    """
    value = value.strip()

    if not value:
        raise InvalidInputError(field, value, "value cannot be empty")

    if len(value) > max_length:
        raise InvalidInputError(field, value, f"too long (max {max_length} chars)")

    # Remove shell metacharacters
    cleaned = _SHELL_METACHARACTERS.sub("", value)
    return cleaned.strip()


def sanitize_scan_type(
    value: str,
    allowed: list[str],
    field: str = "scan_type",
) -> str:
    """Validate an enum-like scan type parameter against an allowlist."""
    value = value.strip().lower()

    if value not in allowed:
        raise InvalidInputError(field, value, f"must be one of: {', '.join(allowed)}")

    return value


def sanitize_severity(
    value: str | list[str],
) -> list[str]:
    """Validate severity level(s)."""
    _valid = {"info", "low", "medium", "high", "critical"}

    if isinstance(value, str):
        values = [v.strip().lower() for v in value.split(",")]
    else:
        values = [v.strip().lower() for v in value]

    invalid = set(values) - _valid
    if invalid:
        raise InvalidInputError(
            "severity", str(value), f"invalid severities: {', '.join(sorted(invalid))}"
        )

    return values


ScanTypeNmap = Literal["syn", "connect", "udp", "version", "ping", "fast"]
ScanTypeMasscan = Literal["syn"]


# Repo URL pattern (https:// or git@)
_REPO_URL_PATTERN = re.compile(
    r"^(https://[a-zA-Z0-9._\-/]+\.git"
    r"|https://[a-zA-Z0-9._\-/]+"
    r"|git@[a-zA-Z0-9._\-]+:[a-zA-Z0-9._\-/]+\.git)$"
)

# Docker image name: registry/namespace/name:tag or name:tag
_DOCKER_IMAGE_PATTERN = re.compile(
    r"^[a-zA-Z0-9._\-/]+(:[a-zA-Z0-9._\-]+)?(@sha256:[a-fA-F0-9]{64})?$"
)

# Proxy URL pattern: scheme://host:port
_PROXY_URL_PATTERN = re.compile(
    r"^(socks5|socks4|http|https)://[a-zA-Z0-9._\-]+(:\d{1,5})?(/[a-zA-Z0-9._\-/]*)?$"
)


def sanitize_repo_url(value: str) -> str:
    """Validate a git repository URL (https:// or git@).

    Prevents command injection via repository URLs passed to git clone / trufflehog / gitleaks.
    """
    value = value.strip()

    if not value:
        raise InvalidInputError("repo_url", value, "repository URL cannot be empty")

    if len(value) > 500:
        raise InvalidInputError("repo_url", value, "repository URL too long (max 500 chars)")

    if _SHELL_METACHARACTERS.search(value):
        raise InvalidInputError("repo_url", value, "contains forbidden shell metacharacters")

    if not _REPO_URL_PATTERN.match(value):
        raise InvalidInputError(
            "repo_url",
            value,
            "not a valid git repository URL (expected https://... or git@...:.../...git)",
        )

    return value


def sanitize_docker_image(value: str) -> str:
    """Validate a Docker image name (e.g. nginx:latest, gcr.io/project/image:tag).

    Prevents command injection via image names passed to trivy, docker, etc.
    """
    value = value.strip()

    if not value:
        raise InvalidInputError("docker_image", value, "Docker image name cannot be empty")

    if len(value) > 256:
        raise InvalidInputError("docker_image", value, "Docker image name too long (max 256 chars)")

    if _SHELL_METACHARACTERS.search(value):
        raise InvalidInputError("docker_image", value, "contains forbidden shell metacharacters")

    if not _DOCKER_IMAGE_PATTERN.match(value):
        raise InvalidInputError(
            "docker_image",
            value,
            "not a valid Docker image name (e.g. nginx:latest, registry.io/org/name:tag)",
        )

    return value.lower()


def sanitize_proxy_url(value: str) -> str:
    """Validate a proxy URL (socks5://, socks4://, http://, https://).

    Prevents injection via proxy URLs passed to httpx, curl, or subprocess tools.
    """
    value = value.strip()

    if not value:
        raise InvalidInputError("proxy_url", value, "proxy URL cannot be empty")

    if len(value) > 200:
        raise InvalidInputError("proxy_url", value, "proxy URL too long (max 200 chars)")

    if _SHELL_METACHARACTERS.search(value):
        raise InvalidInputError("proxy_url", value, "contains forbidden shell metacharacters")

    if not _PROXY_URL_PATTERN.match(value):
        raise InvalidInputError(
            "proxy_url",
            value,
            "not a valid proxy URL (expected socks5://host:port, http://host:port, etc.)",
        )

    # Validate port range if present
    import urllib.parse

    try:
        parsed = urllib.parse.urlparse(value)
        if parsed.port is not None and not (1 <= parsed.port <= 65535):
            raise InvalidInputError(
                "proxy_url", value, f"port {parsed.port} out of range (1-65535)"
            )
    except (ValueError, AttributeError):
        pass

    return value
