"""Target allowlist enforcement.

Every scan target MUST pass the allowlist check before a tool is invoked.
Protects against accidental or intentional scanning of unauthorized hosts.
"""

from __future__ import annotations

import fnmatch
import ipaddress
import urllib.parse

import structlog

from tengu.exceptions import TargetNotAllowedError

logger = structlog.get_logger(__name__)


def _extract_host(target: str) -> str:
    """Extract the hostname/IP from a target (URL, IP, domain, CIDR)."""
    target = target.strip()

    if target.startswith(("http://", "https://")):
        parsed = urllib.parse.urlparse(target)
        host = parsed.hostname or ""
        return host.lower()

    # CIDR — return as-is for network matching
    if "/" in target:
        return target

    return target.lower()


def _host_matches_pattern(host: str, pattern: str) -> bool:
    """Check if a host matches an allowlist/blocklist pattern.

    Supports:
    - Exact match: "example.com"
    - Wildcard: "*.example.com"
    - CIDR: "192.168.1.0/24"
    - Single IP: "10.0.0.1"
    """
    pattern = pattern.strip().lower()

    # CIDR matching
    if "/" in pattern:
        try:
            network = ipaddress.ip_network(pattern, strict=False)
            # Target is itself a CIDR — check if it is a subnet of the allowed network
            if "/" in host:
                try:
                    target_net = ipaddress.ip_network(host, strict=False)
                    if type(target_net) is type(network):
                        return target_net.subnet_of(network)  # type: ignore[arg-type]
                except ValueError:
                    pass
                return False
            # Target is a plain IP — check if it falls within the allowed network
            try:
                addr = ipaddress.ip_address(host)
                return addr in network
            except ValueError:
                pass
        except ValueError:
            pass
        return False

    # Try IP address comparison
    try:
        return ipaddress.ip_address(host) == ipaddress.ip_address(pattern)
    except ValueError:
        pass

    # Wildcard / exact hostname match
    return fnmatch.fnmatch(host, pattern)


class TargetAllowlist:
    """Enforces target restrictions for all scan operations."""

    def __init__(
        self,
        allowed_hosts: list[str],
        blocked_hosts: list[str],
    ) -> None:
        self._allowed = [h.strip().lower() for h in allowed_hosts]
        self._blocked = [h.strip().lower() for h in blocked_hosts]

    def check(self, target: str) -> None:
        """Raise TargetNotAllowedError if target is not permitted.

        Checks in order:
        1. Blocklist (always wins)
        2. Allowlist (must be present if non-empty)
        """
        host = _extract_host(target)
        log = logger.bind(target=target, host=host)

        # Always check blocklist first
        for pattern in self._blocked:
            if _host_matches_pattern(host, pattern):
                log.warning("Target blocked", pattern=pattern)
                raise TargetNotAllowedError(target, f"matches blocked pattern '{pattern}'")

        # If allowlist is configured, target must be in it
        if self._allowed:
            for pattern in self._allowed:
                if _host_matches_pattern(host, pattern):
                    log.debug("Target allowed", pattern=pattern)
                    return
            log.warning("Target not in allowlist")
            raise TargetNotAllowedError(
                target,
                "not in allowed_hosts. Add it to tengu.toml [targets].allowed_hosts",
            )

        # Allowlist is empty — warn but allow (useful for initial setup)
        log.warning(
            "No allowlist configured — allowing target. "
            "Set [targets].allowed_hosts in tengu.toml for production use."
        )

    def is_allowed(self, target: str) -> bool:
        """Return True if target is permitted, False otherwise."""
        try:
            self.check(target)
            return True
        except TargetNotAllowedError:
            return False


def make_allowlist_from_config() -> TargetAllowlist:
    """Create an allowlist instance from the global configuration."""
    from tengu.config import get_config

    cfg = get_config()
    return TargetAllowlist(
        allowed_hosts=cfg.targets.allowed_hosts,
        blocked_hosts=cfg.effective_blocked_hosts,
    )
