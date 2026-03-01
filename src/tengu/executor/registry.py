"""Tool discovery registry — checks which external tools are installed."""

from __future__ import annotations

import asyncio
import shutil

import structlog

from tengu.types import ToolsCheckResult, ToolStatus

logger = structlog.get_logger(__name__)

# All tools Tengu can use, with their categories
_TOOL_CATALOG: list[dict[str, str]] = [
    # Reconnaissance
    {"name": "nmap", "category": "recon"},
    {"name": "masscan", "category": "recon"},
    {"name": "subfinder", "category": "recon"},
    {"name": "amass", "category": "recon"},
    {"name": "dnsrecon", "category": "recon"},
    {"name": "subjack", "category": "recon"},
    {"name": "gowitness", "category": "recon"},
    # Web scanning
    {"name": "nuclei", "category": "web"},
    {"name": "nikto", "category": "web"},
    {"name": "ffuf", "category": "web"},
    {"name": "sslyze", "category": "web"},
    {"name": "gobuster", "category": "web"},
    {"name": "wpscan", "category": "web"},
    {"name": "testssl.sh", "category": "web"},
    # Injection
    {"name": "sqlmap", "category": "injection"},
    {"name": "dalfox", "category": "injection"},
    # Exploitation
    {"name": "msfconsole", "category": "exploit"},
    {"name": "msfvenom", "category": "exploit"},
    {"name": "searchsploit", "category": "exploit"},
    # Brute force
    {"name": "hydra", "category": "bruteforce"},
    {"name": "john", "category": "bruteforce"},
    {"name": "hashcat", "category": "bruteforce"},
    {"name": "cewl", "category": "bruteforce"},
    # Proxy / web app testing
    {"name": "zap.sh", "category": "proxy"},
    {"name": "zaproxy", "category": "proxy"},
    # OSINT
    {"name": "theHarvester", "category": "osint"},
    {"name": "whatweb", "category": "osint"},
    # Secrets
    {"name": "trufflehog", "category": "secrets"},
    {"name": "gitleaks", "category": "secrets"},
    # Container
    {"name": "trivy", "category": "container"},
    # Cloud
    {"name": "scout", "category": "cloud"},
    {"name": "prowler", "category": "cloud"},
    {"name": "checkov", "category": "iac"},
    # API
    {"name": "arjun", "category": "api"},
    # Active Directory
    {"name": "enum4linux-ng", "category": "ad"},
    {"name": "nxc", "category": "ad"},
    {"name": "GetUserSPNs.py", "category": "ad"},
    # Wireless
    {"name": "aircrack-ng", "category": "wireless"},
    {"name": "airodump-ng", "category": "wireless"},
    {"name": "airmon-ng", "category": "wireless"},
    # Stealth
    {"name": "tor", "category": "stealth"},
    {"name": "torsocks", "category": "stealth"},
    {"name": "proxychains4", "category": "stealth"},
    {"name": "socat", "category": "stealth"},
    # Utilities
    {"name": "curl", "category": "utility"},
    {"name": "wget", "category": "utility"},
    {"name": "git", "category": "utility"},
    {"name": "go", "category": "utility"},
    {"name": "python3", "category": "utility"},
]


async def _get_version(executable: str) -> str | None:
    """Try to get the version string for an installed tool."""
    version_flags = ["--version", "-version", "-V", "version"]

    for flag in version_flags:
        try:
            proc = await asyncio.create_subprocess_exec(
                executable,
                flag,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=5)
            output = (stdout + stderr).decode("utf-8", errors="replace")
            # Grab the first non-empty line
            for line in output.splitlines():
                line = line.strip()
                if line:
                    return line[:120]  # cap length
        except (TimeoutError, OSError, FileNotFoundError):
            continue

    return None


def check_tool(name: str, category: str = "unknown") -> ToolStatus:
    """Synchronously check if a tool is available in PATH."""
    path = shutil.which(name)
    return ToolStatus(
        name=name,
        available=path is not None,
        path=path,
        category=category,
    )


async def check_tool_async(name: str, category: str = "unknown") -> ToolStatus:
    """Asynchronously check if a tool is available and get its version."""
    path = shutil.which(name)
    if path is None:
        return ToolStatus(name=name, available=False, category=category)

    version = await _get_version(path)
    return ToolStatus(
        name=name,
        available=True,
        path=path,
        version=version,
        category=category,
    )


async def check_all(verbose: bool = True) -> ToolsCheckResult:
    """Check all tools in the catalog and return a ToolsCheckResult.

    This is what `make doctor` calls.
    """
    tasks = [check_tool_async(t["name"], t["category"]) for t in _TOOL_CATALOG]
    statuses = await asyncio.gather(*tasks)

    result = ToolsCheckResult(
        tools=list(statuses),
        total=len(statuses),
        available=sum(1 for s in statuses if s.available),
        missing=sum(1 for s in statuses if not s.available),
    )

    if verbose:
        _print_status_table(result)

    return result


def _print_status_table(result: ToolsCheckResult) -> None:
    """Print a human-readable tool availability table."""
    print(f"\n{'Tool':<20} {'Category':<15} {'Status':<10} {'Path'}")
    print("-" * 75)

    by_category: dict[str, list[ToolStatus]] = {}
    for tool in result.tools:
        by_category.setdefault(tool.category, []).append(tool)

    for category in sorted(by_category.keys()):
        for tool in by_category[category]:
            status = "✓" if tool.available else "✗"
            path = tool.path or "not found"
            print(f"{tool.name:<20} {tool.category:<15} {status:<10} {path}")

    print("-" * 75)
    print(f"Total: {result.total}  Available: {result.available}  Missing: {result.missing}\n")


def resolve_tool_path(name: str, configured_path: str = "") -> str:
    """Resolve the executable path for a tool.

    Uses configured path if set, otherwise auto-detects via PATH.
    Raises ToolNotFoundError if not found.
    """
    from tengu.exceptions import ToolNotFoundError

    if configured_path:
        return configured_path

    resolved = shutil.which(name)
    if resolved is None:
        raise ToolNotFoundError(name)

    return resolved
