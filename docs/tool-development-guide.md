# Tool Development Guide

This guide walks through everything needed to add a new tool to Tengu.
Read `CLAUDE.md` first for the overall code conventions and security rules.

---

## Anatomy of a Tool

Every Tengu tool is a single `async def` function following a strict structure.
The canonical reference is `src/tengu/tools/recon/nmap.py`.

### Function Signature

```python
async def tool_name(
    ctx: Context,          # type: ignore[type-arg]  — always first parameter
    target: str,           # primary scan target
    option_a: str = "default",
    option_b: int = 60,
    timeout: int | None = None,  # optional timeout override
) -> dict:                 # type: ignore[type-arg]  — always returns dict
```

Rules:
- First parameter is always `ctx: Context` with the `# type: ignore[type-arg]` comment.
- Return type is always `dict` with the `# type: ignore[type-arg]` comment.
- All parameters must have type annotations.
- `timeout: int | None = None` is the standard pattern — `None` means use config default.
- Default values should reflect the safest/most conservative option.

### Docstring

FastMCP exposes the docstring as the tool description shown to Claude. A good docstring
directly improves tool usage accuracy.

```python
async def my_tool(ctx: Context, target: str, ...) -> dict:
    """Short one-line description of what this tool does.

    Longer description if needed. Explain the tool being wrapped,
    what it detects, and any important behavioral notes.

    Args:
        target: What kind of value goes here (IP, hostname, CIDR, URL).
        option_a: What this option controls. List valid values if enum-like.
        option_b: What this number means, and its valid range.
        timeout: Override default scan timeout in seconds.

    Returns:
        Dict with keys: tool, target, duration_seconds, [tool-specific keys].

    Note:
        - Any privilege requirements (root, sudo).
        - Any tool prerequisites.
        - Any destructive behavior that requires human authorization.
    """
```

### Required Imports

```python
from __future__ import annotations

import time                                          # for duration tracking
from typing import Literal                           # for enum parameters

import structlog
from fastmcp import Context

from tengu.config import get_config
from tengu.executor.process import run_command
from tengu.executor.registry import resolve_tool_path
from tengu.security.allowlist import make_allowlist_from_config
from tengu.security.audit import get_audit_logger
from tengu.security.rate_limiter import rate_limited
from tengu.security.sanitizer import sanitize_target  # pick appropriate functions

logger = structlog.get_logger(__name__)
```

---

## 9-Step Implementation Pattern

### Step 1: Create the file

```bash
# Choose the right category directory
src/tengu/tools/recon/        # network reconnaissance tools
src/tengu/tools/web/          # web scanning and analysis tools
src/tengu/tools/osint/        # open-source intelligence tools
src/tengu/tools/injection/    # injection testing tools
src/tengu/tools/exploit/      # exploitation and vuln search tools
src/tengu/tools/bruteforce/   # brute force and hash cracking tools
src/tengu/tools/proxy/        # proxy-based web app testing
src/tengu/tools/analysis/     # correlation and scoring (no external process)
src/tengu/tools/reporting/    # report generation
src/tengu/tools/secrets/      # secret and credential scanning
src/tengu/tools/container/    # container and image security
src/tengu/tools/cloud/        # cloud security auditing
src/tengu/tools/api/          # API security testing
src/tengu/tools/ad/           # Active Directory testing
src/tengu/tools/wireless/     # wireless network testing
src/tengu/tools/iac/          # Infrastructure-as-Code security
src/tengu/tools/social/       # social engineering tools
src/tengu/tools/stealth/      # anonymization and evasion
```

### Step 2: Load configuration and audit logger

```python
async def my_tool(ctx: Context, target: str, ...) -> dict:
    """..."""
    cfg = get_config()
    audit = get_audit_logger()

    # Capture raw params before sanitization for the audit log
    params = {"target": target, "option": option}
```

### Step 3: Sanitize all inputs

Pick the appropriate sanitizer for each parameter type:

```python
# For scan targets (IP, hostname, CIDR, URL)
target = sanitize_target(target)

# For URLs only
url = sanitize_url(url)

# For domain names
domain = sanitize_domain(domain)

# For port specifications
ports = sanitize_port_spec(ports)

# For file paths (wordlists, etc.)
wordlist = sanitize_wordlist_path(wordlist_path)

# For hash values
hash_value = sanitize_hash(hash_value)

# For CVE IDs
cve_id = sanitize_cve_id(cve_id)

# For enum-like string options
scan_type = sanitize_scan_type(scan_type, allowed=["fast", "full", "stealth"])

# For severity lists
severity = sanitize_severity(severity)

# For free-text search queries (strips metacharacters, enforces length)
query = sanitize_free_text(query, field="search_query", max_length=200)
```

If a parameter is an integer, boolean, or literal from a `Literal` type annotation,
it does not need sanitization — Python's type system and FastMCP's deserialization
handle these.

### Step 4: Check the allowlist

Any tool that scans a host MUST check the allowlist:

```python
allowlist = make_allowlist_from_config()
try:
    allowlist.check(target)
except Exception as exc:
    await audit.log_target_blocked("my_tool", target, str(exc))
    raise
```

Pure analysis tools that don't make network connections (e.g., `correlate_findings`,
`score_risk`, `hash_identify`) do not need allowlist checks.

### Step 5: Resolve tool path and build args

```python
tool_path = resolve_tool_path("executable_name", cfg.tools.paths.mytool)
effective_timeout = timeout or cfg.tools.defaults.scan_timeout

# Build argument list — NEVER a single string
args = [
    tool_path,
    "--flag", "value",
    "--other-flag",
    target,
]
```

Rules for building args:
- Always use separate list elements for flags and their values: `["--port", "80"]`
  not `["--port 80"]`.
- Never use f-strings to build a single command string.
- Validate dynamic values with additional regexes if they are embedded in flag values
  (see nmap's script name sanitization as an example).

### Step 6: Report initial progress

```python
await ctx.report_progress(0, 100, f"Starting my_tool on {target}...")
```

Progress reporting helps Claude and users understand that a long-running scan is active.
Use 0-100 as the range, with meaningful messages at key milestones.

### Step 7: Execute with rate limiting and audit logging

```python
async with rate_limited("my_tool"):
    start = time.monotonic()
    await audit.log_tool_call("my_tool", target, params, result="started")

    try:
        stdout, stderr, returncode = await run_command(
            args,
            timeout=effective_timeout,
        )
    except Exception as exc:
        await audit.log_tool_call(
            "my_tool", target, params, result="failed", error=str(exc)
        )
        raise

    duration = time.monotonic() - start

await ctx.report_progress(80, 100, "Parsing results...")
```

### Step 8: Parse output and return

```python
results = _parse_my_tool_output(stdout)

await audit.log_tool_call(
    "my_tool", target, params,
    result="completed",
    duration_seconds=duration,
)
await ctx.report_progress(100, 100, "Scan complete")

return {
    "tool": "my_tool",
    "target": target,
    "command": " ".join(args),
    "duration_seconds": round(duration, 2),
    "findings_count": len(results),
    "results": results,
    "raw_output": stdout,    # include if useful for debugging
}
```

### Step 9: Register in server.py

```python
# In src/tengu/server.py

# Add the import (keep imports grouped by category)
from tengu.tools.category.my_tool import my_tool

# Add the registration (keep tools grouped by category)
mcp.tool()(my_tool)
```

---

## Output Parsing Patterns

### Pattern 1: JSON/JSONL Output

For tools that output JSON or line-delimited JSON (Nuclei, many Go tools):

```python
def _parse_tool_output(output: str) -> list[dict]:
    results = []
    for line in output.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            data = json.loads(line)
            results.append({
                "key": data.get("key", ""),
                "other": data.get("other"),
            })
        except json.JSONDecodeError:
            continue  # skip non-JSON lines (banners, progress output)
    return results
```

### Pattern 2: XML Output

For tools that output XML (Nmap with `-oX -`):

```python
import xml.etree.ElementTree as ET

def _parse_tool_xml(xml_output: str) -> list[dict]:
    results = []
    if not xml_output.strip():
        return results

    try:
        root = ET.fromstring(xml_output)
    except ET.ParseError:
        logger.warning("Failed to parse XML output")
        return results

    for item in root.findall("item"):
        results.append({
            "name": item.get("name", ""),
            "value": item.text or "",
        })

    return results
```

**Never use `xml.etree.ElementTree` with untrusted external XML.**
Nmap generates the XML itself (it is trusted output), so this is safe.
For user-provided XML, use `defusedxml`.

### Pattern 3: Plain Text Output

For tools with unstructured text output (Nikto, Hydra, etc.):

```python
import re

def _parse_tool_text(output: str, target: str) -> list[dict]:
    findings = []

    # Match specific patterns in the output
    pattern = re.compile(r"^\+ (.+)$", re.MULTILINE)
    for match in pattern.finditer(output):
        findings.append({
            "message": match.group(1).strip(),
            "target": target,
        })

    return findings
```

Avoid overly greedy regexes. When output format changes between tool versions,
structured output (JSON/XML) is more reliable.

### Pattern 4: Return Code Handling

Most tools return 0 on success and non-zero on error. However, some security tools
return non-zero when findings are detected (sqlmap, dalfox).

```python
stdout, stderr, returncode = await run_command(args, timeout=effective_timeout)

# For most tools: non-zero means error
if returncode != 0 and not stdout:
    return {
        "tool": "my_tool",
        "target": target,
        "error": stderr[:1000],  # cap stderr length
        "results": [],
    }

# For tools that return non-zero on findings:
# parse stdout regardless of returncode
results = _parse_tool_output(stdout)
```

---

## Testing Requirements

Every new tool must have corresponding tests. No exceptions.

### Minimum Test Coverage

```
tests/
├── unit/
│   └── test_<toolname>.py       # unit tests for the parse function
└── security/
    └── test_command_injection.py  # add the new tool to injection tests
```

### Unit Test Template

```python
"""Unit tests for my_tool."""

from __future__ import annotations

import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from tengu.tools.category.my_tool import my_tool, _parse_my_tool_output


class TestParsing:
    def test_parse_empty_output(self):
        result = _parse_my_tool_output("")
        assert result == []

    def test_parse_valid_output(self):
        sample = "... realistic tool output ..."
        result = _parse_my_tool_output(sample)
        assert len(result) == 1
        assert result[0]["key"] == "expected_value"

    def test_parse_malformed_output(self):
        # Tool should never crash on unexpected output
        result = _parse_my_tool_output("garbage \x00 data \n")
        assert isinstance(result, list)


class TestMyTool:
    @pytest.mark.asyncio
    async def test_rejects_invalid_target(self):
        """Sanitizer must reject shell injection payloads."""
        ctx = MagicMock()
        ctx.report_progress = AsyncMock()

        with pytest.raises(Exception):  # InvalidInputError
            await my_tool(ctx, target="example.com; id")

    @pytest.mark.asyncio
    async def test_rejects_blocked_target(self):
        """Allowlist must reject localhost."""
        ctx = MagicMock()
        ctx.report_progress = AsyncMock()

        with pytest.raises(Exception):  # TargetNotAllowedError
            await my_tool(ctx, target="127.0.0.1")
```

### Security Test — Add to test_command_injection.py

Add your tool's primary target parameter to the existing injection test matrix:

```python
class TestMyToolInjection:
    @pytest.mark.parametrize("payload", SHELL_INJECTION_PAYLOADS)
    def test_my_tool_target_rejects_injection(self, payload: str):
        """my_tool target must reject all shell injection payloads."""
        injected = f"example.com{payload}"
        with pytest.raises(InvalidInputError):
            sanitize_target(injected)
```

If your tool has a unique parameter type (not target/URL/domain), add a sanitizer
for it and add corresponding injection tests.

### Running Tests

```bash
# Run all tests
make test-all

# Run just security tests (fastest for injection verification)
make test-security

# Run with coverage to confirm new code is covered
make coverage
```

---

## Analysis Tools (No External Process)

Analysis tools like `correlate_findings` and `score_risk` work on data already
collected by scan tools. They do not invoke external processes and do not need:
- Sanitizer calls (inputs are structured dicts, not strings)
- Allowlist checks (no network connection)
- Rate limiting (purely computational)

They still need:
- `ctx.report_progress()` calls for long computations
- Proper return dict format
- Registration in `server.py`
- Unit tests

---

## Tool Configuration in tengu.toml

If your tool has a configurable binary path or default options, add them to the
configuration models in `src/tengu/config.py`:

```python
class ToolPathsConfig(BaseModel):
    # ... existing paths ...
    mytool: str = ""   # empty = auto-detect via PATH

class ToolDefaultsConfig(BaseModel):
    # ... existing defaults ...
    mytool_option: str = "default_value"
```

And update `tengu.toml`:

```toml
[tools.paths]
mytool = ""   # leave empty for auto-detection

[tools.defaults]
mytool_option = "default_value"
```

---

## Checklist Before Submitting

- [ ] File placed in correct category directory
- [ ] `from __future__ import annotations` at top of file
- [ ] Complete type annotations on all parameters and return value
- [ ] Comprehensive docstring with Args and Returns sections
- [ ] All string inputs sanitized with appropriate `sanitize_*` function
- [ ] Allowlist check before any network operation
- [ ] `async with rate_limited("tool_name")` wraps subprocess call
- [ ] Audit log entries: "started" before run, "completed"/"failed" after
- [ ] `run_command()` used exclusively (no `subprocess.run`, no `shell=True`)
- [ ] `ctx.report_progress()` called at meaningful milestones
- [ ] Output parser handles empty output, malformed output, and normal output
- [ ] Return dict includes `"tool"`, `"target"`, `"duration_seconds"` at minimum
- [ ] Registered in `server.py` with `mcp.tool()(my_function)`
- [ ] `make lint` passes
- [ ] `make typecheck` passes
- [ ] `make test` passes (including new tests you added)
- [ ] Security tests added for all string parameters
