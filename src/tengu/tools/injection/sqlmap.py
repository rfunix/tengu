"""SQLMap SQL injection testing tool wrapper.

IMPORTANT: SQLMap is a highly intrusive tool. Its use requires explicit
authorization. Level > 2 and risk > 2 should trigger human confirmation.
"""

from __future__ import annotations

import re
import time

import structlog
from fastmcp import Context

from tengu.config import get_config
from tengu.executor.process import run_command
from tengu.executor.registry import resolve_tool_path
from tengu.security.allowlist import make_allowlist_from_config
from tengu.security.audit import get_audit_logger
from tengu.security.rate_limiter import rate_limited
from tengu.security.sanitizer import sanitize_url

logger = structlog.get_logger(__name__)


async def sqlmap_scan(
    ctx: Context,
    url: str,
    method: str = "GET",
    data: str = "",
    parameter: str = "",
    headers: dict[str, str] | None = None,
    level: int = 1,
    risk: int = 1,
    dbms: str = "",
    technique: str = "",
    prefix: str = "",
    suffix: str = "",
    tamper: str = "",
    batch: bool = True,
    dump: bool = False,
    enum_tables: bool = False,
    enum_users: bool = False,
    enum_dbs: bool = False,
    sql_query: str = "",
    timeout: int | None = None,
) -> dict:
    """Test a URL for SQL injection vulnerabilities using SQLMap.

    SQLMap automates the detection and exploitation of SQL injection flaws.
    This tool requires explicit authorization — SQL injection testing
    can cause database errors and potential data exposure.

    Args:
        url: Target URL to test (e.g. "https://example.com/search?q=test").
        method: HTTP method: GET or POST.
        data: POST data string (e.g. "username=admin&password=test").
        parameter: Specific parameter to test (e.g. "q" or "username").
                   If empty, tests all parameters.
        headers: Additional HTTP headers as a dict (e.g. {"Authorization": "Bearer token"}).
                 Useful for testing authenticated endpoints.
        level: Detection aggressiveness level (1-5). Default: 1 (safe).
               Levels 3+ significantly increase request count.
        risk: Risk of tests (1-3). Default: 1 (safe).
              Risk 2+ includes boolean-based tests; Risk 3 includes heavy OR-based tests.
        dbms: Force specific DBMS (e.g. "mysql", "postgresql", "mssql").
              Leave empty for auto-detection.
        technique: SQLi technique(s) to test: B(oolean-blind), E(rror-based),
                   U(nion-query), S(tacked-queries), T(ime-blind), Q(inline-queries).
                   Can be combined: "BT" = boolean + time-blind. Default: all techniques.
        prefix: Injection prefix string to close the original SQL expression
                (e.g. "'))" for LIKE expressions like LIKE '%q%')). Crucial for
                complex injection points that sqlmap can't auto-detect.
        suffix: Injection suffix string appended after payload (e.g. "--").
        tamper: Tamper script name(s) to bypass WAF/filters
                (e.g. "space2comment", "between,randomcase").
        batch: Run in non-interactive batch mode (recommended: True).
        dump: Dump contents of affected database tables (requires confirmed injection).
        enum_tables: Enumerate database tables (--tables flag).
        enum_users: Enumerate database users (--users flag).
        enum_dbs: Enumerate available databases (--dbs flag).
        sql_query: Execute a custom SQL SELECT query via the injection point
                   (e.g. "SELECT email,password FROM Users").
                   Useful when --tables/--dump fail due to JSON response filtering.
        timeout: Override scan timeout in seconds.

    Returns:
        SQL injection test results including vulnerable parameters, DBMS info,
        and optionally dumped data or enumerated tables/users/databases.

    Note:
        - Level > 2 or Risk > 2 requires careful consideration — may cause errors.
        - Target must be in tengu.toml [targets].allowed_hosts.
        - This tool requires explicit human authorization for exploitation.
        - dump/enum_* flags require a confirmed injection point.
    """
    cfg = get_config()
    audit = get_audit_logger()
    params: dict[str, object] = {
        "url": url,
        "method": method,
        "level": level,
        "risk": risk,
        "dump": dump,
        "enum_tables": enum_tables,
        "enum_users": enum_users,
        "enum_dbs": enum_dbs,
    }

    url = sanitize_url(url)
    method = method.upper()
    if method not in ("GET", "POST", "PUT", "DELETE"):
        method = "GET"

    # Clamp level and risk to safe defaults
    level = max(1, min(level, 5))
    risk = max(1, min(risk, 3))

    allowlist = make_allowlist_from_config()
    try:
        allowlist.check(url)
    except Exception as exc:
        await audit.log_target_blocked("sqlmap", url, str(exc))
        raise

    tool_path = resolve_tool_path("sqlmap", cfg.tools.paths.sqlmap)
    effective_timeout = timeout or cfg.tools.defaults.scan_timeout

    args = [
        tool_path,
        "-u",
        url,
        "--method",
        method,
        f"--level={level}",
        f"--risk={risk}",
        "--output-dir=/tmp/sqlmap_tengu",
        "--answers=quit=N,crack=N,reduce the number of requests=N",
        "--flush-session",
        "--no-cast",
        "--no-logging",
    ]

    if batch:
        args.append("--batch")

    if data:
        # Sanitize POST data — remove any shell metacharacters
        safe_data = re.sub(r"[;&|`$<>()\{\}]", "", data)
        args.extend(["--data", safe_data])

    if parameter:
        safe_param = re.sub(r"[^a-zA-Z0-9_\-\[\]]", "", parameter)
        if safe_param:
            args.extend(["-p", safe_param])

    if dbms:
        safe_dbms = re.sub(r"[^a-zA-Z0-9]", "", dbms).lower()
        if safe_dbms in {"mysql", "postgresql", "mssql", "oracle", "sqlite", "access", "db2"}:
            args.extend(["--dbms", safe_dbms])

    if technique:
        safe_technique = re.sub(r"[^BEUSTQbeustq]", "", technique).upper()
        if safe_technique:
            args.extend(["--technique", safe_technique])

    if prefix:
        # Single quotes and parens are legitimate SQL in prefix/suffix — only block
        # shell-dangerous chars. Since we never use shell=True, the risk is minimal.
        safe_prefix = re.sub(r"[\r\n;&|`$<>\{\}\\]", "", prefix)
        if safe_prefix:
            args.extend(["--prefix", safe_prefix])

    if suffix:
        safe_suffix = re.sub(r"[\r\n;&|`$<>\{\}\\]", "", suffix)
        if safe_suffix:
            args.extend(["--suffix", safe_suffix])

    if tamper:
        safe_tamper = re.sub(r"[^a-zA-Z0-9,_\-]", "", tamper)
        if safe_tamper:
            args.extend(["--tamper", safe_tamper])

    if headers:
        for key, value in headers.items():
            # Sanitize header name and value — strip shell metacharacters and newlines
            safe_key = re.sub(r"[\r\n:;&|`$<>()\{\}\\\"']", "", key).strip()
            safe_val = re.sub(r"[\r\n;&|`$<>()\{\}\\\"']", "", value).strip()
            if safe_key and safe_val:
                args.extend(["-H", f"{safe_key}: {safe_val}"])

    if dump:
        args.append("--dump")

    if enum_tables:
        args.append("--tables")

    if enum_users:
        args.append("--users")

    if enum_dbs:
        args.append("--dbs")

    if sql_query:
        # Block shell metacharacters. Note: | is allowed (needed for SQLite || concat).
        # No shell=True is used so | cannot cause pipe injection.
        safe_query = re.sub(r"[\r\n;&`$<>\{\}\\]", "", sql_query)
        if safe_query:
            args.extend(["--sql-query", safe_query])

    # Human confirmation annotation for destructive levels
    if level > 2 or risk > 2:
        logger.warning(
            "SQLMap running with elevated level/risk — requires explicit authorization",
            level=level,
            risk=risk,
            url=url,
        )

    # Stealth: inject --proxy flag if proxy is active
    from tengu.stealth import get_stealth_layer

    stealth = get_stealth_layer()
    if stealth.enabled and stealth.proxy_url:
        args = stealth.inject_proxy_flags("sqlmap", args)

    await ctx.report_progress(0, 100, f"Starting SQLMap test on {url}...")

    async with rate_limited("sqlmap"):
        start = time.monotonic()
        await audit.log_tool_call("sqlmap", url, params, result="started")

        try:
            stdout, stderr, returncode = await run_command(args, timeout=effective_timeout)
        except Exception as exc:
            await audit.log_tool_call("sqlmap", url, params, result="failed", error=str(exc))
            raise

        duration = time.monotonic() - start

    await ctx.report_progress(80, 100, "Parsing SQLMap results...")

    findings = _parse_sqlmap_output(stdout)

    await ctx.report_progress(100, 100, "SQL injection test complete")
    await audit.log_tool_call("sqlmap", url, params, result="completed", duration_seconds=duration)

    result: dict[str, object] = {
        "tool": "sqlmap",
        "url": url,
        "method": method,
        "duration_seconds": round(duration, 2),
        "vulnerable": len(findings.get("vulnerable_params", [])) > 0,
        "vulnerable_parameters": findings.get("vulnerable_params", []),
        "dbms": findings.get("dbms"),
        "injection_types": findings.get("injection_types", []),
        "raw_output_excerpt": stdout[-3000:] if len(stdout) > 3000 else stdout,
    }

    if dump or enum_tables or enum_users or enum_dbs:
        result["enumerated_tables"] = findings.get("tables", [])
        result["enumerated_dbs"] = findings.get("databases", [])
        result["enumerated_users"] = findings.get("users", [])
        result["dumped_data"] = findings.get("dumped_data", [])

    if sql_query:
        result["sql_query"] = sql_query
        result["sql_query_output"] = findings.get("retrieved_rows", [])

    return result


def _parse_sqlmap_output(output: str) -> dict:
    """Parse SQLMap stdout for key findings."""
    result: dict[str, object] = {
        "vulnerable_params": [],
        "dbms": None,
        "injection_types": [],
        "tables": [],
        "databases": [],
        "users": [],
        "dumped_data": [],
        "retrieved_rows": [],
    }

    vulnerable_params: list[str] = []
    injection_types: list[str] = []
    dbms: str | None = None
    tables: list[str] = []
    databases: list[str] = []
    users: list[str] = []
    dumped_data: list[str] = []
    retrieved_rows: list[str] = []

    in_table_listing = False
    in_dump = False

    for line in output.splitlines():
        stripped = line.strip()

        # Parameter vulnerability
        m = re.search(r"parameter '(.+?)' is vulnerable", line, re.IGNORECASE)
        if m:
            param = m.group(1)
            if param not in vulnerable_params:
                vulnerable_params.append(param)

        # DBMS detection
        m = re.search(r"back-end DBMS: (.+)", line, re.IGNORECASE)
        if m:
            dbms = m.group(1).strip()

        # Injection type
        m = re.search(r"Type: (.+)", line, re.IGNORECASE)
        if m:
            itype = m.group(1).strip()
            if itype not in injection_types:
                injection_types.append(itype)

        # Enumerated databases
        m = re.search(r"\[\*\] (.+)", line)
        if m and "available databases" in output:
            db = m.group(1).strip()
            if db and db not in databases:
                databases.append(db)

        # Table listing (lines between header separators)
        if re.search(r"Database: .+", line, re.IGNORECASE):
            in_table_listing = True
        if in_table_listing and stripped.startswith("|"):
            cell = stripped.strip("|").strip()
            if cell and cell.lower() not in ("table", "tables") and cell not in tables:
                tables.append(cell)
        if in_table_listing and stripped.startswith("+--"):
            pass  # separator line, keep scanning
        if in_table_listing and not stripped:
            in_table_listing = False

        # Users
        m = re.search(r"database management system users \[", line, re.IGNORECASE)
        if m:
            in_table_listing = False

        # Dumped rows: capture table rows (| value | value |)
        if stripped.startswith("|") and "|" in stripped[1:]:
            cells = [c.strip() for c in stripped.strip("|").split("|")]
            row = " | ".join(c for c in cells if c)
            if row and row not in dumped_data:
                dumped_data.append(row)

        # Capture --sql-query retrieved rows (two formats):
        # UNION-based: "[*] value"  |  Blind: "[INFO] retrieved: value"
        m = re.match(r"\[\*\] (.+)", stripped)
        if m and not m.group(1).startswith("starting") and not m.group(1).startswith("ending"):
            row = m.group(1).strip()
            if row and row not in retrieved_rows:
                retrieved_rows.append(row)

        m = re.search(r"\[INFO\] retrieved: (.+)", line)
        if m:
            row = m.group(1).strip()
            if row and row not in retrieved_rows:
                retrieved_rows.append(row)

    result["vulnerable_params"] = vulnerable_params
    result["dbms"] = dbms
    result["injection_types"] = injection_types
    result["tables"] = tables
    result["databases"] = databases
    result["users"] = users
    result["dumped_data"] = dumped_data
    result["retrieved_rows"] = retrieved_rows
    return result
