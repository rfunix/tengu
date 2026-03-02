# Show HN: Tengu — Post for Hacker News

## Title

```
Show HN: Tengu – an open-source MCP server that turns Claude into a pentesting copilot
```

## Text

```
Hi HN,

I built Tengu, an open-source MCP server (MIT) that connects Claude to 66 real
pentesting tools — Nmap, Metasploit, SQLMap, Nuclei, Hydra, ZAP, and more.

You describe what you want ("do a full pentest on 192.168.1.100") and the LLM
chains the right tools automatically: validate_target → whatweb → nmap → nikto →
nuclei → sqlmap → correlate_findings → generate_report.

What makes it different from "ChatGPT runs nmap":

- Safety pipeline on every call: input sanitizer (rejects shell metacharacters),
  target allowlist, rate limiter, audit logger. shell=True is banned — 74 tests
  specifically for command injection.

- Human-in-the-loop for anything destructive: exploits, brute force, and
  kerberoasting require explicit confirmation before execution.

- Stealth layer: optional Tor/SOCKS5 proxy injection, UA rotation, and timing
  jitter — transparent to tool code.

- Professional reporting: auto-correlates findings across tools, calculates CVSS
  risk scores, generates MD/HTML/PDF reports.

- 2300+ tests, mypy strict, ruff, 90%+ coverage. Not a weekend hack.

It also ships with 35 guided workflow prompts (full PTES pentest, bug bounty,
AD assessment, cloud audit, compliance checks) and 20 built-in resources
(OWASP Top 10, MITRE ATT&CK, pentest checklists).

Docker-first: `make docker-build && make docker-up` gets you running.
Practice targets (Juice Shop, DVWA) included via `make docker-lab`.

Tech: Python 3.12+, FastMCP 2.0, Pydantic v2, structlog, asyncio.

GitHub: https://github.com/rfunix/tengu

Happy to answer questions about the security model, MCP integration, or
anything else.
```

## Best Time to Post

| Window | UTC | BRT (Brasília) | Breakout Rate |
|--------|-----|----------------|---------------|
| **#1 (best)** | Sunday 11:00–14:00 UTC | Sunday 08:00–11:00 BRT | ~14% |
| **#2** | Saturday 20:00–02:00 UTC | Saturday 17:00–23:00 BRT | ~15.7% |
| **#3 (absolute peak)** | Sunday 12:00 UTC | Sunday 09:00 BRT | 12.2% |

**Recommendation: Sunday at 09:00 BRT (12:00 UTC / 08:00 AM EDT)**

- Sunday has 20–30% higher breakout chance than weekdays
- 12:00 UTC is the single best-performing hour historically
- Aligns with early morning on the US East Coast (primary HN audience)
- Less competition from corporate posts on weekends

**Backup:** Saturday at 17:00 BRT (20:00 UTC).

## Tips

1. Do not ask anyone for upvotes — HN detects and penalizes vote rings.
2. Reply to comments quickly in the first 2 hours — it boosts ranking.
3. Prepare answers for predictable objections:
   - *"Isn't giving an LLM access to exploit tools dangerous?"*
     → Safety pipeline, allowlist, human-in-the-loop gate for destructive actions.
   - *"How is this different from AutoGPT + bash?"*
     → MCP protocol, structured tool calls, no shell=True, 74 injection tests.
   - *"Why not just use Metasploit/Caldera?"*
     → LLM as strategist, not rigid automation; natural language → multi-tool chains.
