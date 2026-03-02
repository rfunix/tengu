# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.2.x   | Yes       |
| 0.1.x   | No        |

## Scope

This security policy covers **Tengu itself** — the MCP server, its security pipeline
(sanitizer, allowlist, rate limiter, audit logger), and the Docker configuration.

It does **not** cover vulnerabilities in the external tools that Tengu orchestrates
(Nmap, Metasploit, SQLMap, etc.). Report those to their respective upstream projects.

## Reporting a Vulnerability

**Please do not open a public GitHub issue for security vulnerabilities.**

### Option 1 — GitHub Security Advisories (preferred)

1. Go to the [Tengu repository](https://github.com/rfunix/tengu)
2. Click **Security** → **Advisories** → **Report a vulnerability**
3. Fill in the details and submit

GitHub will keep the report private until a fix is ready.

### Option 2 — Email

Send details to: **rafinha.unix@gmail.com**

Include:
- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (optional)

## What to Expect

- **Acknowledgement**: within 48 hours
- **Initial assessment**: within 7 days
- **Fix timeline**: depends on severity
  - Critical: target 7 days
  - High: target 14 days
  - Medium/Low: target 30 days
- **Credit**: reporters are credited in the release notes unless they prefer anonymity

## Responsible Disclosure

We follow [coordinated vulnerability disclosure](https://cheatsheetseries.owasp.org/cheatsheets/Vulnerability_Disclosure_Cheat_Sheet.html).
Please give us a reasonable time to release a fix before public disclosure.

## Out of Scope

- Vulnerabilities in external pentesting tools (Nmap, Metasploit, SQLMap, etc.)
- Findings from scanning targets without authorization (Tengu requires explicit allowlisting)
- Issues that require physical access to the machine running Tengu
- Social engineering attacks against Tengu maintainers
