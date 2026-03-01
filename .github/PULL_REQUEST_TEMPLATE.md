## Summary

<!-- Brief description of what this PR changes and why. -->

## Type of Change

- [ ] Bug fix
- [ ] New tool
- [ ] Tool improvement
- [ ] Infrastructure / CI
- [ ] Documentation
- [ ] Refactoring (no behavior change)

## Checklist

### Code Quality
- [ ] `make lint` passes (ruff — 0 errors)
- [ ] `make typecheck` passes (mypy strict — 0 errors)
- [ ] `make format` applied

### Security (mandatory for all tool changes)
- [ ] No `shell=True` anywhere in new/changed code
- [ ] All user inputs sanitized via `sanitize_*` from `tengu.security.sanitizer`
- [ ] Allowlist check (`allowlist.check(target)`) present for tools accepting a target
- [ ] Rate limiting via `async with rate_limited("tool_name")` applied
- [ ] Audit logging (`log_tool_call`) with `started` + `completed`/`failed` entries

### Tests
- [ ] Unit tests added/updated in `tests/unit/`
- [ ] Security/injection tests added/updated in `tests/security/` (for new tools)
- [ ] `make test` passes (all unit + security tests green)

### New Tool (if applicable)
- [ ] Tool file created in `src/tengu/tools/<category>/<tool>.py`
- [ ] Tool registered in `server.py` (`mcp.tool()(my_tool)`)
- [ ] Added to `scripts/install-tools.sh`
- [ ] README badge count updated
- [ ] README tool table updated
- [ ] CLAUDE.md tool count updated

## Testing Notes

<!-- Describe how you tested this. Include any manual steps, edge cases checked, etc. -->

## Related Issues

<!-- Link any related issues: Closes #123, Relates to #456 -->
