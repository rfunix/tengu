"""Professional reporting prompts for Tengu."""

from __future__ import annotations


def executive_report(
    findings: list[dict],
    client_name: str,
    engagement_date: str,
) -> str:
    """Generate an executive-level security report prompt."""
    critical = sum(1 for f in findings if f.get("severity") == "critical")
    high = sum(1 for f in findings if f.get("severity") == "high")
    medium = sum(1 for f in findings if f.get("severity") == "medium")

    return f"""You are a senior security consultant writing an executive summary for {client_name}.

## Engagement Data
- Client: {client_name}
- Assessment Date: {engagement_date}
- Findings: {critical} Critical, {high} High, {medium} Medium, and others

## Your Task
Write a concise executive summary (3-5 paragraphs) for the C-Level audience that:

1. **Opens with the overall security posture** — Describe in business terms whether the
   organization's security is strong, adequate, or at risk. Avoid technical jargon.

2. **Highlights the top 3 business risks** — Translate technical findings into business
   impact (data breach, regulatory fines, reputational damage, service disruption).

3. **Provides strategic recommendations** — 3-5 high-level actions the board or C-suite
   should prioritize or fund.

4. **Closes with a risk outlook** — Brief assessment of what happens if findings are not
   addressed vs. what the security posture looks like post-remediation.

## Style Guidelines
- Write for a non-technical audience
- Use business language (risk, impact, investment, compliance)
- No CVE numbers, CVSS scores, or technical tool names in this section
- Tone: Professional, clear, actionable — not alarmist

## Finding Summary (for context)
{_format_findings_for_prompt(findings[:10])}

Write the executive summary now.
"""


def technical_report(
    findings: list[dict],
    client_name: str,
    scope: list[str],
    methodology: str = "PTES",
) -> str:
    """Generate a technical findings report prompt."""
    return f"""You are a senior penetration tester writing the technical findings section
for a report to {client_name}.

## Context
- Scope: {", ".join(scope)}
- Methodology: {methodology}
- Total Findings: {len(findings)}

## Your Task
For each finding below, write a professional technical documentation that includes:

1. **Clear description** of the vulnerability (what, why it exists, how it was found)
2. **Technical impact** — what an attacker can do if they exploit this
3. **Business impact** — data at risk, compliance implications, service disruption
4. **Evidence** — reference the captured proof-of-concept
5. **Detailed remediation** — specific code changes, configuration updates, or architectural improvements

## Findings to Document
{_format_findings_for_prompt(findings)}

Write thorough, professional documentation for each finding. Use the TENGU-YYYY-NNN
ID format for cross-referencing. Be specific and actionable.
"""


def full_pentest_report(
    findings: list[dict],
    client_name: str,
    scope: list[str],
    rules_of_engagement: str,
    methodology: str = "PTES",
    engagement_dates: str = "",
) -> str:
    """Generate a complete professional pentest report using generate_report."""
    return f"""Generate a complete, professional penetration test report for {client_name}.

## Report Parameters
- Client: {client_name}
- Scope: {", ".join(scope)}
- Engagement Dates: {engagement_dates}
- Methodology: {methodology}
- Rules of Engagement: {rules_of_engagement}
- Total Findings: {len(findings)}

## Instructions

1. First, use `score_risk` with these findings to calculate the overall risk score.

2. Then use `generate_report` with these parameters:
   - client_name="{client_name}"
   - engagement_type="blackbox"  (adjust if known)
   - scope={scope}
   - engagement_dates="{engagement_dates}"
   - findings=(the findings list below)
   - report_type="full"
   - output_format="html"
   - output_path="./reports/{client_name.replace(" ", "_")}_pentest_report.html"

3. Also generate with output_format="markdown" for version control.

4. Write the executive_summary field as a clear, business-focused 3-paragraph summary.

5. Write the conclusion as a forward-looking paragraph on remediation and security maturity.

## Findings Data
{_format_findings_for_prompt(findings)}

Generate the complete report now.
"""


def remediation_plan(
    findings: list[dict],
    priority: str = "risk",
) -> str:
    """Generate a remediation plan prompt."""
    sort_key = {
        "risk": "CVSS score and severity",
        "effort": "implementation effort (quick wins first)",
        "quick-wins": "fast fixes that can be deployed immediately",
    }.get(priority, "risk")

    return f"""Create a detailed, actionable remediation roadmap for the following findings.
Prioritize by: **{sort_key}**.

## Remediation Timeline Framework

### Immediate (0-30 Days) — Critical & High
Address vulnerabilities that pose immediate risk of exploitation or data breach.
Provide specific technical steps for each.

### Short-Term (30-90 Days) — Medium
Address vulnerabilities that could be exploited with more effort.
Include architectural improvements.

### Medium-Term (90-180 Days) — Low
Address security hygiene issues and implement defense-in-depth measures.

### Long-Term (180+ Days) — Strategic
Architecture changes, security program improvements, training.

## Findings to Remediate
{_format_findings_for_prompt(findings)}

For each finding, provide:
1. Specific technical fix (code snippet, config change, or command)
2. Verification method (how to confirm the fix worked)
3. Estimated effort (hours/days)
4. Required resources (team, tools, vendor patches)

Create the remediation plan now.
"""


def finding_detail(
    vulnerability: str,
    target: str,
    evidence: str = "",
    cvss_vector: str = "",
) -> str:
    """Generate a detailed finding documentation prompt."""
    return f"""Document the following vulnerability as a professional pentest finding.

## Finding Information
- Vulnerability: {vulnerability}
- Affected Target: {target}
- CVSS Vector: {cvss_vector or "Not calculated"}
- Evidence: {evidence or "See attached"}

## Required Output Format

Generate a complete finding document with:

1. **Finding ID**: TENGU-{__import__("datetime").datetime.now().year}-XXX (assign appropriate number)
2. **Title**: Concise, descriptive title (max 80 chars)
3. **Severity**: Critical/High/Medium/Low/Informational
4. **CVSS Score**: Calculate from vector if provided, or estimate based on impact
5. **CWE ID**: Identify the most appropriate CWE
6. **OWASP Category**: Map to OWASP Top 10:2025
7. **Description**: Detailed technical description (2-3 paragraphs)
8. **Impact**: Technical impact + business impact
9. **Steps to Reproduce**: Numbered, specific steps anyone can follow
10. **Evidence**: Format the provided evidence professionally
11. **Remediation (Quick Fix)**: Immediate mitigation (1-2 sentences)
12. **Remediation (Long-term)**: Complete fix with code examples or config changes
13. **References**: OWASP, CWE, NVD, vendor advisories

Use `owasp://top10/2025` and `cwe://{vulnerability.split()[0]}` resources for reference.

Document this finding now in the standard format.
"""


def risk_matrix(findings: list[dict]) -> str:
    """Generate a risk matrix visualization prompt."""
    return f"""Create a comprehensive risk matrix for the following {len(findings)} findings.

## Required Output

1. **5x5 Risk Matrix** (Likelihood × Impact)
   Place each finding in the appropriate cell based on its CVSS exploitability
   and impact sub-scores.

2. **Severity Distribution Chart** (text-based bar chart)

3. **OWASP Top 10 Coverage** — Which categories were found

4. **Asset Risk Profile** — Risk score per affected system/application

5. **Top 5 Highest Risk Findings** with brief justification

Use `generate_report` with report_type="risk_matrix" for the formatted output.

## Findings
{_format_findings_for_prompt(findings)}
"""


def retest_report(
    original_findings: list[dict],
    retest_results: list[dict],
) -> str:
    """Generate a retest/verification report prompt."""
    return f"""Write a professional retest report comparing original findings against retest results.

## Context
- Original Assessment: {len(original_findings)} findings
- Retest Results: {len(retest_results)} items retested

## Required Report Structure

### Retest Summary Table

| Finding ID | Title | Original Severity | Status | Notes |
|------------|-------|------------------|--------|-------|
(Fill in for each finding)

### Remediated Findings (Closed)
For each successfully remediated finding:
- Confirm the fix is effective
- Note the remediation approach used
- Mark as RESOLVED

### Partially Remediated
Findings where the fix is incomplete or introduces new issues.

### Outstanding Findings (Still Open)
Findings that were not fixed or where the fix failed.

### New Findings Discovered During Retest
Any additional vulnerabilities identified during the retest process.

### Overall Security Improvement Score
Calculate the improvement in risk score from original to retest.

## Data
Original Findings:
{_format_findings_for_prompt(original_findings)}

Retest Results:
{_format_findings_for_prompt(retest_results)}
"""


def _format_findings_for_prompt(findings: list[dict]) -> str:
    """Format findings for inclusion in prompts."""
    if not findings:
        return "No findings provided."

    lines = []
    for i, f in enumerate(findings[:20]):
        lines.append(
            f"{i + 1}. [{f.get('severity', 'unknown').upper()}] "
            f"{f.get('title', f.get('template_name', 'Unknown'))} "
            f"— {f.get('affected_asset', f.get('url', 'N/A'))} "
            f"(CVSS: {f.get('cvss_score', 'N/A')})"
        )

    if len(findings) > 20:
        lines.append(f"... and {len(findings) - 20} more findings.")

    return "\n".join(lines)
