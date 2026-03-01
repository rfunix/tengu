"""Finding correlation and risk scoring analysis tools."""

from __future__ import annotations

from fastmcp import Context

# CVSS-based severity weights for risk score calculation
_SEVERITY_WEIGHTS = {
    "critical": 10.0,
    "high": 7.5,
    "medium": 5.0,
    "low": 2.5,
    "info": 0.5,
}

# Attack chain patterns — combinations of findings that suggest a viable attack path
_ATTACK_CHAINS: list[dict] = [
    {
        "name": "SQL Injection → Data Exfiltration",
        "description": "SQL injection combined with sensitive data in scope suggests high-impact data breach potential.",
        "required_owasp": ["A03"],
        "severity": "critical",
    },
    {
        "name": "Broken Access Control → Privilege Escalation",
        "description": "Access control failures combined with authentication weaknesses indicate privilege escalation risk.",
        "required_owasp": ["A01", "A07"],
        "severity": "critical",
    },
    {
        "name": "Outdated Components → Known CVE Exploitation",
        "description": "Vulnerable components with public CVEs and available exploits represent a high exploitation risk.",
        "required_owasp": ["A06"],
        "severity": "high",
    },
    {
        "name": "Misconfiguration → Information Disclosure",
        "description": "Security misconfigurations exposing sensitive information can facilitate further attacks.",
        "required_owasp": ["A05"],
        "severity": "medium",
    },
    {
        "name": "XSS → Session Hijacking",
        "description": "Cross-site scripting with missing secure cookie flags enables session token theft.",
        "required_owasp": ["A03", "A07"],
        "severity": "high",
    },
    {
        "name": "SSRF → Internal Network Access",
        "description": "Server-Side Request Forgery can be used to probe internal network services.",
        "required_owasp": ["A10"],
        "severity": "high",
    },
]


async def correlate_findings(
    ctx: Context,
    findings: list[dict],
) -> dict:
    """Correlate multiple findings to identify attack chains and compound risks.

    Analyzes findings from multiple tools to identify patterns, attack chains,
    and compound risks that are more severe than individual findings suggest.

    Args:
        findings: List of Finding objects (as dicts) from any Tengu tool.
                  Each finding should have: severity, owasp_category, cve_ids, tool.

    Returns:
        Correlation analysis with identified attack chains, risk score,
        and prioritized remediation recommendations.
    """
    await ctx.report_progress(0, 3, "Correlating findings...")

    if not findings:
        return {
            "tool": "correlate_findings",
            "findings_count": 0,
            "attack_chains": [],
            "compound_risks": [],
            "overall_risk_score": 0.0,
            "message": "No findings to correlate.",
        }

    # Parse findings into Finding objects where possible
    parsed: list[dict] = findings

    # Count by severity
    severity_counts: dict[str, int] = {}
    for f in parsed:
        sev = f.get("severity", "info").lower()
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    # Identify OWASP categories present
    owasp_present = set()
    for f in parsed:
        owasp = f.get("owasp_category", "")
        # Extract category ID (e.g. "A03" from "A03:2025 - Injection")
        if owasp and owasp[:3].startswith("A") and owasp[1:3].isdigit():
            owasp_present.add(owasp[:3])

    await ctx.report_progress(1, 3, "Identifying attack chains...")

    # Identify viable attack chains
    attack_chains = []
    for chain in _ATTACK_CHAINS:
        required = set(chain["required_owasp"])
        if required.issubset(owasp_present):
            attack_chains.append(
                {
                    "name": chain["name"],
                    "description": chain["description"],
                    "severity": chain["severity"],
                    "relevant_owasp_categories": list(required),
                }
            )

    # Find findings with CVE IDs that have public exploits
    exploitable_findings = [f for f in parsed if f.get("cve_ids") or f.get("exploit_available")]

    await ctx.report_progress(2, 3, "Calculating compound risk score...")

    # Calculate overall risk score (0-10)
    risk_score = _calculate_risk_score(parsed, attack_chains)

    # Cross-tool correlations
    tools_used = list({f.get("tool", "unknown") for f in parsed})

    # Group findings by affected asset for asset-level risk assessment
    assets: dict[str, list] = {}
    for f in parsed:
        asset = f.get("affected_asset", "unknown")
        assets.setdefault(asset, []).append(f)

    high_risk_assets = [
        {
            "asset": asset,
            "finding_count": len(asset_findings),
            "highest_severity": max(
                (f.get("severity", "info") for f in asset_findings),
                key=lambda s: _SEVERITY_WEIGHTS.get(s, 0),
            ),
        }
        for asset, asset_findings in assets.items()
        if len(asset_findings) > 1
    ]

    await ctx.report_progress(3, 3, "Correlation complete")

    return {
        "tool": "correlate_findings",
        "findings_analyzed": len(parsed),
        "severity_breakdown": severity_counts,
        "tools_used": tools_used,
        "owasp_categories_present": sorted(owasp_present),
        "attack_chains_identified": attack_chains,
        "exploitable_findings_count": len(exploitable_findings),
        "high_risk_assets": high_risk_assets,
        "overall_risk_score": round(risk_score, 1),
        "risk_rating": _score_to_rating(risk_score),
        "remediation_priority": _build_remediation_priority(parsed),
    }


def _calculate_risk_score(
    findings: list[dict],
    attack_chains: list[dict],
) -> float:
    """Calculate an overall risk score (0-10) from findings and attack chains."""
    if not findings:
        return 0.0

    # Base score from CVSS average
    cvss_scores = [
        f.get("cvss_score", _SEVERITY_WEIGHTS.get(f.get("severity", "info"), 0)) for f in findings
    ]
    base_score = sum(cvss_scores) / len(cvss_scores) if cvss_scores else 0.0

    # Boost for attack chains (each chain adds 0.5, max 2.0)
    chain_boost = min(len(attack_chains) * 0.5, 2.0)

    # Count criticals
    critical_count = sum(1 for f in findings if f.get("severity") == "critical")
    critical_boost = min(critical_count * 0.3, 1.5)

    return min(base_score + chain_boost + critical_boost, 10.0)


def _score_to_rating(score: float) -> str:
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    if score >= 1.0:
        return "LOW"
    return "INFORMATIONAL"


def _build_remediation_priority(findings: list[dict]) -> list[dict]:
    """Build a prioritized remediation list."""
    # Sort by CVSS score descending, then by severity
    sorted_findings = sorted(
        findings,
        key=lambda f: (
            _SEVERITY_WEIGHTS.get(f.get("severity", "info"), 0),
            f.get("cvss_score", 0),
        ),
        reverse=True,
    )

    priority_list = []
    for i, finding in enumerate(sorted_findings[:20]):
        sev = finding.get("severity", "info")
        if sev in ("critical", "high"):
            timeframe = "0-30 days"
        elif sev == "medium":
            timeframe = "30-90 days"
        else:
            timeframe = "90-180 days"

        priority_list.append(
            {
                "priority": i + 1,
                "title": finding.get("title", finding.get("template_name", "Unknown finding")),
                "severity": sev,
                "cvss_score": finding.get("cvss_score", 0),
                "affected_asset": finding.get("affected_asset", finding.get("url", "")),
                "recommended_timeframe": timeframe,
                "tool": finding.get("tool", ""),
            }
        )

    return priority_list


async def score_risk(
    ctx: Context,
    findings: list[dict],
    context: str = "",
) -> dict:
    """Calculate a comprehensive risk score based on CVSS scores and engagement context.

    Args:
        findings: List of findings from any Tengu tool.
        context: Optional engagement context that affects risk multipliers
                 (e.g. "external-facing e-commerce", "internal HR system").

    Returns:
        Risk scorecard with overall score, breakdown, and risk matrix data.
    """
    await ctx.report_progress(0, 2, "Calculating risk score...")

    severity_counts: dict[str, int] = {}
    cvss_total = 0.0
    cvss_count = 0

    for f in findings:
        sev = f.get("severity", "info").lower()
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

        cvss = f.get("cvss_score")
        if cvss:
            cvss_total += float(cvss)
            cvss_count += 1

    avg_cvss = cvss_total / cvss_count if cvss_count > 0 else 0.0

    # Weight by severity distribution
    weighted_score = sum(
        count * _SEVERITY_WEIGHTS.get(sev, 0) for sev, count in severity_counts.items()
    )

    # Normalize to 0-10
    normalized = min(weighted_score / len(findings), 10.0) if findings else 0.0

    # Apply context multiplier
    context_multiplier = 1.0
    if context:
        context_lower = context.lower()
        if any(word in context_lower for word in ["external", "internet", "public"]):
            context_multiplier = 1.2
        elif any(word in context_lower for word in ["internal", "intranet", "vpn"]):
            context_multiplier = 0.9

    final_score = min(normalized * context_multiplier, 10.0)

    await ctx.report_progress(2, 2, "Done")

    return {
        "tool": "score_risk",
        "findings_count": len(findings),
        "overall_risk_score": round(final_score, 1),
        "risk_rating": _score_to_rating(final_score),
        "average_cvss": round(avg_cvss, 1),
        "severity_distribution": severity_counts,
        "risk_matrix": {
            "critical": severity_counts.get("critical", 0),
            "high": severity_counts.get("high", 0),
            "medium": severity_counts.get("medium", 0),
            "low": severity_counts.get("low", 0),
            "info": severity_counts.get("info", 0),
        },
        "context_applied": context or "none",
        "context_multiplier": context_multiplier,
    }
