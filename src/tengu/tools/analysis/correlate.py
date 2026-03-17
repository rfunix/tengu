"""Finding correlation and risk scoring analysis tools."""

from __future__ import annotations

from fastmcp import Context

from tengu.tools.analysis.scoring import (
    SEVERITY_WEIGHTS as _SEVERITY_WEIGHTS,
)
from tengu.tools.analysis.scoring import (
    calculate_risk_score,
    score_to_rating,
)

# Per-tool confidence weights — how reliable is each tool's finding?
# 1.0 = confirmed exploitable, 0.5 = informational / high false-positive rate
_TOOL_CONFIDENCE: dict[str, float] = {
    "sqlmap": 0.95,
    "nuclei": 0.85,
    "dalfox": 0.80,
    "nmap": 0.90,
    "nikto": 0.50,
    "ffuf": 0.70,
    "feroxbuster": 0.70,
    "commix": 0.85,
    "hydra": 0.90,
    "wpscan": 0.75,
    "gobuster": 0.65,
    "trivy": 0.80,
    "gitleaks": 0.75,
    "trufflehog": 0.85,
    "testssl": 0.80,
    "wafw00f": 0.70,
    "crlfuzz": 0.75,
    "whatweb": 0.60,
    "arjun": 0.65,
    "katana": 0.60,
    "searchsploit": 0.70,
    "metasploit": 0.95,
    "zap": 0.75,
}

DEFAULT_CONFIDENCE = 0.60


def _deduplicate_findings(
    findings: list[dict],
) -> tuple[list[dict], list[dict]]:
    """Deduplicate findings reported by multiple tools on the same asset.

    Groups findings by ``(affected_asset, owasp_category)`` or
    ``(affected_asset, cve_id)``.  When multiple tools report the same
    finding, the one with the highest tool confidence is kept; the others
    are recorded as *conflicts*.

    Returns:
        ``(deduplicated, conflicts)`` — *conflicts* lists cases where
        tools disagreed or duplicated a finding.
    """
    # Build groups keyed by (asset, category_or_cve)
    groups: dict[tuple[str, str], list[dict]] = {}

    for f in findings:
        asset = f.get("affected_asset", f.get("url", "unknown"))
        # Try CVE ID first (most precise), then OWASP category
        cve_ids = f.get("cve_ids") or f.get("cve_id")
        owasp = f.get("owasp_category", "")
        if isinstance(owasp, list):
            owasp = owasp[0] if owasp else ""

        if cve_ids:
            if isinstance(cve_ids, list):
                for cve in cve_ids:
                    key = (str(asset), str(cve))
                    groups.setdefault(key, []).append(f)
            else:
                key = (str(asset), str(cve_ids))
                groups.setdefault(key, []).append(f)
        elif owasp:
            key = (str(asset), str(owasp))
            groups.setdefault(key, []).append(f)
        else:
            # No grouping key — keep as-is in a unique bucket
            key = (str(asset), f"_unique_{id(f)}")
            groups[key] = [f]

    deduplicated: list[dict] = []
    conflicts: list[dict] = []

    for (asset, group_key), group in groups.items():
        if len(group) == 1:
            deduplicated.append(group[0])
            continue

        # Multiple tools — pick the one with highest confidence
        scored = sorted(
            group,
            key=lambda f: _TOOL_CONFIDENCE.get(f.get("tool", ""), DEFAULT_CONFIDENCE),
            reverse=True,
        )
        best = scored[0]
        deduplicated.append(best)

        # Record the conflict
        conflicts.append(
            {
                "affected_asset": asset,
                "group_key": group_key,
                "kept": {
                    "tool": best.get("tool", "unknown"),
                    "severity": best.get("severity", "info"),
                    "confidence": _TOOL_CONFIDENCE.get(best.get("tool", ""), DEFAULT_CONFIDENCE),
                },
                "duplicates": [
                    {
                        "tool": f.get("tool", "unknown"),
                        "severity": f.get("severity", "info"),
                        "confidence": _TOOL_CONFIDENCE.get(f.get("tool", ""), DEFAULT_CONFIDENCE),
                    }
                    for f in scored[1:]
                ],
            }
        )

    return deduplicated, conflicts


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

    # Deduplicate findings from multiple tools on the same asset
    parsed, dedup_conflicts = _deduplicate_findings(findings)
    deduplicated_count = len(findings) - len(parsed)

    # Count by severity
    severity_counts: dict[str, int] = {}
    for f in parsed:
        sev = f.get("severity", "info").lower()
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    # Identify OWASP categories present
    owasp_present = set()
    for f in parsed:
        owasp = f.get("owasp_category", "")
        # Normalize: LLM may return a list instead of a string
        if isinstance(owasp, list):
            owasp = owasp[0] if owasp else ""
        owasp = str(owasp)
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
    risk_score = calculate_risk_score(parsed, attack_chains=attack_chains)

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
        "original_findings_count": len(findings),
        "deduplicated_count": deduplicated_count,
        "conflicts": dedup_conflicts,
        "severity_breakdown": severity_counts,
        "tools_used": tools_used,
        "owasp_categories_present": sorted(owasp_present),
        "attack_chains_identified": attack_chains,
        "exploitable_findings_count": len(exploitable_findings),
        "high_risk_assets": high_risk_assets,
        "overall_risk_score": round(risk_score, 1),
        "risk_rating": score_to_rating(risk_score),
        "remediation_priority": _build_remediation_priority(parsed),
    }


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
        if cvss is not None:
            cvss_total += float(cvss)
            cvss_count += 1

    avg_cvss = cvss_total / cvss_count if cvss_count > 0 else 0.0

    # Apply context multiplier
    context_multiplier = 1.0
    if context:
        context_lower = context.lower()
        if any(word in context_lower for word in ["external", "internet", "public"]):
            context_multiplier = 1.2
        elif any(word in context_lower for word in ["internal", "intranet", "vpn"]):
            context_multiplier = 0.9

    # Use unified scoring algorithm
    final_score = calculate_risk_score(
        findings,
        context_multiplier=context_multiplier,
    )

    await ctx.report_progress(2, 2, "Done")

    return {
        "tool": "score_risk",
        "findings_count": len(findings),
        "overall_risk_score": round(final_score, 1),
        "risk_rating": score_to_rating(final_score),
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
