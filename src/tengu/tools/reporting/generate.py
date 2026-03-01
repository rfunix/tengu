"""Report generation tool using Jinja2 templates.

Generates professional penetration test reports in Markdown, HTML, and PDF formats.
"""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Literal

import structlog
from fastmcp import Context

from tengu.types import Finding, PentestReport, RiskMatrix, ToolInfo

logger = structlog.get_logger(__name__)

ReportFormat = Literal["markdown", "html", "pdf"]
ReportType = Literal["full", "executive", "technical", "finding", "risk_matrix"]

_TEMPLATES_DIR = Path(__file__).parent / "templates"

_SEVERITY_WEIGHTS = {
    "critical": 10.0,
    "high": 7.5,
    "medium": 5.0,
    "low": 2.5,
    "info": 0.5,
}


def _normalize_finding(f: dict, index: int) -> dict:  # type: ignore[type-arg]
    """Normalize a loose finding dict into a Finding-compatible dict.

    Accepts simplified formats from AI tool calls (e.g. url/parameter/remediation
    as plain strings) and maps them to the Finding model's field names.
    """
    out = dict(f)

    # Auto-generate ID if missing
    if not out.get("id"):
        out["id"] = f"TENGU-{datetime.now().year}-{index:03d}"

    # Map 'url' → 'affected_asset' if affected_asset not present
    if not out.get("affected_asset"):
        out["affected_asset"] = out.pop("url", out.get("target", "unknown"))

    # Remove keys that don't belong to Finding
    for key in ("url", "target", "parameter"):
        out.pop(key, None)

    # Map 'remediation' (string) → 'remediation_short'
    if "remediation" in out and not out.get("remediation_short"):
        out["remediation_short"] = out.pop("remediation")
    else:
        out.pop("remediation", None)

    # Normalize 'evidence': str or list[str] → list[Evidence dict]
    raw_evidence = out.get("evidence")
    if isinstance(raw_evidence, str):
        out["evidence"] = [{"type": "tool_output", "title": "Evidence", "content": raw_evidence}]
    elif isinstance(raw_evidence, list):
        normalized_ev = []
        for ev in raw_evidence:
            if isinstance(ev, str):
                normalized_ev.append({"type": "tool_output", "title": "Evidence", "content": ev})
            elif isinstance(ev, dict) and "type" in ev and "title" in ev and "content" in ev:
                normalized_ev.append(ev)
        out["evidence"] = normalized_ev
    else:
        out.pop("evidence", None)

    return out


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


def _build_risk_matrix(findings: list[Finding]) -> RiskMatrix:
    """Build a RiskMatrix from a list of findings."""
    matrix = RiskMatrix(
        critical_count=sum(1 for f in findings if f.severity == "critical"),
        high_count=sum(1 for f in findings if f.severity == "high"),
        medium_count=sum(1 for f in findings if f.severity == "medium"),
        low_count=sum(1 for f in findings if f.severity == "low"),
        info_count=sum(1 for f in findings if f.severity == "info"),
        total=len(findings),
    )

    if findings:
        weighted = sum(_SEVERITY_WEIGHTS.get(f.severity, 0) for f in findings)
        matrix.risk_score = round(min(weighted / len(findings), 10.0), 1)

    return matrix


async def generate_report(
    ctx: Context,  # type: ignore[type-arg]
    client_name: str,
    engagement_type: str = "blackbox",
    scope: list[str] | None = None,
    exclusions: list[str] | None = None,
    engagement_dates: str = "",
    findings: list[dict] | None = None,  # type: ignore[type-arg]
    executive_summary: str = "",
    conclusion: str = "",
    report_type: ReportType = "full",
    output_format: ReportFormat = "markdown",
    output_path: str = "",
    tools_used: list[str] | None = None,
) -> dict:  # type: ignore[type-arg]
    """Generate a professional penetration test report.

    Creates a comprehensive security assessment report from collected findings,
    formatted according to industry standards (PTES, OWASP).

    Args:
        client_name: Name of the client organization.
        engagement_type: Type of test: 'blackbox', 'greybox', or 'whitebox'.
        scope: List of in-scope targets (IPs, domains, URLs).
        exclusions: List of explicitly excluded targets.
        engagement_dates: Testing period (e.g. "2026-02-15 to 2026-02-28").
        findings: List of finding dicts from Tengu tools.
        executive_summary: Executive summary text (can be LLM-generated).
        conclusion: Report conclusion text.
        report_type: 'full', 'executive', 'technical', 'finding', or 'risk_matrix'.
        output_format: 'markdown', 'html', or 'pdf'.
        output_path: File path to save the report. If empty, returns content inline.
        tools_used: List of tool names used during the engagement.

    Returns:
        Generated report content and metadata.
    """
    await ctx.report_progress(0, 5, "Preparing report data...")

    if engagement_type not in ("blackbox", "greybox", "whitebox"):
        engagement_type = "blackbox"

    # Parse findings
    parsed_findings: list[Finding] = []
    for f in findings or []:
        try:
            normalized = _normalize_finding(f, len(parsed_findings) + 1)
            parsed_findings.append(Finding(**normalized))
        except Exception as exc:
            logger.warning("Skipping invalid finding", error=str(exc))

    # Sort by CVSS descending
    parsed_findings.sort(key=lambda f: f.cvss_score, reverse=True)

    # Build report model
    tool_infos = [ToolInfo(name=t) for t in (tools_used or [])]

    risk_matrix = _build_risk_matrix(parsed_findings)

    # Calculate overall risk score
    if parsed_findings:
        weighted = sum(_SEVERITY_WEIGHTS.get(f.severity, 0) for f in parsed_findings)
        overall_score = round(min(weighted / len(parsed_findings), 10.0), 1)
    else:
        overall_score = 0.0

    report = PentestReport(
        client_name=client_name,
        engagement_type=engagement_type,  # type: ignore[arg-type]
        scope=scope or [],
        exclusions=exclusions or [],
        engagement_dates=engagement_dates or datetime.now().strftime("%Y-%m-%d"),
        tools_used=tool_infos,
        findings=parsed_findings,
        overall_risk_score=overall_score,
        executive_summary=executive_summary or None,
        conclusion=conclusion or None,
        risk_matrix=risk_matrix,
    )

    await ctx.report_progress(2, 5, "Rendering template...")

    # Build OWASP distribution
    owasp_distribution: dict[str, int] = {}
    for f in parsed_findings:
        if f.owasp_category:
            owasp_distribution[f.owasp_category] = owasp_distribution.get(f.owasp_category, 0) + 1

    template_context = {
        "report": report,
        "risk_matrix": risk_matrix,
        "risk_rating": _score_to_rating(overall_score),
        "owasp_distribution": owasp_distribution,
        # For risk_matrix template
        "client_name": client_name,
        "engagement_dates": engagement_dates,
        "critical_count": risk_matrix.critical_count,
        "high_count": risk_matrix.high_count,
        "medium_count": risk_matrix.medium_count,
        "low_count": risk_matrix.low_count,
        "info_count": risk_matrix.info_count,
        "overall_risk_score": overall_score,
    }

    template_map: dict[str, str] = {
        "full": "full_report.md.j2",
        "executive": "executive_report.md.j2",
        "technical": "full_report.md.j2",  # Same template, different sections
        "risk_matrix": "risk_matrix.md.j2",
    }

    template_file = template_map.get(report_type, "full_report.md.j2")
    markdown_content = _render_template(template_file, template_context)

    await ctx.report_progress(3, 5, f"Generating {output_format} output...")

    final_content = markdown_content

    if output_format == "html":
        final_content = _markdown_to_html(markdown_content, client_name)
    elif output_format == "pdf":
        try:
            html = _markdown_to_html(markdown_content, client_name)
            final_content = _html_to_pdf(html)
        except ImportError:
            logger.warning("WeasyPrint not installed — returning Markdown instead")
            output_format = "markdown"

    await ctx.report_progress(4, 5, "Saving report...")

    # Save to file if path provided
    saved_path = None
    if output_path:
        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        mode = "wb" if output_format == "pdf" else "w"
        encoding = None if output_format == "pdf" else "utf-8"
        with path.open(mode, encoding=encoding) as f:
            f.write(final_content)  # type: ignore[arg-type]
        saved_path = str(path.resolve())

    await ctx.report_progress(5, 5, "Report complete")

    return {
        "tool": "generate_report",
        "report_type": report_type,
        "output_format": output_format,
        "client_name": client_name,
        "findings_count": len(parsed_findings),
        "overall_risk_score": overall_score,
        "risk_rating": _score_to_rating(overall_score),
        "saved_to": saved_path,
        "content": final_content if output_format != "pdf" else "[PDF binary — saved to file]",
    }


def _render_template(template_name: str, context: dict) -> str:  # type: ignore[type-arg]
    """Render a Jinja2 template with the given context."""
    try:
        from jinja2 import Environment, FileSystemLoader, select_autoescape

        env = Environment(
            loader=FileSystemLoader(str(_TEMPLATES_DIR)),
            autoescape=select_autoescape(["html"]),
            trim_blocks=True,
            lstrip_blocks=True,
        )
        template = env.get_template(template_name)
        return template.render(**context)

    except ImportError:
        # Fallback: simple JSON report if Jinja2 not installed
        logger.warning("Jinja2 not installed — generating JSON report")
        return json.dumps(
            {k: str(v) for k, v in context.items()},
            indent=2,
            default=str,
        )
    except Exception as exc:
        logger.error("Template rendering failed", template=template_name, error=str(exc))
        return f"# Report Generation Error\n\nFailed to render template: {exc}"


def _markdown_to_html(markdown: str, title: str = "Pentest Report") -> str:
    """Convert Markdown to styled HTML."""
    try:
        import markdown as md  # type: ignore[import]

        html_body = md.markdown(
            markdown,
            extensions=["tables", "fenced_code", "toc", "attr_list"],
        )
    except ImportError:
        # Basic HTML escaping fallback
        import html as html_module

        html_body = f"<pre>{html_module.escape(markdown)}</pre>"

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>{title} — Penetration Test Report</title>
<style>
  :root {{
    --critical: #dc2626;
    --high: #ea580c;
    --medium: #ca8a04;
    --low: #16a34a;
    --info: #2563eb;
  }}
  body {{
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
    max-width: 1100px;
    margin: 0 auto;
    padding: 2rem;
    color: #1a1a1a;
    line-height: 1.6;
  }}
  h1 {{ color: #0f172a; border-bottom: 3px solid #dc2626; padding-bottom: 0.5rem; }}
  h2 {{ color: #0f172a; border-bottom: 1px solid #e2e8f0; padding-bottom: 0.3rem; margin-top: 2rem; }}
  h3 {{ color: #1e293b; }}
  table {{ border-collapse: collapse; width: 100%; margin: 1rem 0; }}
  th {{ background: #0f172a; color: white; padding: 0.5rem 1rem; text-align: left; }}
  td {{ padding: 0.5rem 1rem; border-bottom: 1px solid #e2e8f0; }}
  tr:nth-child(even) {{ background: #f8fafc; }}
  code {{ background: #f1f5f9; padding: 0.2rem 0.4rem; border-radius: 3px; font-size: 0.9em; }}
  pre {{ background: #1e293b; color: #e2e8f0; padding: 1rem; border-radius: 6px; overflow-x: auto; }}
  pre code {{ background: none; color: inherit; padding: 0; }}
  blockquote {{ border-left: 4px solid #dc2626; padding: 0.5rem 1rem; margin: 0; background: #fef2f2; }}
  .confidential {{
    background: #fef2f2;
    border: 2px solid #dc2626;
    padding: 0.5rem 1rem;
    text-align: center;
    font-weight: bold;
    color: #dc2626;
    margin-bottom: 2rem;
  }}
  @media print {{
    body {{ max-width: none; }}
    h1, h2, h3 {{ page-break-after: avoid; }}
    table {{ page-break-inside: avoid; }}
  }}
</style>
</head>
<body>
<div class="confidential">⚠️ CONFIDENTIAL — FOR AUTHORIZED RECIPIENTS ONLY ⚠️</div>
{html_body}
</body>
</html>"""


def _html_to_pdf(html: str) -> bytes:
    """Convert HTML to PDF using WeasyPrint."""
    try:
        from weasyprint import HTML  # type: ignore[import]

        return HTML(string=html).write_pdf()
    except ImportError as exc:
        raise ImportError(
            "WeasyPrint is not installed. Run: uv pip install 'tengu[reporting]'"
        ) from exc
