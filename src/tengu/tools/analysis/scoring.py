"""Unified risk scoring algorithm for Tengu.

Used by both ``score_risk`` and ``generate_report`` to ensure consistent
risk scores across all output surfaces.
"""

from __future__ import annotations

# CVSS-based severity weights (fallback when no real CVSS score is provided)
SEVERITY_WEIGHTS: dict[str, float] = {
    "critical": 10.0,
    "high": 7.5,
    "medium": 5.0,
    "low": 2.5,
    "info": 0.5,
}


def calculate_risk_score(
    findings: list[dict],
    *,
    attack_chains: list[dict] | None = None,
    context_multiplier: float = 1.0,
) -> float:
    """Calculate a unified risk score (0-10) from findings.

    Algorithm:
        1. For each finding, use its ``cvss_score`` if present, otherwise
           fall back to the fixed severity weight.
        2. Exclude informational findings to avoid diluting the score.
        3. Compute the weighted average of all scored findings.
        4. Add a boost for identified attack chains (0.5 per chain, max 2.0).
        5. Add a boost for each critical finding (0.3 each, max 1.5).
        6. Apply the optional context multiplier (e.g. 1.2 for external targets).
        7. Clamp to [0.0, 10.0].

    Args:
        findings: List of finding dicts. Each should have at least ``severity``.
                  ``cvss_score`` is optional but preferred.
        attack_chains: Optional list of identified attack chain dicts.
        context_multiplier: Multiplier for engagement context (default 1.0).

    Returns:
        Risk score between 0.0 and 10.0.
    """
    if not findings:
        return 0.0

    # Step 1-2: collect per-finding scores, exclude informational
    info_sevs = {"info", "informational"}
    scored = [f for f in findings if f.get("severity", "info").lower() not in info_sevs]
    scored_or_all = scored if scored else findings

    cvss_scores = [
        f.get("cvss_score")
        if f.get("cvss_score")
        else SEVERITY_WEIGHTS.get(f.get("severity", "info").lower(), 0)
        for f in scored_or_all
    ]

    # Coerce to float safely
    safe_scores = []
    for s in cvss_scores:
        try:
            safe_scores.append(float(s))
        except (ValueError, TypeError):
            safe_scores.append(0.0)

    # Step 3: weighted average
    base_score = sum(safe_scores) / len(safe_scores) if safe_scores else 0.0

    # Step 4: attack chain boost
    chain_boost = 0.0
    if attack_chains:
        chain_boost = min(len(attack_chains) * 0.5, 2.0)

    # Step 5: critical boost
    critical_count = sum(1 for f in findings if f.get("severity", "").lower() == "critical")
    critical_boost = min(critical_count * 0.3, 1.5)

    # Step 6-7: apply context multiplier and clamp
    final = (base_score + chain_boost + critical_boost) * context_multiplier
    return round(min(max(final, 0.0), 10.0), 1)


def score_to_rating(score: float) -> str:
    """Convert a numeric risk score to a human-readable rating."""
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    if score >= 1.0:
        return "LOW"
    return "INFORMATIONAL"
