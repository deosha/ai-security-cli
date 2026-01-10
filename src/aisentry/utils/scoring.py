"""
Security Scoring Utilities

Centralized scoring logic used by all reporters (HTML, JSON, CLI).
Ensures consistent scoring across all output formats.
"""

import math
from typing import Any, Dict, List, Optional, Tuple, Union

from aisentry.models.finding import Finding
from aisentry.models.result import CategoryScore

# Risk level thresholds and colors
RISK_LEVELS = [
    (90, "EXCELLENT", "#10b981"),
    (75, "GOOD", "#3b82f6"),
    (60, "ADEQUATE", "#f59e0b"),
    (40, "NEEDS_IMPROVEMENT", "#ef4444"),
    (20, "POOR", "#dc2626"),
    (0, "CRITICAL", "#991b1b")
]


def calculate_overall_score(
    findings: Optional[List[Union[Finding, Dict[str, Any]]]] = None,
    category_scores: Optional[Union[List[CategoryScore], Dict[str, CategoryScore]]] = None
) -> float:
    """
    Calculate overall security score (0-100)

    Uses framework category scores if available, otherwise calculates
    from findings using diminishing returns algorithm.

    Args:
        findings: List of Finding objects or dicts
        category_scores: Framework category scores (list or dict)

    Returns:
        Score from 0-100
    """
    # If we have framework scores, use them (confidence-weighted average)
    if category_scores:
        return _score_from_categories(category_scores)

    # Otherwise, calculate from findings
    if findings:
        return _score_from_findings(findings)

    # No data available
    return 100.0


def _score_from_categories(
    category_scores: Union[List[CategoryScore], Dict[str, CategoryScore]]
) -> float:
    """Calculate score from framework category scores"""

    # Convert dict to list if needed
    if isinstance(category_scores, dict):
        category_scores = list(category_scores.values())

    if not category_scores:
        return 100.0

    # Use confidence-weighted average
    total_weighted_score = 0.0
    total_weight = 0.0

    for category_score in category_scores:
        # Handle both dict and CategoryScore object
        if isinstance(category_score, dict):
            weight = category_score['confidence']
            score = category_score['score']
        else:
            weight = category_score.confidence
            score = category_score.score

        total_weighted_score += score * weight
        total_weight += weight

    if total_weight == 0:
        return 100.0

    return total_weighted_score / total_weight


def _score_from_findings(
    findings: List[Union[Finding, Dict[str, Any]]]
) -> float:
    """
    Calculate score from findings using diminishing returns

    Uses square root scale with severity caps to prevent
    many findings from tanking the score to 0.
    """
    if not findings:
        return 100.0

    # Count findings by severity
    severity_counts = {
        "CRITICAL": 0,
        "HIGH": 0,
        "MEDIUM": 0,
        "LOW": 0
    }

    for finding in findings:
        # Handle both Finding objects and dicts
        if isinstance(finding, Finding):
            severity = finding.severity.value
        elif isinstance(finding, dict):
            severity = finding.get('severity', 'INFO')
        else:
            continue

        if severity in severity_counts:
            severity_counts[severity] += 1

    # Maximum deductions per severity level (caps the impact)
    max_deductions = {
        "CRITICAL": 40,  # Cap CRITICAL impact at -40 points
        "HIGH": 30,      # Cap HIGH impact at -30 points
        "MEDIUM": 20,    # Cap MEDIUM impact at -20 points
        "LOW": 10        # Cap LOW impact at -10 points
    }

    total_deduction = 0
    for severity, count in severity_counts.items():
        if count > 0:
            max_deduction = max_deductions[severity]
            # Use square root scale: deduction = max * (1 - 1/sqrt(count + 1))
            # This provides diminishing returns - more findings = smaller incremental penalty
            deduction = max_deduction * (1 - 1 / math.sqrt(count + 1))
            total_deduction += deduction

    # Cap at 0
    score = max(0, 100 - total_deduction)
    return score


def get_risk_level(score: float) -> Tuple[str, str]:
    """
    Get risk level and color from score

    Args:
        score: Security score (0-100)

    Returns:
        Tuple of (risk_level, color_hex)
    """
    for threshold, level, color in RISK_LEVELS:
        if score >= threshold:
            return level, color
    return "CRITICAL", "#991b1b"


def get_severity_counts(
    findings: List[Union[Finding, Dict[str, Any]]]
) -> Dict[str, int]:
    """
    Count findings by severity

    Args:
        findings: List of Finding objects or dicts

    Returns:
        Dict mapping severity to count
    """
    counts = {
        "CRITICAL": 0,
        "HIGH": 0,
        "MEDIUM": 0,
        "LOW": 0,
        "INFO": 0
    }

    for finding in findings:
        # Handle both Finding objects and dicts
        if isinstance(finding, Finding):
            severity = finding.severity.value
        elif isinstance(finding, dict):
            severity = finding.get('severity', 'INFO')
        else:
            continue

        if severity in counts:
            counts[severity] += 1

    return counts


def calculate_confidence_weighted_score(
    category_scores: List[CategoryScore]
) -> Tuple[float, float]:
    """
    Calculate confidence-weighted average score

    Args:
        category_scores: List of framework category scores

    Returns:
        Tuple of (overall_score, overall_confidence)
    """
    if not category_scores:
        return 0.0, 0.0

    # Use confidence-weighted average
    total_weighted_score = 0.0
    total_weight = 0.0

    for category_score in category_scores:
        weight = category_score.confidence
        total_weighted_score += category_score.score * weight
        total_weight += weight

    if total_weight == 0:
        return 0.0, 0.0

    overall_score = total_weighted_score / total_weight

    # Calculate overall confidence (average of category confidences)
    overall_confidence = sum(cs.confidence for cs in category_scores) / len(category_scores)

    return overall_score, overall_confidence
