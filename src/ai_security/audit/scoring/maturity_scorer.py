"""
Maturity scorer for calculating audit scores.
"""

from typing import Dict, List

from ..models import (
    AuditResult,
    CategoryScore,
    ControlEvidence,
    MaturityLevel,
    Recommendation,
)


class MaturityScorer:
    """
    Calculate maturity scores from control evidence.

    Uses weighted averages to compute category and overall scores.
    """

    # Default category weights
    CATEGORY_WEIGHTS = {
        "prompt_security": 0.15,
        "model_security": 0.12,
        "data_privacy": 0.12,
        "owasp_llm": 0.15,
        "blue_team": 0.10,
        "governance": 0.10,
    }

    # Priority mapping based on score
    PRIORITY_THRESHOLDS = {
        0: "critical",
        25: "high",
        50: "medium",
        75: "low",
    }

    def __init__(self, custom_weights: Dict[str, float] = None):
        """Initialize scorer with optional custom weights."""
        self.weights = custom_weights or self.CATEGORY_WEIGHTS

    def score_category(
        self,
        category_id: str,
        category_name: str,
        controls: List[ControlEvidence],
    ) -> CategoryScore:
        """
        Calculate score for a category of controls.

        Args:
            category_id: Category identifier
            category_name: Human-readable category name
            controls: List of control evidence

        Returns:
            CategoryScore with calculated score
        """
        if not controls:
            return CategoryScore(
                category_id=category_id,
                category_name=category_name,
                score=0.0,
                controls=controls,
                weight=self.weights.get(category_id, 1.0),
            )

        # Calculate average score from all controls
        total_score = sum(c.score for c in controls)
        avg_score = total_score / len(controls)

        return CategoryScore(
            category_id=category_id,
            category_name=category_name,
            score=avg_score,
            controls=controls,
            weight=self.weights.get(category_id, 1.0),
        )

    def calculate_overall_score(
        self,
        categories: Dict[str, CategoryScore],
    ) -> float:
        """
        Calculate weighted overall score from category scores.

        Args:
            categories: Dictionary of category scores

        Returns:
            Overall score (0-100)
        """
        if not categories:
            return 0.0

        total_weight = 0.0
        weighted_sum = 0.0

        for cat_id, cat_score in categories.items():
            weight = self.weights.get(cat_id, 1.0)
            weighted_sum += cat_score.score * weight
            total_weight += weight

        if total_weight == 0:
            return 0.0

        return weighted_sum / total_weight

    def generate_recommendations(
        self,
        categories: Dict[str, CategoryScore],
    ) -> List[Recommendation]:
        """
        Generate recommendations based on missing or weak controls.

        Args:
            categories: Dictionary of category scores

        Returns:
            List of prioritized recommendations
        """
        recommendations = []

        for cat_id, cat_score in categories.items():
            for control in cat_score.controls:
                # Add recommendations for non-detected or weak controls
                if not control.detected or control.score < 50:
                    priority = self._get_priority(control.score)

                    for rec_text in control.recommendations:
                        recommendations.append(Recommendation(
                            priority=priority,
                            category=cat_id,
                            control_id=control.control_id,
                            title=control.control_name,
                            description=f"Control not detected or below threshold",
                            remediation=rec_text,
                        ))

        # Sort by priority (critical first)
        priority_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        recommendations.sort(key=lambda r: priority_order.get(r.priority, 99))

        return recommendations

    def _get_priority(self, score: float) -> str:
        """Get priority level based on score."""
        for threshold, priority in sorted(
            self.PRIORITY_THRESHOLDS.items(), reverse=True
        ):
            if score >= threshold:
                return priority
        return "critical"

    def create_audit_result(
        self,
        audit_id: str,
        project_path: str,
        categories: Dict[str, CategoryScore],
        files_scanned: int,
        scan_duration: float,
    ) -> AuditResult:
        """
        Create complete audit result.

        Args:
            audit_id: Unique audit identifier
            project_path: Path that was audited
            categories: Dictionary of category scores
            files_scanned: Number of files scanned
            scan_duration: Duration of scan in seconds

        Returns:
            Complete AuditResult
        """
        from datetime import datetime

        overall_score = self.calculate_overall_score(categories)
        maturity_level = MaturityLevel.from_score(overall_score)
        recommendations = self.generate_recommendations(categories)

        return AuditResult(
            audit_id=audit_id,
            project_path=project_path,
            timestamp=datetime.now(),
            overall_score=overall_score,
            maturity_level=maturity_level,
            categories=categories,
            recommendations=recommendations,
            files_scanned=files_scanned,
            scan_duration_seconds=scan_duration,
        )
