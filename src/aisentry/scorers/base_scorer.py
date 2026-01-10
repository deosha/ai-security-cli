"""
Base Scorer for AI Guardian Framework Categories

Scorers calculate security posture scores (0-100) for framework categories,
while Detectors find vulnerabilities.
"""

import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Dict, List

logger = logging.getLogger(__name__)


@dataclass
class CategoryScore:
    """Score for a framework category"""
    category_id: str  # e.g., "1_prompt_security"
    category_name: str  # e.g., "Prompt Security"
    score: int  # 0-100
    confidence: float  # 0.0-1.0

    # Subscores for subcategories
    subscores: Dict[str, int] = field(default_factory=dict)

    # What was detected
    detected_controls: List[str] = field(default_factory=list)

    # What's missing
    gaps: List[str] = field(default_factory=list)

    # Evidence used for scoring
    evidence: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to JSON-serializable dict"""
        return {
            'category_id': self.category_id,
            'category_name': self.category_name,
            'score': self.score,
            'confidence': self.confidence,
            'subscores': self.subscores,
            'detected_controls': self.detected_controls,
            'gaps': self.gaps,
            'evidence': self.evidence
        }


class BaseScorer(ABC):
    """
    Base class for all framework category scorers

    Unlike detectors that find vulnerabilities, scorers calculate
    security posture scores based on implemented controls.
    """

    category_id: str = ""
    category_name: str = ""

    def __init__(self, verbose: bool = False):
        self.verbose = verbose

    @abstractmethod
    def calculate_score(self, parsed_data: Dict[str, Any]) -> CategoryScore:
        """
        Calculate category score from parsed code

        Args:
            parsed_data: Parsed code structure from parser

        Returns:
            CategoryScore with score, confidence, and evidence
        """
        raise NotImplementedError

    def _weighted_average(
        self,
        scores: List[int],
        weights: List[float]
    ) -> int:
        """Calculate weighted average of scores"""
        if not scores or not weights or len(scores) != len(weights):
            return 0

        total_weight = sum(weights)
        if total_weight == 0:
            return 0

        weighted_sum = sum(score * weight for score, weight in zip(scores, weights))
        return int(weighted_sum / total_weight)

    def _calculate_confidence(
        self,
        detection_count: int,
        total_possible: int,
        base_confidence: float = 0.7
    ) -> float:
        """
        Calculate confidence based on detection coverage

        Args:
            detection_count: Number of controls detected
            total_possible: Total number of detectable controls
            base_confidence: Base confidence level

        Returns:
            Confidence score (0.0-1.0)
        """
        if total_possible == 0:
            return 0.5  # Unknown

        coverage = detection_count / total_possible

        # Scale confidence based on coverage
        confidence = base_confidence * (0.5 + 0.5 * coverage)

        return min(1.0, max(0.0, confidence))

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}(id={self.category_id})"
