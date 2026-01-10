"""Finding data model - represents a single security issue from static analysis"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, Optional


class Severity(Enum):
    """Finding severity levels"""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class Confidence(Enum):
    """Detection confidence levels with thresholds"""

    HIGH = (0.9, 1.0, "High confidence - directly observable in code")
    MEDIUM = (0.6, 0.89, "Medium confidence - heuristic-based detection")
    LOW = (0.3, 0.59, "Low confidence - requires runtime verification")
    UNCERTAIN = (0.0, 0.29, "Uncertain - manual review recommended")

    @property
    def min_value(self) -> float:
        return self.value[0]

    @property
    def max_value(self) -> float:
        return self.value[1]

    @property
    def description(self) -> str:
        return self.value[2]

    @classmethod
    def from_score(cls, score: float) -> "Confidence":
        """Get confidence level from numeric score"""
        if score >= 0.9:
            return cls.HIGH
        elif score >= 0.6:
            return cls.MEDIUM
        elif score >= 0.3:
            return cls.LOW
        else:
            return cls.UNCERTAIN


@dataclass
class Finding:
    """
    Represents a single security finding from static code analysis

    Confidence is kept separate from severity to avoid double-penalty
    """

    # Required fields
    id: str
    category: str
    severity: Severity
    confidence: float  # 0.0-1.0
    title: str

    # Optional details
    description: Optional[str] = None
    file_path: Optional[str] = None
    line_number: Optional[int] = None
    code_snippet: Optional[str] = None
    recommendation: Optional[str] = None

    # Standards mapping
    cwe_id: Optional[str] = None
    owasp_category: Optional[str] = None

    # Evidence for confidence calculation
    evidence: Dict[str, Any] = field(default_factory=dict)

    @property
    def confidence_level(self) -> Confidence:
        """Get confidence level enum"""
        return Confidence.from_score(self.confidence)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to JSON-serializable dict (matches schema)"""
        result = {
            "id": self.id,
            "category": self.category,
            "severity": self.severity.value,
            "confidence": round(self.confidence, 2),
            "title": self.title,
        }

        # Add optional fields if present
        if self.description:
            result["description"] = self.description
        if self.file_path:
            result["file_path"] = self.file_path
        if self.line_number:
            result["line_number"] = self.line_number
        if self.code_snippet:
            result["code_snippet"] = self.code_snippet
        if self.recommendation:
            result["recommendation"] = self.recommendation
        if self.cwe_id:
            result["cwe_id"] = self.cwe_id
        if self.owasp_category:
            result["owasp_category"] = self.owasp_category
        if self.evidence:
            result["evidence"] = self.evidence

        return result

    def __str__(self) -> str:
        """Human-readable representation"""
        location = f"{self.file_path}:{self.line_number}" if self.file_path else "N/A"
        return (
            f"[{self.severity.value}] {self.title} "
            f"(confidence: {self.confidence:.0%}) at {location}"
        )
