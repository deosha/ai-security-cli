"""
Audit data models for evidence and scoring.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional
from datetime import datetime


class MaturityLevel(Enum):
    """Security maturity levels."""
    INITIAL = "Initial"           # 0-20: Ad-hoc, no formal controls
    DEVELOPING = "Developing"     # 21-40: Some controls, inconsistent
    DEFINED = "Defined"           # 41-60: Documented processes
    MANAGED = "Managed"           # 61-80: Measured and controlled
    OPTIMIZING = "Optimizing"     # 81-100: Continuous improvement

    @classmethod
    def from_score(cls, score: float) -> "MaturityLevel":
        """Get maturity level from score (0-100)."""
        if score <= 20:
            return cls.INITIAL
        elif score <= 40:
            return cls.DEVELOPING
        elif score <= 60:
            return cls.DEFINED
        elif score <= 80:
            return cls.MANAGED
        else:
            return cls.OPTIMIZING


class ControlLevel(Enum):
    """Detection level for a control."""
    NONE = "none"
    BASIC = "basic"
    INTERMEDIATE = "intermediate"
    ADVANCED = "advanced"
    COMPREHENSIVE = "comprehensive"

    def to_score(self) -> int:
        """Convert level to numeric score."""
        scores = {
            "none": 0,
            "basic": 25,
            "intermediate": 50,
            "advanced": 75,
            "comprehensive": 100,
        }
        return scores.get(self.value, 0)


class EvidenceType(Enum):
    """Type of evidence found."""
    AST = "ast"                    # Code pattern via AST
    CONFIG = "config"              # Configuration file
    FILE = "file"                  # File presence
    DEPENDENCY = "dependency"      # Package/library
    IMPORT = "import"              # Import statement
    DECORATOR = "decorator"        # Function decorator
    PATTERN = "pattern"            # Regex pattern match


@dataclass
class EvidenceItem:
    """Single piece of evidence for a control detection."""
    type: EvidenceType
    file_path: str
    description: str
    line_number: Optional[int] = None
    snippet: Optional[str] = None
    confidence: float = 1.0

    def to_dict(self) -> dict:
        return {
            "type": self.type.value,
            "file_path": self.file_path,
            "line_number": self.line_number,
            "snippet": self.snippet,
            "description": self.description,
            "confidence": self.confidence,
        }


@dataclass
class ControlEvidence:
    """Evidence for a single security control."""
    control_id: str
    control_name: str
    category: str
    detected: bool
    level: ControlLevel
    confidence: float
    evidence_items: List[EvidenceItem] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)

    @property
    def score(self) -> int:
        """Get numeric score for this control."""
        return self.level.to_score()

    def to_dict(self) -> dict:
        return {
            "control_id": self.control_id,
            "control_name": self.control_name,
            "category": self.category,
            "detected": self.detected,
            "level": self.level.value,
            "confidence": self.confidence,
            "score": self.score,
            "evidence": [e.to_dict() for e in self.evidence_items],
            "recommendations": self.recommendations,
        }


@dataclass
class CategoryScore:
    """Score for a category of controls."""
    category_id: str
    category_name: str
    score: float
    max_score: float = 100.0
    controls: List[ControlEvidence] = field(default_factory=list)
    weight: float = 1.0

    @property
    def percentage(self) -> float:
        """Get percentage score."""
        return (self.score / self.max_score) * 100 if self.max_score > 0 else 0

    @property
    def detected_count(self) -> int:
        """Count of detected controls."""
        return sum(1 for c in self.controls if c.detected)

    @property
    def total_count(self) -> int:
        """Total number of controls."""
        return len(self.controls)

    def to_dict(self) -> dict:
        return {
            "category_id": self.category_id,
            "category_name": self.category_name,
            "score": round(self.score, 1),
            "max_score": self.max_score,
            "percentage": round(self.percentage, 1),
            "detected_count": self.detected_count,
            "total_count": self.total_count,
            "controls": [c.to_dict() for c in self.controls],
        }


@dataclass
class Recommendation:
    """Security recommendation based on audit findings."""
    priority: str  # critical, high, medium, low
    category: str
    control_id: str
    title: str
    description: str
    remediation: str
    docs_url: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "priority": self.priority,
            "category": self.category,
            "control_id": self.control_id,
            "title": self.title,
            "description": self.description,
            "remediation": self.remediation,
            "docs_url": self.docs_url,
        }


@dataclass
class AuditResult:
    """Complete audit result."""
    audit_id: str
    project_path: str
    timestamp: datetime
    overall_score: float
    maturity_level: MaturityLevel
    categories: Dict[str, CategoryScore] = field(default_factory=dict)
    recommendations: List[Recommendation] = field(default_factory=list)
    files_scanned: int = 0
    scan_duration_seconds: float = 0.0

    @property
    def detected_controls_count(self) -> int:
        """Total detected controls across all categories."""
        return sum(cat.detected_count for cat in self.categories.values())

    @property
    def total_controls_count(self) -> int:
        """Total controls across all categories."""
        return sum(cat.total_count for cat in self.categories.values())

    def to_dict(self) -> dict:
        return {
            "audit_id": self.audit_id,
            "project_path": self.project_path,
            "timestamp": self.timestamp.isoformat(),
            "overall_score": round(self.overall_score, 1),
            "maturity_level": self.maturity_level.value,
            "files_scanned": self.files_scanned,
            "scan_duration_seconds": round(self.scan_duration_seconds, 2),
            "detected_controls": self.detected_controls_count,
            "total_controls": self.total_controls_count,
            "categories": {k: v.to_dict() for k, v in self.categories.items()},
            "recommendations": [r.to_dict() for r in self.recommendations],
        }
