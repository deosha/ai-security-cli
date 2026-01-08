"""
Base class for security control detectors.
"""

from abc import ABC, abstractmethod
from typing import Dict, List, Optional, TYPE_CHECKING

from ..models import ControlEvidence, ControlLevel, EvidenceItem, EvidenceType

if TYPE_CHECKING:
    from ..analyzers import ASTAnalyzer, ConfigAnalyzer, DependencyAnalyzer


class BaseControlDetector(ABC):
    """
    Base class for detecting security controls.

    Each detector checks for the presence and maturity level
    of a specific security control.
    """

    control_id: str = ""
    control_name: str = ""
    category: str = ""
    description: str = ""

    # Recommendations when control is not detected
    recommendations: List[str] = []

    def __init__(
        self,
        ast_analyzer: "ASTAnalyzer",
        config_analyzer: "ConfigAnalyzer",
        dependency_analyzer: "DependencyAnalyzer",
    ):
        self.ast = ast_analyzer
        self.config = config_analyzer
        self.deps = dependency_analyzer

    @abstractmethod
    def detect(self) -> ControlEvidence:
        """
        Detect the presence and level of this control.

        Returns:
            ControlEvidence with detection results
        """
        pass

    def _create_evidence(
        self,
        detected: bool,
        level: ControlLevel,
        evidence_items: List[EvidenceItem],
        confidence: Optional[float] = None,
    ) -> ControlEvidence:
        """Helper to create ControlEvidence."""
        # Calculate confidence from evidence if not provided
        if confidence is None:
            if not evidence_items:
                confidence = 0.0
            else:
                confidence = min(1.0, sum(e.confidence for e in evidence_items) / len(evidence_items))

        return ControlEvidence(
            control_id=self.control_id,
            control_name=self.control_name,
            category=self.category,
            detected=detected,
            level=level,
            confidence=confidence,
            evidence_items=evidence_items,
            recommendations=self.recommendations if not detected else [],
        )

    def _evidence_from_ast(
        self,
        file_path: str,
        line_number: int,
        snippet: str,
        description: str,
        confidence: float = 0.8,
    ) -> EvidenceItem:
        """Create evidence from AST match."""
        return EvidenceItem(
            type=EvidenceType.AST,
            file_path=file_path,
            line_number=line_number,
            snippet=snippet,
            description=description,
            confidence=confidence,
        )

    def _evidence_from_import(
        self,
        file_path: str,
        line_number: int,
        module_name: str,
        description: str,
        confidence: float = 0.9,
    ) -> EvidenceItem:
        """Create evidence from import statement."""
        return EvidenceItem(
            type=EvidenceType.IMPORT,
            file_path=file_path,
            line_number=line_number,
            snippet=module_name,
            description=description,
            confidence=confidence,
        )

    def _evidence_from_dependency(
        self,
        file_path: str,
        package_name: str,
        description: str,
        confidence: float = 0.95,
    ) -> EvidenceItem:
        """Create evidence from dependency."""
        return EvidenceItem(
            type=EvidenceType.DEPENDENCY,
            file_path=file_path,
            snippet=package_name,
            description=description,
            confidence=confidence,
        )

    def _evidence_from_config(
        self,
        file_path: str,
        key: str,
        value: str,
        description: str,
        confidence: float = 0.85,
    ) -> EvidenceItem:
        """Create evidence from config."""
        return EvidenceItem(
            type=EvidenceType.CONFIG,
            file_path=file_path,
            snippet=f"{key}: {value}",
            description=description,
            confidence=confidence,
        )

    def _evidence_from_decorator(
        self,
        file_path: str,
        line_number: int,
        decorator_name: str,
        description: str,
        confidence: float = 0.9,
    ) -> EvidenceItem:
        """Create evidence from decorator."""
        return EvidenceItem(
            type=EvidenceType.DECORATOR,
            file_path=file_path,
            line_number=line_number,
            snippet=f"@{decorator_name}",
            description=description,
            confidence=confidence,
        )

    def _evidence_from_file(
        self,
        file_path: str,
        description: str,
        confidence: float = 0.7,
    ) -> EvidenceItem:
        """Create evidence from file presence."""
        return EvidenceItem(
            type=EvidenceType.FILE,
            file_path=file_path,
            description=description,
            confidence=confidence,
        )


class ControlCategory(ABC):
    """
    Base class for a category of controls.

    Groups related controls together.
    """

    category_id: str = ""
    category_name: str = ""
    weight: float = 1.0

    def __init__(
        self,
        ast_analyzer: "ASTAnalyzer",
        config_analyzer: "ConfigAnalyzer",
        dependency_analyzer: "DependencyAnalyzer",
    ):
        self.ast = ast_analyzer
        self.config = config_analyzer
        self.deps = dependency_analyzer
        self._detectors: List[BaseControlDetector] = []

    @abstractmethod
    def _create_detectors(self) -> List[BaseControlDetector]:
        """Create all control detectors for this category."""
        pass

    def detect_all(self) -> List[ControlEvidence]:
        """Run all control detectors and return evidence."""
        if not self._detectors:
            self._detectors = self._create_detectors()

        results = []
        for detector in self._detectors:
            try:
                evidence = detector.detect()
                results.append(evidence)
            except Exception as e:
                # Create failed detection
                results.append(ControlEvidence(
                    control_id=detector.control_id,
                    control_name=detector.control_name,
                    category=detector.category,
                    detected=False,
                    level=ControlLevel.NONE,
                    confidence=0.0,
                    evidence_items=[],
                    recommendations=[f"Detection failed: {str(e)}"],
                ))

        return results
