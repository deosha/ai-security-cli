"""Base detector class - all static security detectors inherit from this"""

from abc import ABC, abstractmethod
from typing import List, Dict, Any, Optional
import logging

from ai_security.models.finding import Finding, Confidence

logger = logging.getLogger(__name__)


class BaseDetector(ABC):
    """
    Base class for all static security detectors

    Key design decisions:
    1. detect() returns ONLY high-confidence findings (auto-filtered)
    2. Confidence is calculated per-finding based on evidence
    3. Low-confidence findings are logged but not returned
    """

    # Subclasses must set these
    detector_id: str = "BASE"
    detector_name: str = "Base Detector"

    # Default confidence threshold (can be overridden)
    default_confidence_threshold: float = 0.7

    def __init__(
        self,
        confidence_threshold: Optional[float] = None,
        verbose: bool = False
    ):
        """
        Initialize detector

        Args:
            confidence_threshold: Minimum confidence to report findings (default: 0.7)
            verbose: If True, log uncertain findings for debugging
        """
        self.confidence_threshold = confidence_threshold or self.default_confidence_threshold
        self.verbose = verbose

    def detect(self, parsed_data: Dict[str, Any]) -> List[Finding]:
        """
        Main detection method - returns only HIGH-CONFIDENCE findings

        This is the public API - automatically filters by confidence.

        Args:
            parsed_data: Parsed source code structure from parser

        Returns:
            List of high-confidence findings only
        """
        # Gather all potential findings
        all_findings = self._gather_potential_findings(parsed_data)

        # Filter by confidence threshold
        actionable_findings = []
        uncertain_findings = []

        for finding in all_findings:
            # Calculate confidence based on evidence
            confidence = self.calculate_confidence(finding.evidence)
            finding.confidence = confidence

            if confidence >= self.confidence_threshold:
                # High confidence - include in results
                actionable_findings.append(finding)
            else:
                # Low confidence - track separately
                uncertain_findings.append(finding)

        # Log uncertain findings for tuning (if verbose)
        if uncertain_findings and self.verbose:
            self._log_uncertain_findings(uncertain_findings)

        return actionable_findings

    @abstractmethod
    def _gather_potential_findings(self, parsed_data: Dict[str, Any]) -> List[Finding]:
        """
        Gather all potential findings (before confidence filtering)

        Override this in subclasses with detector-specific logic.

        Args:
            parsed_data: Parsed source code structure

        Returns:
            List of findings with evidence (confidence not yet calculated)
        """
        raise NotImplementedError("Subclass must implement _gather_potential_findings()")

    @abstractmethod
    def calculate_confidence(self, evidence: Dict[str, Any]) -> float:
        """
        Calculate confidence score based on evidence

        Override in subclass with detector-specific heuristics.

        Args:
            evidence: Dictionary of evidence gathered for a finding

        Returns:
            Confidence score (0.0-1.0)

        Example:
            def calculate_confidence(self, evidence):
                score = 0.0

                # High confidence signals
                if evidence.get('has_hardcoded_string'):
                    score += 0.5
                if evidence.get('matches_api_key_pattern'):
                    score += 0.4

                # Reduce confidence if ambiguous
                if evidence.get('could_be_test_data'):
                    score -= 0.2

                return max(0.0, min(1.0, score))
        """
        raise NotImplementedError("Subclass must implement calculate_confidence()")

    def _log_uncertain_findings(self, findings: List[Finding]) -> None:
        """Log uncertain findings for debugging and tuning"""
        logger.info(f"[{self.detector_id}] Found {len(findings)} uncertain findings:")
        for finding in findings:
            logger.info(
                f"  - {finding.title} "
                f"(confidence={finding.confidence:.2f}) "
                f"at {finding.file_path}:{finding.line_number}"
            )
            if finding.evidence:
                logger.debug(f"    Evidence: {finding.evidence}")

    def get_confidence_message(self, confidence: float) -> str:
        """Get human-readable confidence message"""
        conf_level = Confidence.from_score(confidence)
        return conf_level.description

    def apply_mitigations(self, confidence: float, evidence: Dict[str, Any]) -> float:
        """
        Apply mitigation-based confidence demotions.

        Override in subclasses to implement domain-specific mitigation detection.
        This allows detectors to reduce confidence when mitigating controls are present,
        rather than relying on scanner-level filters.

        Args:
            confidence: Base confidence score (0.0-1.0)
            evidence: Dictionary of evidence for the finding

        Returns:
            Adjusted confidence score after applying mitigations

        Example mitigations by detector:
            LLM01: sanitize/escape/allowlist functions, PromptTemplate usage
            LLM02: html.escape/bleach, parameterized SQL, subprocess shell=False
            LLM05: verified pinning, signed downloads, no dynamic plugin exec
            LLM09: human-in-the-loop approvals, policy checks

        Example implementation:
            def apply_mitigations(self, confidence: float, evidence: Dict) -> float:
                if evidence.get('has_sanitization'):
                    confidence -= 0.25
                if evidence.get('has_parameterized_query'):
                    confidence -= 0.30
                return max(0.0, confidence)
        """
        # Default: no mitigation adjustments
        # Subclasses override to add domain-specific logic
        return confidence

    def __repr__(self) -> str:
        return (
            f"{self.__class__.__name__}"
            f"(id={self.detector_id}, threshold={self.confidence_threshold})"
        )
