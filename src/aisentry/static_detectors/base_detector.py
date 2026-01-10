"""Base detector class - all static security detectors inherit from this"""

import logging
from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional, Set

from aisentry.models.finding import Confidence, Finding

logger = logging.getLogger(__name__)


# =============================================================================
# NEGATIVE EVIDENCE PATTERNS
# These patterns indicate the code is likely secure and should reduce confidence
# =============================================================================

SANITIZATION_PATTERNS: Set[str] = {
    # HTML/XSS sanitization
    'html.escape', 'markupsafe', 'bleach.clean', 'bleach.sanitize',
    'escape(', 'sanitize(', 'cgi.escape', 'django.utils.html.escape',
    'jinja2.escape', 'nh3.clean',

    # Command/shell sanitization
    'shlex.quote', 'pipes.quote', 'shell=False',

    # SQL parameterization
    'parameterized', 'prepared_statement', 'bind_param',

    # URL encoding
    'urllib.parse.quote', 'urlencode', 'quote_plus',
}

VALIDATION_PATTERNS: Set[str] = {
    # Input validation
    'validate(', 'validator', 'pydantic', 'jsonschema',
    'schema.validate', 'voluptuous', 'cerberus',

    # Type checking
    'isinstance(', 'type(', 'typing.',

    # Allowlist/denylist
    'allowlist', 'whitelist', 'blocklist', 'denylist', 'blacklist',

    # Regex validation
    're.match', 're.fullmatch', 'regex.match',
}

SECURITY_CONTROLS: Set[str] = {
    # Authentication/authorization
    'requires_auth', '@login_required', '@authenticated',
    'check_permission', 'has_permission', 'is_authorized',

    # Rate limiting
    '@ratelimit', '@rate_limit', 'throttle', 'limiter',

    # Human approval
    'human_review', 'requires_approval', 'human_in_loop',
    'manual_approval', 'await_confirmation',

    # Verification
    'verify_signature', 'verify_checksum', 'verify_hash',
    'check_integrity', 'validate_token',
}

TEST_FILE_PATTERNS: Set[str] = {
    'test_', '_test.py', 'tests/', 'testing/', 'spec_',
    'mock_', 'fixture', 'conftest',
}


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

        # Detect negative evidence at file level
        source_lines = parsed_data.get('source_lines', [])
        file_path = parsed_data.get('file_path', '')
        negative_evidence = self._detect_negative_evidence(source_lines, file_path)

        # Filter by confidence threshold
        actionable_findings = []
        uncertain_findings = []

        for finding in all_findings:
            # Calculate confidence based on evidence
            confidence = self.calculate_confidence(finding.evidence)

            # Apply detector-specific mitigations (e.g., sanitization, parameterized queries)
            confidence = self.apply_mitigations(confidence, finding.evidence)

            # Apply negative evidence adjustments
            confidence = self._apply_negative_evidence(
                confidence, finding, negative_evidence, source_lines
            )

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

    def _detect_negative_evidence(
        self,
        source_lines: List[str],
        file_path: str
    ) -> Dict[str, Any]:
        """
        Detect negative evidence patterns at file level.

        Returns a dictionary indicating which security patterns are present:
        - has_sanitization: Sanitization functions detected
        - has_validation: Input validation detected
        - has_security_controls: Security controls (auth, rate limiting) detected
        - is_test_file: File appears to be a test file
        """
        source_code = '\n'.join(source_lines).lower()
        file_path_lower = file_path.lower()

        return {
            'has_sanitization': any(
                pattern.lower() in source_code for pattern in SANITIZATION_PATTERNS
            ),
            'has_validation': any(
                pattern.lower() in source_code for pattern in VALIDATION_PATTERNS
            ),
            'has_security_controls': any(
                pattern.lower() in source_code for pattern in SECURITY_CONTROLS
            ),
            'is_test_file': any(
                pattern in file_path_lower for pattern in TEST_FILE_PATTERNS
            ),
        }

    def _apply_negative_evidence(
        self,
        confidence: float,
        finding: Finding,
        negative_evidence: Dict[str, Any],
        source_lines: List[str]
    ) -> float:
        """
        Apply negative evidence to reduce confidence score.

        This is a hook that subclasses can override for domain-specific logic.
        The base implementation applies common reductions.
        """
        original_confidence = confidence

        # Check for sanitization near the finding location
        finding_context = self._get_finding_context(
            source_lines, finding.line_number, context_lines=5
        )
        context_lower = finding_context.lower()

        # Strong negative evidence in immediate context
        for pattern in SANITIZATION_PATTERNS:
            if pattern.lower() in context_lower:
                confidence -= 0.25
                break

        # Moderate negative evidence in immediate context
        for pattern in VALIDATION_PATTERNS:
            if pattern.lower() in context_lower:
                confidence -= 0.15
                break

        # File-level negative evidence (weaker signal)
        if negative_evidence.get('has_security_controls'):
            confidence -= 0.10

        # Test files should have lower confidence
        if negative_evidence.get('is_test_file'):
            confidence -= 0.20

        # Never go below 0 or above 1
        confidence = max(0.0, min(1.0, confidence))

        # Log significant demotions for debugging
        if self.verbose and confidence < original_confidence - 0.1:
            logger.debug(
                f"[{self.detector_id}] Confidence reduced "
                f"{original_confidence:.2f} -> {confidence:.2f} "
                f"for {finding.title[:40]}..."
            )

        return confidence

    def _get_finding_context(
        self,
        source_lines: List[str],
        line_num: int,
        context_lines: int = 5
    ) -> str:
        """Get source code context around a finding."""
        start = max(0, line_num - context_lines - 1)
        end = min(len(source_lines), line_num + context_lines)
        return '\n'.join(source_lines[start:end])

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
