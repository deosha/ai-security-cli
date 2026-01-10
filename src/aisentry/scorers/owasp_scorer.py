"""
OWASP Vulnerability Scorer

Aggregates findings from 10 OWASP LLM detectors into a category score.
Unlike framework scorers that assess security posture, this scorer
converts vulnerability findings into a 0-100 score.

Scoring Logic:
- Start at 100 (perfect)
- Deduct points based on severity and count
- Consider confidence to avoid false positive penalties
"""

import logging
from collections import Counter
from typing import Any, Dict, List, Tuple

from aisentry.models.finding import Finding, Severity
from aisentry.scorers.base_scorer import BaseScorer, CategoryScore

logger = logging.getLogger(__name__)


class OWASPScorer(BaseScorer):
    """
    Score OWASP LLM vulnerability findings

    Converts detector findings into a 0-100 security score:
    - 100: No vulnerabilities
    - 75-99: Low severity issues only
    - 50-74: Medium severity issues
    - 25-49: High severity issues
    - 0-24: Critical severity issues

    Weighting Strategy:
    - CRITICAL: -40 points per finding (capped)
    - HIGH: -20 points per finding
    - MEDIUM: -10 points per finding
    - LOW: -5 points per finding
    - INFO: -1 point per finding

    Confidence multiplier: score_deduction *= confidence
    """

    category_id = "0_owasp_vulnerabilities"
    category_name = "OWASP LLM Vulnerabilities"

    # Severity weights (point deductions)
    SEVERITY_WEIGHTS = {
        Severity.CRITICAL: 40,
        Severity.HIGH: 20,
        Severity.MEDIUM: 10,
        Severity.LOW: 5,
        Severity.INFO: 1
    }

    # OWASP LLM Top 10 detector IDs
    OWASP_DETECTORS = {
        'LLM01': 'Prompt Injection',
        'LLM02': 'Insecure Output Handling',
        'LLM03': 'Training Data Poisoning',
        'LLM04': 'Model Denial of Service',
        'LLM05': 'Supply Chain Vulnerabilities',
        'LLM06': 'Sensitive Information Disclosure',
        'LLM07': 'Insecure Plugin Design',
        'LLM08': 'Excessive Agency',
        'LLM09': 'Overreliance',
        'LLM10': 'Model Theft'
    }

    def __init__(self, verbose: bool = False):
        super().__init__(verbose)
        self._findings_cache: List[Finding] = []

    def set_findings(self, findings: List[Finding]) -> None:
        """
        Set findings to score (called by scanner before calculate_score)

        Args:
            findings: List of OWASP detector findings
        """
        self._findings_cache = findings

    def _extract_detector_id(self, finding_id: str) -> str:
        """
        Extract detector ID from finding ID

        Finding IDs can be in formats:
        - "LLM01_/path/to/file_123" -> "LLM01"
        - "LLM01-001" -> "LLM01"

        Args:
            finding_id: Full finding ID

        Returns:
            Detector ID (e.g., "LLM01")
        """
        # Try underscore split first
        if '_' in finding_id:
            return finding_id.split('_')[0]
        # Try dash split
        if '-' in finding_id:
            return finding_id.split('-')[0]
        # Return as-is if no separator
        return finding_id

    def calculate_score(self, parsed_data: Dict[str, Any]) -> CategoryScore:
        """
        Calculate OWASP vulnerability score from findings

        Note: This scorer uses findings set via set_findings() rather than
        parsing code directly. The parsed_data parameter is kept for
        interface consistency with other scorers.

        Args:
            parsed_data: Parsed code (not used directly, but kept for consistency)

        Returns:
            CategoryScore with vulnerability-based score
        """
        findings = self._findings_cache

        if not findings:
            # No findings = perfect score with all detectors at 100
            all_subscores = {detector_id: 100 for detector_id in self.OWASP_DETECTORS.keys()}
            all_protected = [
                f"{name} (no vulnerabilities found)"
                for name in self.OWASP_DETECTORS.values()
            ]

            return CategoryScore(
                category_id=self.category_id,
                category_name=self.category_name,
                score=100,
                confidence=1.0,
                subscores=all_subscores,
                detected_controls=all_protected,
                gaps=[],
                evidence={
                    'total_findings': 0,
                    'findings_by_severity': {},
                    'findings_by_detector': {},
                    'deduction_breakdown': {}
                }
            )

        # Calculate score
        score, evidence = self._calculate_vulnerability_score(findings)

        # Calculate subscores per detector
        subscores = self._calculate_detector_subscores(findings)

        # Identify what's vulnerable vs. what's protected
        vulnerable_areas = self._identify_vulnerable_areas(findings)
        protected_areas = self._identify_protected_areas()

        # Calculate confidence based on finding confidence
        confidence = self._calculate_aggregate_confidence(findings)

        return CategoryScore(
            category_id=self.category_id,
            category_name=self.category_name,
            score=score,
            confidence=confidence,
            subscores=subscores,
            detected_controls=protected_areas,
            gaps=vulnerable_areas,
            evidence=evidence
        )

    def _calculate_vulnerability_score(
        self,
        findings: List[Finding]
    ) -> Tuple[int, Dict[str, Any]]:
        """
        Calculate score based on vulnerability findings

        Strategy:
        - Start at 100 (perfect)
        - Deduct points based on severity × confidence
        - Cap at 0 (worst)

        Args:
            findings: List of vulnerability findings

        Returns:
            Tuple of (score, evidence_dict)
        """
        # Start at perfect score
        score = 100

        # Count findings by severity
        severity_counts = Counter()
        detector_counts = Counter()
        total_deduction = 0
        deduction_breakdown = {}

        for finding in findings:
            severity = finding.severity
            detector_id = self._extract_detector_id(finding.id)

            severity_counts[severity.value] += 1
            detector_counts[detector_id] += 1

            # Calculate deduction for this finding
            base_deduction = self.SEVERITY_WEIGHTS.get(severity, 1)
            confidence_multiplier = finding.confidence
            deduction = base_deduction * confidence_multiplier

            # Track deduction breakdown
            key = f"{severity.value}_{detector_id}"
            if key not in deduction_breakdown:
                deduction_breakdown[key] = {
                    'severity': severity.value,
                    'detector': detector_id,
                    'count': 0,
                    'total_deduction': 0
                }
            deduction_breakdown[key]['count'] += 1
            deduction_breakdown[key]['total_deduction'] += deduction

            total_deduction += deduction

        # Apply total deduction (capped at 100)
        score = max(0, score - int(total_deduction))

        # Build evidence
        evidence = {
            'total_findings': len(findings),
            'findings_by_severity': dict(severity_counts),
            'findings_by_detector': dict(detector_counts),
            'total_deduction': int(total_deduction),
            'deduction_breakdown': deduction_breakdown,
            'final_score': score
        }

        return score, evidence

    def _calculate_detector_subscores(
        self,
        findings: List[Finding]
    ) -> Dict[str, int]:
        """
        Calculate per-detector subscores

        Each OWASP detector gets a subscore:
        - 100: No findings for this detector
        - <100: Findings present, score based on severity

        Args:
            findings: List of vulnerability findings

        Returns:
            Dict mapping detector_id to subscore (0-100)
        """
        subscores = {}

        # Group findings by detector
        findings_by_detector = {}
        for finding in findings:
            detector_id = self._extract_detector_id(finding.id)
            if detector_id not in findings_by_detector:
                findings_by_detector[detector_id] = []
            findings_by_detector[detector_id].append(finding)

        # Calculate subscore for each detector
        for detector_id, detector_name in self.OWASP_DETECTORS.items():
            detector_findings = findings_by_detector.get(detector_id, [])

            if not detector_findings:
                # No findings = perfect score
                subscores[detector_id] = 100
            else:
                # Calculate deduction for this detector
                deduction = 0
                for finding in detector_findings:
                    base_deduction = self.SEVERITY_WEIGHTS.get(finding.severity, 1)
                    deduction += base_deduction * finding.confidence

                # Cap deduction at 100
                subscore = max(0, 100 - int(deduction))
                subscores[detector_id] = subscore

        return subscores

    def _identify_vulnerable_areas(self, findings: List[Finding]) -> List[str]:
        """
        Identify which OWASP categories have vulnerabilities

        Args:
            findings: List of vulnerability findings

        Returns:
            List of vulnerable area descriptions
        """
        vulnerable = []

        # Group by detector
        detectors_with_findings = set()
        for finding in findings:
            detector_id = self._extract_detector_id(finding.id)
            detectors_with_findings.add(detector_id)

        # Build vulnerability descriptions
        for detector_id in sorted(detectors_with_findings):
            detector_name = self.OWASP_DETECTORS.get(detector_id, detector_id)
            detector_findings = [
                f for f in findings
                if f.id.startswith(detector_id)
            ]

            # Count by severity
            severity_counts = Counter(f.severity for f in detector_findings)

            # Build description
            severity_strs = []
            for severity in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW]:
                count = severity_counts.get(severity, 0)
                if count > 0:
                    severity_strs.append(f"{count} {severity.value.lower()}")

            if severity_strs:
                vuln_desc = f"{detector_name}: {', '.join(severity_strs)}"
                vulnerable.append(vuln_desc)

        return vulnerable

    def _identify_protected_areas(self) -> List[str]:
        """
        Identify which OWASP categories have NO vulnerabilities

        Returns:
            List of protected area descriptions
        """
        findings = self._findings_cache

        if not findings:
            # All areas protected
            return [
                f"{name} (no vulnerabilities found)"
                for name in self.OWASP_DETECTORS.values()
            ]

        # Find detectors with findings
        detectors_with_findings = set()
        for finding in findings:
            detector_id = self._extract_detector_id(finding.id)
            detectors_with_findings.add(detector_id)

        # Protected = not in vulnerable set
        protected = []
        for detector_id, detector_name in self.OWASP_DETECTORS.items():
            if detector_id not in detectors_with_findings:
                protected.append(f"{detector_name} (no vulnerabilities found)")

        return protected

    def _calculate_aggregate_confidence(self, findings: List[Finding]) -> float:
        """
        Calculate aggregate confidence from finding confidences

        Uses weighted average based on severity:
        - Higher severity findings contribute more to confidence

        Args:
            findings: List of vulnerability findings

        Returns:
            Aggregate confidence (0.0-1.0)
        """
        if not findings:
            return 1.0  # High confidence when no findings

        # Weight confidences by severity
        weighted_sum = 0.0
        total_weight = 0.0

        for finding in findings:
            weight = self.SEVERITY_WEIGHTS.get(finding.severity, 1)
            weighted_sum += finding.confidence * weight
            total_weight += weight

        if total_weight == 0:
            return 0.7  # Default confidence

        return min(1.0, weighted_sum / total_weight)
