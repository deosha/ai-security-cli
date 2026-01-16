"""
Security-Focused Evaluation Metrics.

Calculates standard ML metrics (precision, recall, F1) plus security-specific
metrics for vulnerability detection evaluation.

Key Metrics:
- Critical Recall: Recall specifically for high-severity vulnerabilities
- False Positive Rate: Important for usability in real-world pipelines
- Detection Latency: Time to scan (important for CI/CD integration)
"""

import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

import numpy as np

from aisentry.models.finding import Finding, Severity

logger = logging.getLogger(__name__)


@dataclass
class GroundTruth:
    """Ground truth label for a code sample."""
    file_path: str
    line_number: int
    is_vulnerable: bool
    category: str  # LLM01, TAINT01, etc.
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW
    attack_vector: Optional[str] = None  # direct, indirect, stored
    description: Optional[str] = None

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "GroundTruth":
        return cls(
            file_path=data['file_path'],
            line_number=data['line_number'],
            is_vulnerable=data['is_vulnerable'],
            category=data['category'],
            severity=data['severity'],
            attack_vector=data.get('attack_vector'),
            description=data.get('description'),
        )


@dataclass
class MetricsReport:
    """Complete metrics report for evaluation."""
    # Standard metrics
    precision: float
    recall: float
    f1_score: float
    accuracy: float

    # Counts
    true_positives: int
    false_positives: int
    false_negatives: int
    true_negatives: int

    # Security-specific metrics
    critical_recall: float  # Recall for CRITICAL/HIGH severity
    critical_precision: float
    detection_rate_by_category: Dict[str, float] = field(default_factory=dict)
    detection_rate_by_severity: Dict[str, float] = field(default_factory=dict)

    # Confidence metrics
    mean_confidence_tp: float = 0.0  # Mean confidence of true positives
    mean_confidence_fp: float = 0.0  # Mean confidence of false positives

    # Performance
    total_scan_time_seconds: float = 0.0
    files_scanned: int = 0
    avg_time_per_file_ms: float = 0.0

    # Breakdown
    findings_by_detector: Dict[str, int] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            'precision': self.precision,
            'recall': self.recall,
            'f1_score': self.f1_score,
            'accuracy': self.accuracy,
            'true_positives': self.true_positives,
            'false_positives': self.false_positives,
            'false_negatives': self.false_negatives,
            'true_negatives': self.true_negatives,
            'critical_recall': self.critical_recall,
            'critical_precision': self.critical_precision,
            'detection_rate_by_category': self.detection_rate_by_category,
            'detection_rate_by_severity': self.detection_rate_by_severity,
            'mean_confidence_tp': self.mean_confidence_tp,
            'mean_confidence_fp': self.mean_confidence_fp,
            'total_scan_time_seconds': self.total_scan_time_seconds,
            'files_scanned': self.files_scanned,
            'avg_time_per_file_ms': self.avg_time_per_file_ms,
            'findings_by_detector': self.findings_by_detector,
        }

    def to_latex(self) -> str:
        """Generate LaTeX table row for research paper."""
        return (
            f"& {self.precision:.3f} & {self.recall:.3f} & {self.f1_score:.3f} "
            f"& {self.critical_recall:.3f} & {self.true_positives} & {self.false_positives} \\\\"
        )

    def to_markdown(self) -> str:
        """Generate Markdown table for documentation."""
        return f"""
## Evaluation Results

| Metric | Value |
|--------|-------|
| Precision | {self.precision:.3f} |
| Recall | {self.recall:.3f} |
| F1 Score | {self.f1_score:.3f} |
| Accuracy | {self.accuracy:.3f} |
| Critical Recall | {self.critical_recall:.3f} |

### Confusion Matrix
|  | Predicted Positive | Predicted Negative |
|--|--------------------|--------------------|
| **Actual Positive** | {self.true_positives} (TP) | {self.false_negatives} (FN) |
| **Actual Negative** | {self.false_positives} (FP) | {self.true_negatives} (TN) |

### Detection by Category
{self._category_table()}

### Performance
- Total scan time: {self.total_scan_time_seconds:.2f}s
- Files scanned: {self.files_scanned}
- Avg time per file: {self.avg_time_per_file_ms:.1f}ms
"""

    def _category_table(self) -> str:
        if not self.detection_rate_by_category:
            return "No category data"
        lines = ["| Category | Detection Rate |", "|----------|----------------|"]
        for cat, rate in sorted(self.detection_rate_by_category.items()):
            lines.append(f"| {cat} | {rate:.1%} |")
        return "\n".join(lines)


class SecurityMetrics:
    """
    Calculate security-focused evaluation metrics.

    Designed for vulnerability detection where:
    - False negatives are more costly than false positives (security risk)
    - Critical vulnerabilities must have high recall
    - Confidence calibration matters for prioritization
    """

    @staticmethod
    def calculate(
        findings: List[Finding],
        ground_truth: List[GroundTruth],
        scan_time_seconds: float = 0.0,
        files_scanned: int = 0,
        file_level: bool = True,
    ) -> MetricsReport:
        """
        Calculate comprehensive metrics comparing findings to ground truth.

        Args:
            findings: List of detector findings
            ground_truth: List of ground truth labels
            scan_time_seconds: Total scan time
            files_scanned: Number of files scanned
            file_level: If True, match at file level (ignoring line numbers)

        Returns:
            MetricsReport with all metrics
        """
        # Build lookup sets for matching
        finding_locations = SecurityMetrics._build_finding_set(findings, file_level=file_level)
        truth_vulnerable = SecurityMetrics._build_truth_set(ground_truth, vulnerable_only=True, file_level=file_level)
        truth_safe = SecurityMetrics._build_truth_set(ground_truth, vulnerable_only=False, file_level=file_level)

        # Calculate TP, FP, FN, TN
        true_positives = finding_locations & truth_vulnerable
        false_positives = finding_locations - truth_vulnerable
        false_negatives = truth_vulnerable - finding_locations
        true_negatives = truth_safe - finding_locations

        tp = len(true_positives)
        fp = len(false_positives)
        fn = len(false_negatives)
        tn = len(true_negatives)

        # Standard metrics
        precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0.0
        accuracy = (tp + tn) / (tp + fp + fn + tn) if (tp + fp + fn + tn) > 0 else 0.0

        # Critical recall (CRITICAL + HIGH severity)
        if file_level:
            critical_truth = {
                (SecurityMetrics._normalize_path(gt.file_path), 0)
                for gt in ground_truth
                if gt.is_vulnerable and gt.severity in ('CRITICAL', 'HIGH')
            }
            critical_findings = {
                (SecurityMetrics._normalize_path(f.file_path), 0)
                for f in findings
                if f.severity in (Severity.CRITICAL, Severity.HIGH)
            }
        else:
            critical_truth = {
                (SecurityMetrics._normalize_path(gt.file_path), gt.line_number)
                for gt in ground_truth
                if gt.is_vulnerable and gt.severity in ('CRITICAL', 'HIGH')
            }
            critical_findings = {
                (SecurityMetrics._normalize_path(f.file_path), f.line_number)
                for f in findings
                if f.severity in (Severity.CRITICAL, Severity.HIGH)
            }
        critical_detected = finding_locations & critical_truth
        critical_recall = len(critical_detected) / len(critical_truth) if critical_truth else 0.0

        # Critical precision
        critical_tp = len(critical_findings & critical_truth)
        critical_precision = critical_tp / len(critical_findings) if critical_findings else 0.0

        # Detection rate by category
        category_rates = SecurityMetrics._calculate_category_rates(findings, ground_truth)

        # Detection rate by severity
        severity_rates = SecurityMetrics._calculate_severity_rates(findings, ground_truth)

        # Confidence metrics
        mean_conf_tp, mean_conf_fp = SecurityMetrics._calculate_confidence_metrics(
            findings, truth_vulnerable
        )

        # Findings by detector
        detector_counts = {}
        for f in findings:
            cat = f.category.split(':')[0].strip() if f.category else 'unknown'
            detector_counts[cat] = detector_counts.get(cat, 0) + 1

        return MetricsReport(
            precision=precision,
            recall=recall,
            f1_score=f1,
            accuracy=accuracy,
            true_positives=tp,
            false_positives=fp,
            false_negatives=fn,
            true_negatives=tn,
            critical_recall=critical_recall,
            critical_precision=critical_precision,
            detection_rate_by_category=category_rates,
            detection_rate_by_severity=severity_rates,
            mean_confidence_tp=mean_conf_tp,
            mean_confidence_fp=mean_conf_fp,
            total_scan_time_seconds=scan_time_seconds,
            files_scanned=files_scanned,
            avg_time_per_file_ms=(scan_time_seconds * 1000 / files_scanned) if files_scanned > 0 else 0,
            findings_by_detector=detector_counts,
        )

    @staticmethod
    def _normalize_path(path: str) -> str:
        """Normalize path for comparison (extract filename for simple matching)."""
        # Convert to Path object for normalization
        p = Path(path)
        # Use last 3 parts for matching (e.g., 'vulnerable/direct/direct_000.py')
        parts = p.parts[-3:] if len(p.parts) >= 3 else p.parts
        return '/'.join(parts)

    @staticmethod
    def _build_finding_set(findings: List[Finding], file_level: bool = False) -> Set[Tuple[str, int]]:
        """Build set of (file_path, line_number) from findings."""
        if file_level:
            # Use file-level matching (line_number=0 as placeholder)
            return {(SecurityMetrics._normalize_path(f.file_path), 0) for f in findings if f.file_path}
        return {(SecurityMetrics._normalize_path(f.file_path), f.line_number) for f in findings if f.file_path and f.line_number}

    @staticmethod
    def _build_truth_set(ground_truth: List[GroundTruth], vulnerable_only: bool, file_level: bool = False) -> Set[Tuple[str, int]]:
        """Build set of (file_path, line_number) from ground truth."""
        if file_level:
            if vulnerable_only:
                return {(SecurityMetrics._normalize_path(gt.file_path), 0) for gt in ground_truth if gt.is_vulnerable}
            else:
                return {(SecurityMetrics._normalize_path(gt.file_path), 0) for gt in ground_truth if not gt.is_vulnerable}
        if vulnerable_only:
            return {(SecurityMetrics._normalize_path(gt.file_path), gt.line_number) for gt in ground_truth if gt.is_vulnerable}
        else:
            return {(SecurityMetrics._normalize_path(gt.file_path), gt.line_number) for gt in ground_truth if not gt.is_vulnerable}

    @staticmethod
    def _calculate_category_rates(
        findings: List[Finding],
        ground_truth: List[GroundTruth]
    ) -> Dict[str, float]:
        """Calculate detection rate for each vulnerability category."""
        rates = {}

        # Group ground truth by category
        by_category: Dict[str, List[GroundTruth]] = {}
        for gt in ground_truth:
            if gt.is_vulnerable:
                cat = gt.category.split(':')[0].strip()
                by_category.setdefault(cat, []).append(gt)

        # Build finding lookup
        finding_locations = {(f.file_path, f.line_number) for f in findings}

        # Calculate rate per category
        for cat, truths in by_category.items():
            detected = sum(
                1 for gt in truths
                if (gt.file_path, gt.line_number) in finding_locations
            )
            rates[cat] = detected / len(truths) if truths else 0.0

        return rates

    @staticmethod
    def _calculate_severity_rates(
        findings: List[Finding],
        ground_truth: List[GroundTruth]
    ) -> Dict[str, float]:
        """Calculate detection rate for each severity level."""
        rates = {}
        finding_locations = {(f.file_path, f.line_number) for f in findings}

        for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
            truths = [gt for gt in ground_truth if gt.is_vulnerable and gt.severity == severity]
            if truths:
                detected = sum(
                    1 for gt in truths
                    if (gt.file_path, gt.line_number) in finding_locations
                )
                rates[severity] = detected / len(truths)

        return rates

    @staticmethod
    def _calculate_confidence_metrics(
        findings: List[Finding],
        truth_vulnerable: Set[Tuple[str, int]]
    ) -> Tuple[float, float]:
        """Calculate mean confidence for TPs and FPs."""
        tp_confidences = []
        fp_confidences = []

        for f in findings:
            loc = (f.file_path, f.line_number)
            if loc in truth_vulnerable:
                tp_confidences.append(f.confidence)
            else:
                fp_confidences.append(f.confidence)

        mean_tp = np.mean(tp_confidences) if tp_confidences else 0.0
        mean_fp = np.mean(fp_confidences) if fp_confidences else 0.0

        return float(mean_tp), float(mean_fp)

    @staticmethod
    def compare_methods(
        method_results: Dict[str, MetricsReport],
        baseline_name: str = "pattern_only"
    ) -> str:
        """
        Generate comparison table between detection methods.

        Args:
            method_results: Dict mapping method name to MetricsReport
            baseline_name: Name of baseline method for relative comparison

        Returns:
            Markdown table comparing methods
        """
        if baseline_name not in method_results:
            baseline = None
        else:
            baseline = method_results[baseline_name]

        lines = [
            "| Method | Precision | Recall | F1 | Critical Recall | TP | FP |",
            "|--------|-----------|--------|----|-----------------|----|----| "
        ]

        for name, report in sorted(method_results.items()):
            # Calculate relative improvement if baseline exists
            if baseline and name != baseline_name:
                f1_delta = ((report.f1_score - baseline.f1_score) / baseline.f1_score * 100
                           if baseline.f1_score > 0 else 0)
                f1_str = f"{report.f1_score:.3f} ({f1_delta:+.1f}%)"
            else:
                f1_str = f"{report.f1_score:.3f}"

            lines.append(
                f"| {name} | {report.precision:.3f} | {report.recall:.3f} | {f1_str} | "
                f"{report.critical_recall:.3f} | {report.true_positives} | {report.false_positives} |"
            )

        return "\n".join(lines)
