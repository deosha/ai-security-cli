"""Unified result models for static and live testing"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional

from .finding import Finding
from .vulnerability import LiveTestResult, LiveVulnerability


def _get_risk_level(score: float) -> str:
    """Get risk level from score"""
    if score >= 90:
        return "EXCELLENT"
    elif score >= 75:
        return "GOOD"
    elif score >= 60:
        return "ADEQUATE"
    elif score >= 40:
        return "NEEDS_IMPROVEMENT"
    elif score >= 20:
        return "POOR"
    else:
        return "CRITICAL"


def _get_confidence_level(confidence: float) -> str:
    """Get confidence level from float"""
    if confidence >= 0.9:
        return "VERY_HIGH"
    elif confidence >= 0.75:
        return "HIGH"
    elif confidence >= 0.5:
        return "MEDIUM"
    else:
        return "LOW"


@dataclass
class CategoryScore:
    """Score for a single security category"""

    category_id: str
    category_name: str
    score: int  # 0-100
    confidence: float  # 0.0-1.0
    subscores: Dict[str, int] = field(default_factory=dict)
    detected_controls: List[str] = field(default_factory=list)
    gaps: List[str] = field(default_factory=list)
    evidence: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to JSON-serializable dict"""
        return {
            "category_id": self.category_id,
            "category_name": self.category_name,
            "score": self.score,
            "confidence": round(self.confidence, 2),
            "subscores": self.subscores,
            "detected_controls": self.detected_controls,
            "gaps": self.gaps,
            "evidence": self.evidence,
        }


@dataclass
class ScanResult:
    """Result from static code analysis."""

    scan_type: str = "static"
    target_path: str = ""
    timestamp: datetime = field(default_factory=datetime.now)
    findings: List[Finding] = field(default_factory=list)
    category_scores: Dict[str, CategoryScore] = field(default_factory=dict)
    overall_score: float = 100.0
    confidence: float = 0.0
    files_scanned: int = 0
    duration_seconds: float = 0.0
    metadata: Dict[str, Any] = field(default_factory=dict)

    @property
    def risk_level(self) -> str:
        return _get_risk_level(self.overall_score)

    @property
    def findings_by_severity(self) -> Dict[str, int]:
        """Count findings by severity"""
        counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        for finding in self.findings:
            counts[finding.severity.value] += 1
        return counts

    def to_dict(self) -> Dict[str, Any]:
        """Convert to JSON-serializable dict"""
        return {
            "scan_type": self.scan_type,
            "target_path": self.target_path,
            "timestamp": self.timestamp.isoformat(),
            "findings": [f.to_dict() for f in self.findings],
            "category_scores": {k: v.to_dict() for k, v in self.category_scores.items()},
            "overall_score": round(self.overall_score, 2),
            "confidence": round(self.confidence, 2),
            "risk_level": self.risk_level,
            "files_scanned": self.files_scanned,
            "duration_seconds": round(self.duration_seconds, 2),
            "findings_by_severity": self.findings_by_severity,
            "metadata": self.metadata,
        }


@dataclass
class TestResult:
    """Result from live model testing."""

    test_type: str = "live"
    provider: str = ""
    model: str = ""
    timestamp: datetime = field(default_factory=datetime.now)
    vulnerabilities: List[LiveVulnerability] = field(default_factory=list)
    detector_results: List[LiveTestResult] = field(default_factory=list)
    overall_score: float = 100.0
    confidence: float = 0.0
    duration_seconds: float = 0.0
    metadata: Dict[str, Any] = field(default_factory=dict)

    @property
    def risk_level(self) -> str:
        return _get_risk_level(self.overall_score)

    @property
    def vulnerabilities_by_severity(self) -> Dict[str, int]:
        """Count vulnerabilities by severity"""
        counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        for vuln in self.vulnerabilities:
            counts[vuln.severity.value] += 1
        return counts

    @property
    def total_tests_run(self) -> int:
        """Total tests run across all detectors"""
        return sum(r.tests_run for r in self.detector_results)

    @property
    def total_tests_passed(self) -> int:
        """Total tests passed across all detectors"""
        return sum(r.tests_passed for r in self.detector_results)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to JSON-serializable dict"""
        return {
            "test_type": self.test_type,
            "provider": self.provider,
            "model": self.model,
            "timestamp": self.timestamp.isoformat(),
            "vulnerabilities": [v.to_dict() for v in self.vulnerabilities],
            "detector_results": [d.to_dict() for d in self.detector_results],
            "overall_score": round(self.overall_score, 2),
            "confidence": round(self.confidence, 2),
            "risk_level": self.risk_level,
            "vulnerabilities_by_severity": self.vulnerabilities_by_severity,
            "total_tests_run": self.total_tests_run,
            "total_tests_passed": self.total_tests_passed,
            "duration_seconds": round(self.duration_seconds, 2),
            "metadata": self.metadata,
        }


@dataclass
class UnifiedResult:
    """
    Combined result supporting both static and live testing.

    Can contain just static results, just live results, or both (hybrid).
    """

    result_type: str  # "static", "live", or "hybrid"
    timestamp: datetime = field(default_factory=datetime.now)

    # Static analysis results (optional)
    static_result: Optional[ScanResult] = None

    # Live testing results (optional)
    live_result: Optional[TestResult] = None

    # Combined scoring (calculated from components)
    overall_score: float = 100.0
    confidence: float = 0.0

    # Tool metadata
    tool_version: str = "1.0.0"
    schema_version: str = "1.0"

    @property
    def risk_level(self) -> str:
        return _get_risk_level(self.overall_score)

    @property
    def confidence_level(self) -> str:
        return _get_confidence_level(self.confidence)

    def calculate_combined_score(
        self, static_weight: float = 0.4, live_weight: float = 0.6
    ) -> None:
        """
        Calculate combined score from static and live results.

        Uses hybrid scoring approach:
        - Static analysis: 40% weight (code patterns)
        - Live testing: 60% weight (runtime behavior)
        """
        if self.result_type == "static" and self.static_result:
            self.overall_score = self.static_result.overall_score
            self.confidence = self.static_result.confidence
        elif self.result_type == "live" and self.live_result:
            self.overall_score = self.live_result.overall_score
            self.confidence = self.live_result.confidence
        elif self.result_type == "hybrid" and self.static_result and self.live_result:
            # Hybrid scoring
            self.overall_score = (
                self.static_result.overall_score * static_weight
                + self.live_result.overall_score * live_weight
            )
            # Confidence increases when both agree
            score_diff = abs(
                self.static_result.overall_score - self.live_result.overall_score
            )
            if score_diff < 10:
                self.confidence = 0.95  # Very high agreement
            elif score_diff < 20:
                self.confidence = 0.85
            elif score_diff < 30:
                self.confidence = 0.70
            else:
                self.confidence = 0.50  # Low agreement

    def to_dict(self) -> Dict[str, Any]:
        """Convert to JSON-serializable dict (full report format)"""
        result = {
            "version": self.schema_version,
            "metadata": {
                "tool": "aisentry",
                "tool_version": self.tool_version,
                "timestamp": self.timestamp.isoformat(),
                "result_type": self.result_type,
            },
            "result_type": self.result_type,
            "summary": {
                "overall_score": round(self.overall_score, 2),
                "risk_level": self.risk_level,
                "confidence": round(self.confidence, 2),
                "confidence_level": self.confidence_level,
            },
        }

        if self.static_result:
            result["static_analysis"] = self.static_result.to_dict()

        if self.live_result:
            result["live_testing"] = self.live_result.to_dict()

        # Build recommendations
        recommendations = []
        if self.static_result:
            critical_count = self.static_result.findings_by_severity.get("CRITICAL", 0)
            high_count = self.static_result.findings_by_severity.get("HIGH", 0)
            if critical_count > 0:
                recommendations.append(
                    f"Address {critical_count} CRITICAL code vulnerabilities immediately"
                )
            if high_count > 0:
                recommendations.append(
                    f"Review and fix {high_count} HIGH severity code issues"
                )

        if self.live_result:
            critical_count = self.live_result.vulnerabilities_by_severity.get("CRITICAL", 0)
            high_count = self.live_result.vulnerabilities_by_severity.get("HIGH", 0)
            if critical_count > 0:
                recommendations.append(
                    f"Investigate {critical_count} CRITICAL runtime vulnerabilities"
                )
            if high_count > 0:
                recommendations.append(
                    f"Address {high_count} HIGH severity model vulnerabilities"
                )

        if not recommendations:
            if self.overall_score >= 90:
                recommendations.append("Excellent security posture - maintain current practices")
            elif self.overall_score >= 75:
                recommendations.append("Good security - consider periodic reviews")
            else:
                recommendations.append("Review security configurations and controls")

        result["summary"]["recommendations"] = recommendations

        return result
