"""JSON reporter for security scan results"""

import json
from datetime import datetime
from typing import Any, Dict, List

from aisentry.models.finding import Finding, Severity
from aisentry.models.result import ScanResult, TestResult, UnifiedResult
from aisentry.models.vulnerability import LiveVulnerability

from .base_reporter import BaseReporter


class JSONReporter(BaseReporter):
    """
    Generates JSON reports for security scan and test results.

    Output follows a consistent schema for both static and live results.
    """

    def __init__(self, pretty: bool = True, verbose: bool = False):
        """
        Initialize JSON reporter.

        Args:
            pretty: Use indented formatting
            verbose: Include additional debug information
        """
        super().__init__(verbose=verbose)
        self.pretty = pretty
        self.indent = 2 if pretty else None

    def generate_scan_report(self, result: ScanResult) -> str:
        """Generate JSON report for static scan results."""
        report = {
            "report_type": "static_scan",
            "generated_at": datetime.utcnow().isoformat() + "Z",
            "summary": {
                "target": result.target_path,
                "files_scanned": result.files_scanned,
                "overall_score": round(result.overall_score, 2),
                "confidence": round(result.confidence, 2),
                "duration_seconds": round(result.duration_seconds, 3),
                "findings_count": len(result.findings),
                "severity_breakdown": self._get_severity_breakdown(result.findings),
            },
            "category_scores": self._format_category_scores(result.category_scores),
            "findings": self._format_findings(result.findings),
            "metadata": result.metadata or {},
        }

        return json.dumps(report, indent=self.indent, default=str)

    def generate_test_report(self, result: TestResult) -> str:
        """Generate JSON report for live test results."""
        tests_run = result.total_tests_run
        tests_passed = result.total_tests_passed

        report = {
            "report_type": "live_test",
            "generated_at": datetime.utcnow().isoformat() + "Z",
            "summary": {
                "provider": result.provider,
                "model": result.model,
                "overall_score": round(result.overall_score, 2),
                "confidence": round(result.confidence, 2),
                "tests_run": tests_run,
                "tests_passed": tests_passed,
                "pass_rate": round(tests_passed / max(tests_run, 1) * 100, 1),
                "duration_seconds": round(result.duration_seconds, 3),
                "vulnerabilities_count": len(result.vulnerabilities),
                "severity_breakdown": self._get_vuln_severity_breakdown(result.vulnerabilities),
            },
            "detector_results": self._format_detector_results(result.detector_results),
            "vulnerabilities": self._format_vulnerabilities(result.vulnerabilities),
            "metadata": result.metadata or {},
        }

        return json.dumps(report, indent=self.indent, default=str)

    def generate_unified_report(self, result: UnifiedResult) -> str:
        """Generate JSON report combining static and live results."""
        # Compute derived values from actual result fields
        static_score = result.static_result.overall_score if result.static_result else None
        live_score = result.live_result.overall_score if result.live_result else None

        # Count issues
        total_issues = 0
        critical_issues = 0
        high_issues = 0

        if result.static_result:
            total_issues += len(result.static_result.findings)
            severity_counts = result.static_result.findings_by_severity
            critical_issues += severity_counts.get("CRITICAL", 0)
            high_issues += severity_counts.get("HIGH", 0)

        if result.live_result:
            total_issues += len(result.live_result.vulnerabilities)
            severity_counts = result.live_result.vulnerabilities_by_severity
            critical_issues += severity_counts.get("CRITICAL", 0)
            high_issues += severity_counts.get("HIGH", 0)

        # Build recommendations
        recommendations = []
        if critical_issues > 0:
            recommendations.append(f"Address {critical_issues} CRITICAL issues immediately")
        if high_issues > 0:
            recommendations.append(f"Review and fix {high_issues} HIGH severity issues")
        if not recommendations:
            if result.overall_score >= 90:
                recommendations.append("Excellent security posture - maintain current practices")
            elif result.overall_score >= 75:
                recommendations.append("Good security - consider periodic reviews")
            else:
                recommendations.append("Review security configurations and controls")

        report = {
            "report_type": "unified",
            "generated_at": datetime.utcnow().isoformat() + "Z",
            "summary": {
                "overall_score": round(result.overall_score, 2),
                "static_score": round(static_score, 2) if static_score is not None else None,
                "live_score": round(live_score, 2) if live_score is not None else None,
                "confidence": round(result.confidence, 2),
                "total_issues": total_issues,
                "critical_issues": critical_issues,
                "high_issues": high_issues,
            },
            "static_results": self._format_scan_result(result.static_result) if result.static_result else None,
            "live_results": self._format_test_result(result.live_result) if result.live_result else None,
            "recommendations": recommendations,
        }

        return json.dumps(report, indent=self.indent, default=str)

    def _get_severity_breakdown(self, findings: List[Finding]) -> Dict[str, int]:
        """Get count of findings by severity."""
        breakdown = {s.value: 0 for s in Severity}
        for finding in findings:
            breakdown[finding.severity.value] += 1
        return breakdown

    def _get_vuln_severity_breakdown(self, vulns: List[LiveVulnerability]) -> Dict[str, int]:
        """Get count of vulnerabilities by severity."""
        breakdown = {s.value: 0 for s in Severity}
        for vuln in vulns:
            breakdown[vuln.severity.value] += 1
        return breakdown

    def _format_category_scores(self, category_scores: Dict) -> List[Dict[str, Any]]:
        """Format category scores for JSON output."""
        scores = []
        for cat_id, score in category_scores.items():
            scores.append({
                "category_id": cat_id,
                "category_name": score.category_name,
                "score": round(score.score, 2),
                "confidence": round(score.confidence, 2),
                "subscores": getattr(score, 'subscores', {}),
                "detected_controls": getattr(score, 'detected_controls', []),
                "gaps": getattr(score, 'gaps', []),
            })
        return scores

    def _format_findings(self, findings: List[Finding]) -> List[Dict[str, Any]]:
        """Format findings for JSON output."""
        formatted = []
        for finding in findings:
            formatted.append({
                "id": finding.id,
                "category": finding.category,
                "severity": finding.severity.value,
                "confidence": round(finding.confidence, 2),
                "title": finding.title,
                "description": finding.description,
                "file_path": finding.file_path,
                "line_number": finding.line_number,
                "code_snippet": finding.code_snippet,
                "recommendation": finding.recommendation,
            })
        return formatted

    def _format_vulnerabilities(self, vulns: List[LiveVulnerability]) -> List[Dict[str, Any]]:
        """Format vulnerabilities for JSON output."""
        formatted = []
        for vuln in vulns:
            formatted.append({
                "id": vuln.id,
                "detector_id": vuln.detector_id,
                "severity": vuln.severity.value,
                "confidence": round(vuln.confidence, 2),
                "title": vuln.title,
                "description": vuln.description,
                "prompt_used": vuln.prompt_used,
                "response_preview": vuln.response_received[:200] + "..." if len(vuln.response_received) > 200 else vuln.response_received,
                "evidence": vuln.evidence,
                "remediation": vuln.remediation,
            })
        return formatted

    def _format_detector_results(self, results: List) -> List[Dict[str, Any]]:
        """Format detector results for JSON output."""
        formatted = []
        for result in results:
            formatted.append({
                "detector_id": result.detector_id,
                "detector_name": result.detector_name,
                "score": round(result.score, 2),
                "confidence": round(result.confidence, 2),
                "tests_run": result.tests_run,
                "tests_passed": result.tests_passed,
                "vulnerabilities_count": len(result.vulnerabilities),
                "duration_ms": round(result.duration_ms, 1),
            })
        return formatted

    def _format_scan_result(self, result: ScanResult) -> Dict[str, Any]:
        """Format scan result for unified report."""
        return {
            "target": result.target_path,
            "files_scanned": result.files_scanned,
            "score": round(result.overall_score, 2),
            "findings_count": len(result.findings),
            "severity_breakdown": self._get_severity_breakdown(result.findings),
        }

    def _format_test_result(self, result: TestResult) -> Dict[str, Any]:
        """Format test result for unified report."""
        return {
            "provider": result.provider,
            "model": result.model,
            "score": round(result.overall_score, 2),
            "tests_run": result.total_tests_run,
            "tests_passed": result.total_tests_passed,
            "vulnerabilities_count": len(result.vulnerabilities),
        }
