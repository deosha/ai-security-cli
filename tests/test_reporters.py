"""
Unit tests for aisentry reporters (JSON, SARIF).
"""

import json
import pytest

from aisentry.models.finding import Finding, Severity
from aisentry.models.result import CategoryScore, ScanResult
from aisentry.reporters.json_reporter import JSONReporter
from aisentry.reporters.sarif_reporter import SARIFReporter


class TestJSONReporter:
    """Test JSONReporter class."""

    @pytest.fixture
    def reporter(self):
        """Create JSON reporter instance."""
        return JSONReporter(pretty=True)

    @pytest.fixture
    def sample_findings(self):
        """Create sample findings."""
        return [
            Finding(
                id="F001",
                category="LLM01: Prompt Injection",
                severity=Severity.HIGH,
                confidence=0.85,
                title="User input in prompt",
                description="User input directly concatenated into prompt",
                file_path="app.py",
                line_number=42,
                code_snippet='f"Process: {user_input}"',
                recommendation="Use parameterized prompts",
            ),
            Finding(
                id="F002",
                category="LLM02: Insecure Output",
                severity=Severity.MEDIUM,
                confidence=0.7,
                title="Unvalidated output",
                description="LLM output used without validation",
                file_path="utils.py",
                line_number=15,
            ),
        ]

    @pytest.fixture
    def sample_scan_result(self, sample_findings):
        """Create sample scan result."""
        return ScanResult(
            target_path="/path/to/project",
            findings=sample_findings,
            category_scores={
                "prompt_security": CategoryScore(
                    category_id="prompt_security",
                    category_name="Prompt Security",
                    score=75,
                    confidence=0.85,
                    detected_controls=["input_validation"],
                    gaps=["No output filtering"],
                ),
            },
            overall_score=75.0,
            confidence=0.8,
            files_scanned=10,
            duration_seconds=1.5,
            metadata={"version": "1.0"},
        )

    def test_reporter_initialization(self):
        """Test reporter initialization."""
        reporter = JSONReporter(pretty=True, verbose=True)
        assert reporter.pretty is True
        assert reporter.indent == 2

        reporter = JSONReporter(pretty=False)
        assert reporter.indent is None

    def test_generate_scan_report_structure(self, reporter, sample_scan_result):
        """Test scan report has correct structure."""
        report_json = reporter.generate_scan_report(sample_scan_result)
        report = json.loads(report_json)

        assert report["report_type"] == "static_scan"
        assert "generated_at" in report
        assert "summary" in report
        assert "category_scores" in report
        assert "findings" in report
        assert "metadata" in report

    def test_generate_scan_report_summary(self, reporter, sample_scan_result):
        """Test scan report summary fields."""
        report_json = reporter.generate_scan_report(sample_scan_result)
        report = json.loads(report_json)

        summary = report["summary"]
        assert summary["target"] == "/path/to/project"
        assert summary["files_scanned"] == 10
        assert summary["overall_score"] == 75.0
        assert summary["confidence"] == 0.8
        assert summary["findings_count"] == 2

    def test_generate_scan_report_severity_breakdown(self, reporter, sample_scan_result):
        """Test severity breakdown in report."""
        report_json = reporter.generate_scan_report(sample_scan_result)
        report = json.loads(report_json)

        breakdown = report["summary"]["severity_breakdown"]
        assert breakdown["HIGH"] == 1
        assert breakdown["MEDIUM"] == 1
        assert breakdown["CRITICAL"] == 0

    def test_generate_scan_report_findings(self, reporter, sample_scan_result):
        """Test findings in report."""
        report_json = reporter.generate_scan_report(sample_scan_result)
        report = json.loads(report_json)

        findings = report["findings"]
        assert len(findings) == 2

        first = findings[0]
        assert first["id"] == "F001"
        assert first["category"] == "LLM01: Prompt Injection"
        assert first["severity"] == "HIGH"
        assert first["confidence"] == 0.85
        assert first["file_path"] == "app.py"
        assert first["line_number"] == 42

    def test_generate_scan_report_category_scores(self, reporter, sample_scan_result):
        """Test category scores in report."""
        report_json = reporter.generate_scan_report(sample_scan_result)
        report = json.loads(report_json)

        scores = report["category_scores"]
        assert len(scores) == 1
        assert scores[0]["category_id"] == "prompt_security"
        assert scores[0]["score"] == 75
        assert "input_validation" in scores[0]["detected_controls"]

    def test_generate_scan_report_metadata(self, reporter, sample_scan_result):
        """Test metadata in report."""
        report_json = reporter.generate_scan_report(sample_scan_result)
        report = json.loads(report_json)

        assert report["metadata"] == {"version": "1.0"}

    def test_empty_scan_result(self, reporter):
        """Test report for empty scan result."""
        result = ScanResult(
            target_path="/empty/project",
            files_scanned=0,
        )
        report_json = reporter.generate_scan_report(result)
        report = json.loads(report_json)

        assert report["summary"]["findings_count"] == 0
        assert report["findings"] == []

    def test_get_severity_breakdown(self, reporter, sample_findings):
        """Test _get_severity_breakdown method."""
        breakdown = reporter._get_severity_breakdown(sample_findings)
        assert breakdown["HIGH"] == 1
        assert breakdown["MEDIUM"] == 1
        assert breakdown["LOW"] == 0
        assert breakdown["CRITICAL"] == 0
        assert breakdown["INFO"] == 0

    def test_format_findings(self, reporter, sample_findings):
        """Test _format_findings method."""
        formatted = reporter._format_findings(sample_findings)
        assert len(formatted) == 2
        assert formatted[0]["id"] == "F001"
        assert formatted[0]["severity"] == "HIGH"
        assert formatted[0]["confidence"] == 0.85


class TestSARIFReporter:
    """Test SARIFReporter class."""

    @pytest.fixture
    def reporter(self):
        """Create SARIF reporter instance."""
        return SARIFReporter()

    @pytest.fixture
    def sample_findings(self):
        """Create sample findings."""
        return [
            Finding(
                id="F001",
                category="LLM01: Prompt Injection",
                severity=Severity.HIGH,
                confidence=0.85,
                title="User input in prompt",
                description="User input directly concatenated",
                file_path="app.py",
                line_number=42,
                cwe_id="CWE-94",
            ),
            Finding(
                id="F002",
                category="LLM02: Insecure Output",
                severity=Severity.CRITICAL,
                confidence=0.95,
                title="Unvalidated output execution",
                file_path="utils.py",
                line_number=15,
            ),
        ]

    @pytest.fixture
    def sample_scan_result(self, sample_findings):
        """Create sample scan result."""
        return ScanResult(
            target_path="/path/to/project",
            findings=sample_findings,
            files_scanned=5,
        )

    def test_reporter_initialization(self):
        """Test reporter initialization."""
        reporter = SARIFReporter(verbose=True)
        assert reporter.verbose is True

    def test_generate_sarif_structure(self, reporter, sample_scan_result):
        """Test SARIF report has correct structure."""
        sarif_json = reporter.generate_scan_report(sample_scan_result)
        sarif = json.loads(sarif_json)

        assert "$schema" in sarif
        assert sarif["version"] == "2.1.0"
        assert "runs" in sarif
        assert len(sarif["runs"]) == 1

    def test_generate_sarif_tool_info(self, reporter, sample_scan_result):
        """Test SARIF tool information."""
        sarif_json = reporter.generate_scan_report(sample_scan_result)
        sarif = json.loads(sarif_json)

        tool = sarif["runs"][0]["tool"]["driver"]
        assert tool["name"] == "aisentry"
        assert "version" in tool
        assert "informationUri" in tool

    def test_generate_sarif_rules(self, reporter, sample_scan_result):
        """Test SARIF rules section."""
        sarif_json = reporter.generate_scan_report(sample_scan_result)
        sarif = json.loads(sarif_json)

        rules = sarif["runs"][0]["tool"]["driver"]["rules"]
        assert len(rules) >= 1

    def test_generate_sarif_results(self, reporter, sample_scan_result):
        """Test SARIF results section."""
        sarif_json = reporter.generate_scan_report(sample_scan_result)
        sarif = json.loads(sarif_json)

        results = sarif["runs"][0]["results"]
        assert len(results) == 2

    def test_sarif_result_fields(self, reporter, sample_scan_result):
        """Test individual SARIF result fields."""
        sarif_json = reporter.generate_scan_report(sample_scan_result)
        sarif = json.loads(sarif_json)

        result = sarif["runs"][0]["results"][0]
        assert "ruleId" in result
        assert "level" in result
        assert "message" in result
        assert "locations" in result

    def test_sarif_severity_mapping(self, reporter, sample_scan_result):
        """Test SARIF severity level mapping."""
        sarif_json = reporter.generate_scan_report(sample_scan_result)
        sarif = json.loads(sarif_json)

        results = sarif["runs"][0]["results"]
        levels = [r["level"] for r in results]
        assert "error" in levels or "warning" in levels

    def test_sarif_location_info(self, reporter, sample_scan_result):
        """Test SARIF location information."""
        sarif_json = reporter.generate_scan_report(sample_scan_result)
        sarif = json.loads(sarif_json)

        result = sarif["runs"][0]["results"][0]
        location = result["locations"][0]["physicalLocation"]
        assert "artifactLocation" in location
        assert "region" in location

    def test_empty_scan_result(self, reporter):
        """Test SARIF report for empty scan result."""
        result = ScanResult(
            target_path="/empty/project",
            files_scanned=0,
        )
        sarif_json = reporter.generate_scan_report(result)
        sarif = json.loads(sarif_json)

        assert sarif["runs"][0]["results"] == []

    def test_sarif_schema_url(self, reporter, sample_scan_result):
        """Test SARIF schema URL is valid."""
        sarif_json = reporter.generate_scan_report(sample_scan_result)
        sarif = json.loads(sarif_json)

        schema = sarif["$schema"]
        assert "sarif" in schema.lower()
        assert "2.1.0" in schema


class TestBaseReporter:
    """Test base reporter functionality through subclasses."""

    def test_json_reporter_inheritance(self):
        """Test JSONReporter inherits from BaseReporter."""
        reporter = JSONReporter()
        assert hasattr(reporter, 'generate_scan_report')
        assert hasattr(reporter, 'verbose')

    def test_sarif_reporter_inheritance(self):
        """Test SARIFReporter inherits from BaseReporter."""
        reporter = SARIFReporter()
        assert hasattr(reporter, 'generate_scan_report')
        assert hasattr(reporter, 'verbose')
