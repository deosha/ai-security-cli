"""
Unit tests for aisentry models (Finding, ScanResult, CategoryScore).
"""

from datetime import datetime

from aisentry.models.finding import Confidence, Finding, Severity
from aisentry.models.result import CategoryScore, ScanResult, _get_risk_level, _get_confidence_level


class TestSeverity:
    """Test Severity enum."""

    def test_severity_values(self):
        """Test severity enum values."""
        assert Severity.CRITICAL.value == "CRITICAL"
        assert Severity.HIGH.value == "HIGH"
        assert Severity.MEDIUM.value == "MEDIUM"
        assert Severity.LOW.value == "LOW"
        assert Severity.INFO.value == "INFO"

    def test_severity_ordering(self):
        """Test that severities can be compared by name."""
        severities = [Severity.INFO, Severity.CRITICAL, Severity.LOW]
        # Sort by value alphabetically
        sorted_names = sorted([s.value for s in severities])
        assert sorted_names == ["CRITICAL", "INFO", "LOW"]


class TestConfidence:
    """Test Confidence enum."""

    def test_confidence_properties(self):
        """Test confidence level properties."""
        assert Confidence.HIGH.min_value == 0.9
        assert Confidence.HIGH.max_value == 1.0
        assert "High confidence" in Confidence.HIGH.description

        assert Confidence.MEDIUM.min_value == 0.6
        assert Confidence.MEDIUM.max_value == 0.89

        assert Confidence.LOW.min_value == 0.3
        assert Confidence.LOW.max_value == 0.59

        assert Confidence.UNCERTAIN.min_value == 0.0
        assert Confidence.UNCERTAIN.max_value == 0.29

    def test_from_score_high(self):
        """Test from_score returns HIGH for >= 0.9."""
        assert Confidence.from_score(0.9) == Confidence.HIGH
        assert Confidence.from_score(0.95) == Confidence.HIGH
        assert Confidence.from_score(1.0) == Confidence.HIGH

    def test_from_score_medium(self):
        """Test from_score returns MEDIUM for 0.6-0.89."""
        assert Confidence.from_score(0.6) == Confidence.MEDIUM
        assert Confidence.from_score(0.75) == Confidence.MEDIUM
        assert Confidence.from_score(0.89) == Confidence.MEDIUM

    def test_from_score_low(self):
        """Test from_score returns LOW for 0.3-0.59."""
        assert Confidence.from_score(0.3) == Confidence.LOW
        assert Confidence.from_score(0.45) == Confidence.LOW
        assert Confidence.from_score(0.59) == Confidence.LOW

    def test_from_score_uncertain(self):
        """Test from_score returns UNCERTAIN for < 0.3."""
        assert Confidence.from_score(0.0) == Confidence.UNCERTAIN
        assert Confidence.from_score(0.15) == Confidence.UNCERTAIN
        assert Confidence.from_score(0.29) == Confidence.UNCERTAIN


class TestFinding:
    """Test Finding dataclass."""

    def test_finding_creation(self):
        """Test basic finding creation."""
        finding = Finding(
            id="F001",
            category="LLM01: Prompt Injection",
            severity=Severity.HIGH,
            confidence=0.85,
            title="User input in prompt",
        )
        assert finding.id == "F001"
        assert finding.category == "LLM01: Prompt Injection"
        assert finding.severity == Severity.HIGH
        assert finding.confidence == 0.85
        assert finding.title == "User input in prompt"

    def test_finding_optional_fields(self):
        """Test finding with optional fields."""
        finding = Finding(
            id="F002",
            category="LLM02",
            severity=Severity.MEDIUM,
            confidence=0.7,
            title="Test finding",
            description="Detailed description",
            file_path="/path/to/file.py",
            line_number=42,
            code_snippet="vulnerable_code()",
            recommendation="Fix the code",
            cwe_id="CWE-94",
            owasp_category="LLM02",
            evidence={"source": "user_input"},
        )
        assert finding.description == "Detailed description"
        assert finding.file_path == "/path/to/file.py"
        assert finding.line_number == 42
        assert finding.cwe_id == "CWE-94"

    def test_finding_default_values(self):
        """Test finding default values."""
        finding = Finding(
            id="F003",
            category="LLM01",
            severity=Severity.LOW,
            confidence=0.5,
            title="Test",
        )
        assert finding.description is None
        assert finding.file_path is None
        assert finding.line_number is None
        assert finding.evidence == {}

    def test_confidence_level_property(self):
        """Test confidence_level property."""
        finding_high = Finding(
            id="1", category="LLM01", severity=Severity.HIGH,
            confidence=0.95, title="High confidence"
        )
        assert finding_high.confidence_level == Confidence.HIGH

        finding_medium = Finding(
            id="2", category="LLM01", severity=Severity.HIGH,
            confidence=0.7, title="Medium confidence"
        )
        assert finding_medium.confidence_level == Confidence.MEDIUM

    def test_to_dict_minimal(self):
        """Test to_dict with minimal fields."""
        finding = Finding(
            id="F001",
            category="LLM01",
            severity=Severity.HIGH,
            confidence=0.85,
            title="Test finding",
        )
        result = finding.to_dict()
        assert result["id"] == "F001"
        assert result["category"] == "LLM01"
        assert result["severity"] == "HIGH"
        assert result["confidence"] == 0.85
        assert result["title"] == "Test finding"
        # Optional fields should not be present
        assert "description" not in result
        assert "file_path" not in result

    def test_to_dict_full(self):
        """Test to_dict with all fields."""
        finding = Finding(
            id="F001",
            category="LLM01",
            severity=Severity.CRITICAL,
            confidence=0.95,
            title="Critical finding",
            description="A critical issue",
            file_path="app.py",
            line_number=10,
            code_snippet="code",
            recommendation="Fix it",
            cwe_id="CWE-94",
            owasp_category="LLM01",
            evidence={"key": "value"},
        )
        result = finding.to_dict()
        assert result["description"] == "A critical issue"
        assert result["file_path"] == "app.py"
        assert result["line_number"] == 10
        assert result["code_snippet"] == "code"
        assert result["recommendation"] == "Fix it"
        assert result["cwe_id"] == "CWE-94"
        assert result["owasp_category"] == "LLM01"
        assert result["evidence"] == {"key": "value"}

    def test_str_representation(self):
        """Test string representation."""
        finding = Finding(
            id="F001",
            category="LLM01",
            severity=Severity.HIGH,
            confidence=0.85,
            title="Test finding",
            file_path="app.py",
            line_number=42,
        )
        result = str(finding)
        assert "[HIGH]" in result
        assert "Test finding" in result
        assert "85%" in result
        assert "app.py:42" in result

    def test_str_without_location(self):
        """Test string representation without file path."""
        finding = Finding(
            id="F001",
            category="LLM01",
            severity=Severity.LOW,
            confidence=0.5,
            title="Test",
        )
        result = str(finding)
        assert "N/A" in result


class TestRiskLevel:
    """Test _get_risk_level function."""

    def test_excellent(self):
        assert _get_risk_level(90) == "EXCELLENT"
        assert _get_risk_level(100) == "EXCELLENT"

    def test_good(self):
        assert _get_risk_level(75) == "GOOD"
        assert _get_risk_level(89) == "GOOD"

    def test_adequate(self):
        assert _get_risk_level(60) == "ADEQUATE"
        assert _get_risk_level(74) == "ADEQUATE"

    def test_needs_improvement(self):
        assert _get_risk_level(40) == "NEEDS_IMPROVEMENT"
        assert _get_risk_level(59) == "NEEDS_IMPROVEMENT"

    def test_poor(self):
        assert _get_risk_level(20) == "POOR"
        assert _get_risk_level(39) == "POOR"

    def test_critical(self):
        assert _get_risk_level(0) == "CRITICAL"
        assert _get_risk_level(19) == "CRITICAL"


class TestConfidenceLevel:
    """Test _get_confidence_level function."""

    def test_very_high(self):
        assert _get_confidence_level(0.9) == "VERY_HIGH"
        assert _get_confidence_level(1.0) == "VERY_HIGH"

    def test_high(self):
        assert _get_confidence_level(0.75) == "HIGH"
        assert _get_confidence_level(0.89) == "HIGH"

    def test_medium(self):
        assert _get_confidence_level(0.5) == "MEDIUM"
        assert _get_confidence_level(0.74) == "MEDIUM"

    def test_low(self):
        assert _get_confidence_level(0.0) == "LOW"
        assert _get_confidence_level(0.49) == "LOW"


class TestCategoryScore:
    """Test CategoryScore dataclass."""

    def test_basic_creation(self):
        """Test basic category score creation."""
        score = CategoryScore(
            category_id="prompt_security",
            category_name="Prompt Security",
            score=85,
            confidence=0.9,
        )
        assert score.category_id == "prompt_security"
        assert score.category_name == "Prompt Security"
        assert score.score == 85
        assert score.confidence == 0.9

    def test_with_details(self):
        """Test category score with all details."""
        score = CategoryScore(
            category_id="model_security",
            category_name="Model Security",
            score=70,
            confidence=0.8,
            subscores={"input_validation": 80, "output_filtering": 60},
            detected_controls=["rate_limiting", "input_sanitization"],
            gaps=["No output encoding"],
            evidence={"files_analyzed": 10},
        )
        assert score.subscores == {"input_validation": 80, "output_filtering": 60}
        assert len(score.detected_controls) == 2
        assert "No output encoding" in score.gaps

    def test_to_dict(self):
        """Test to_dict conversion."""
        score = CategoryScore(
            category_id="test",
            category_name="Test Category",
            score=75,
            confidence=0.85,
            subscores={"sub1": 80},
            detected_controls=["control1"],
            gaps=["gap1"],
            evidence={"key": "value"},
        )
        result = score.to_dict()
        assert result["category_id"] == "test"
        assert result["category_name"] == "Test Category"
        assert result["score"] == 75
        assert result["confidence"] == 0.85
        assert result["subscores"] == {"sub1": 80}
        assert result["detected_controls"] == ["control1"]
        assert result["gaps"] == ["gap1"]
        assert result["evidence"] == {"key": "value"}


class TestScanResult:
    """Test ScanResult dataclass."""

    def test_default_creation(self):
        """Test default scan result creation."""
        result = ScanResult()
        assert result.scan_type == "static"
        assert result.target_path == ""
        assert result.findings == []
        assert result.category_scores == {}
        assert result.overall_score == 100.0
        assert result.files_scanned == 0

    def test_with_findings(self):
        """Test scan result with findings."""
        findings = [
            Finding(
                id="1",
                category="LLM01",
                severity=Severity.HIGH,
                confidence=0.9,
                title="Finding 1",
            ),
            Finding(
                id="2",
                category="LLM02",
                severity=Severity.MEDIUM,
                confidence=0.7,
                title="Finding 2",
            ),
        ]
        result = ScanResult(
            target_path="/path/to/project",
            findings=findings,
            files_scanned=10,
        )
        assert len(result.findings) == 2
        assert result.files_scanned == 10

    def test_risk_level_property(self):
        """Test risk_level property."""
        excellent = ScanResult(overall_score=95)
        assert excellent.risk_level == "EXCELLENT"

        poor = ScanResult(overall_score=25)
        assert poor.risk_level == "POOR"

    def test_findings_by_severity(self):
        """Test findings_by_severity property."""
        findings = [
            Finding(id="1", category="LLM01", severity=Severity.CRITICAL, confidence=0.9, title="F1"),
            Finding(id="2", category="LLM01", severity=Severity.HIGH, confidence=0.8, title="F2"),
            Finding(id="3", category="LLM01", severity=Severity.HIGH, confidence=0.7, title="F3"),
            Finding(id="4", category="LLM01", severity=Severity.MEDIUM, confidence=0.6, title="F4"),
        ]
        result = ScanResult(findings=findings)
        counts = result.findings_by_severity
        assert counts["CRITICAL"] == 1
        assert counts["HIGH"] == 2
        assert counts["MEDIUM"] == 1
        assert counts["LOW"] == 0
        assert counts["INFO"] == 0

    def test_to_dict(self):
        """Test to_dict conversion."""
        finding = Finding(
            id="1",
            category="LLM01",
            severity=Severity.HIGH,
            confidence=0.85,
            title="Test finding",
        )
        category_score = CategoryScore(
            category_id="prompt",
            category_name="Prompt Security",
            score=80,
            confidence=0.9,
        )
        result = ScanResult(
            target_path="/project",
            findings=[finding],
            category_scores={"prompt": category_score},
            overall_score=80.0,
            confidence=0.85,
            files_scanned=5,
            duration_seconds=1.5,
            metadata={"version": "1.0"},
        )
        data = result.to_dict()

        assert data["scan_type"] == "static"
        assert data["target_path"] == "/project"
        assert len(data["findings"]) == 1
        assert data["findings"][0]["id"] == "1"
        assert "prompt" in data["category_scores"]
        assert data["overall_score"] == 80.0
        assert data["confidence"] == 0.85
        assert data["risk_level"] == "GOOD"
        assert data["files_scanned"] == 5
        assert data["duration_seconds"] == 1.5
        assert data["findings_by_severity"]["HIGH"] == 1
        assert data["metadata"] == {"version": "1.0"}

    def test_timestamp_in_to_dict(self):
        """Test that timestamp is properly serialized."""
        result = ScanResult()
        data = result.to_dict()
        assert "timestamp" in data
        # Should be ISO format string
        datetime.fromisoformat(data["timestamp"])
