"""
Unit tests for aisentry audit module.
"""

import tempfile
from pathlib import Path

import pytest

from aisentry.audit.engine import AuditEngine
from aisentry.audit.models import (
    AuditResult, CategoryScore, ControlEvidence, ControlLevel,
    EvidenceItem, EvidenceType, MaturityLevel, Recommendation
)
from aisentry.audit.analyzers.ast_analyzer import ASTAnalyzer
from aisentry.audit.analyzers.config_analyzer import ConfigAnalyzer
from aisentry.audit.analyzers.dependency_analyzer import DependencyAnalyzer


class TestMaturityLevel:
    """Test MaturityLevel enum."""

    def test_maturity_levels(self):
        """Test maturity level values."""
        assert MaturityLevel.INITIAL.value == "Initial"
        assert MaturityLevel.DEVELOPING.value == "Developing"
        assert MaturityLevel.DEFINED.value == "Defined"
        assert MaturityLevel.MANAGED.value == "Managed"
        assert MaturityLevel.OPTIMIZING.value == "Optimizing"

    def test_maturity_from_score_initial(self):
        """Test maturity level from low score."""
        assert MaturityLevel.from_score(10) == MaturityLevel.INITIAL
        assert MaturityLevel.from_score(20) == MaturityLevel.INITIAL

    def test_maturity_from_score_developing(self):
        """Test maturity level from developing score."""
        assert MaturityLevel.from_score(30) == MaturityLevel.DEVELOPING
        assert MaturityLevel.from_score(40) == MaturityLevel.DEVELOPING

    def test_maturity_from_score_defined(self):
        """Test maturity level from defined score."""
        assert MaturityLevel.from_score(50) == MaturityLevel.DEFINED
        assert MaturityLevel.from_score(60) == MaturityLevel.DEFINED

    def test_maturity_from_score_managed(self):
        """Test maturity level from managed score."""
        assert MaturityLevel.from_score(70) == MaturityLevel.MANAGED
        assert MaturityLevel.from_score(80) == MaturityLevel.MANAGED

    def test_maturity_from_score_optimizing(self):
        """Test maturity level from high score."""
        assert MaturityLevel.from_score(90) == MaturityLevel.OPTIMIZING
        assert MaturityLevel.from_score(100) == MaturityLevel.OPTIMIZING


class TestControlLevel:
    """Test ControlLevel enum."""

    def test_control_levels(self):
        """Test control level values."""
        assert ControlLevel.NONE.value == "none"
        assert ControlLevel.BASIC.value == "basic"
        assert ControlLevel.COMPREHENSIVE.value == "comprehensive"

    def test_control_to_score(self):
        """Test control level to score conversion."""
        assert ControlLevel.NONE.to_score() == 0
        assert ControlLevel.BASIC.to_score() == 25
        assert ControlLevel.INTERMEDIATE.to_score() == 50
        assert ControlLevel.ADVANCED.to_score() == 75
        assert ControlLevel.COMPREHENSIVE.to_score() == 100


class TestEvidenceItem:
    """Test EvidenceItem dataclass."""

    def test_evidence_item_creation(self):
        """Test evidence item creation."""
        item = EvidenceItem(
            type=EvidenceType.AST,
            file_path="app.py",
            description="Found rate limiting decorator",
            line_number=42,
            snippet="@rate_limit(100)",
            confidence=0.9,
        )
        assert item.type == EvidenceType.AST
        assert item.file_path == "app.py"
        assert item.line_number == 42

    def test_evidence_item_to_dict(self):
        """Test evidence item to_dict."""
        item = EvidenceItem(
            type=EvidenceType.CONFIG,
            file_path="config.yaml",
            description="Found security config",
        )
        data = item.to_dict()
        assert data["type"] == "config"
        assert data["file_path"] == "config.yaml"


class TestControlEvidence:
    """Test ControlEvidence dataclass."""

    def test_control_evidence_creation(self):
        """Test control evidence creation."""
        evidence = ControlEvidence(
            control_id="CTRL-001",
            control_name="Rate Limiting",
            category="dos_protection",
            detected=True,
            level=ControlLevel.ADVANCED,
            confidence=0.85,
        )
        assert evidence.control_id == "CTRL-001"
        assert evidence.detected is True
        assert evidence.score == 75  # ADVANCED = 75

    def test_control_evidence_to_dict(self):
        """Test control evidence to_dict."""
        evidence = ControlEvidence(
            control_id="CTRL-002",
            control_name="Input Validation",
            category="input_security",
            detected=False,
            level=ControlLevel.NONE,
            confidence=0.5,
            recommendations=["Add input validation"],
        )
        data = evidence.to_dict()
        assert data["control_id"] == "CTRL-002"
        assert data["detected"] is False
        assert data["score"] == 0


class TestCategoryScore:
    """Test CategoryScore dataclass."""

    def test_category_score_creation(self):
        """Test category score creation."""
        category = CategoryScore(
            category_id="prompt_security",
            category_name="Prompt Security",
            score=75,
        )
        assert category.category_id == "prompt_security"
        assert category.score == 75

    def test_category_percentage(self):
        """Test category percentage calculation."""
        category = CategoryScore(
            category_id="test",
            category_name="Test",
            score=80,
            max_score=100,
        )
        assert category.percentage == 80.0

    def test_category_detected_count(self):
        """Test detected count property."""
        controls = [
            ControlEvidence("C1", "Control 1", "cat", True, ControlLevel.BASIC, 0.9),
            ControlEvidence("C2", "Control 2", "cat", False, ControlLevel.NONE, 0.5),
            ControlEvidence("C3", "Control 3", "cat", True, ControlLevel.ADVANCED, 0.8),
        ]
        category = CategoryScore(
            category_id="test",
            category_name="Test",
            score=50,
            controls=controls,
        )
        assert category.detected_count == 2
        assert category.total_count == 3

    def test_category_to_dict(self):
        """Test category to_dict."""
        category = CategoryScore(
            category_id="test",
            category_name="Test Category",
            score=65,
        )
        data = category.to_dict()
        assert data["category_id"] == "test"
        assert data["score"] == 65


class TestRecommendation:
    """Test Recommendation dataclass."""

    def test_recommendation_creation(self):
        """Test recommendation creation."""
        rec = Recommendation(
            priority="high",
            category="prompt_security",
            control_id="CTRL-001",
            title="Implement input validation",
            description="User input should be validated",
            remediation="Add input sanitization",
            docs_url="https://docs.example.com/security",
        )
        assert rec.priority == "high"
        assert rec.title == "Implement input validation"

    def test_recommendation_to_dict(self):
        """Test recommendation to_dict."""
        rec = Recommendation(
            priority="critical",
            category="output_security",
            control_id="CTRL-002",
            title="Add output encoding",
            description="Encode LLM output",
            remediation="Use html.escape()",
        )
        data = rec.to_dict()
        assert data["priority"] == "critical"
        assert data["control_id"] == "CTRL-002"


class TestASTAnalyzer:
    """Test ASTAnalyzer class."""

    @pytest.fixture
    def analyzer(self):
        return ASTAnalyzer()

    def test_analyzer_initialization(self, analyzer):
        """Test analyzer initialization."""
        assert analyzer is not None
        assert analyzer is not None

    def test_analyze_empty_directory(self, analyzer):
        """Test analyzing empty directory."""
        with tempfile.TemporaryDirectory() as tmpdir:
            count = analyzer.analyze_directory(Path(tmpdir))
            assert count == 0

    def test_analyze_directory_with_python(self, analyzer):
        """Test analyzing directory with Python files."""
        with tempfile.TemporaryDirectory() as tmpdir:
            (Path(tmpdir) / "test.py").write_text("def foo(): pass")
            count = analyzer.analyze_directory(Path(tmpdir))
            assert count == 1

    def test_analyze_nested_directory(self, analyzer):
        """Test analyzing nested directories."""
        with tempfile.TemporaryDirectory() as tmpdir:
            subdir = Path(tmpdir) / "src"
            subdir.mkdir()
            (subdir / "module.py").write_text("class Foo: pass")
            count = analyzer.analyze_directory(Path(tmpdir))
            assert count == 1


class TestConfigAnalyzer:
    """Test ConfigAnalyzer class."""

    @pytest.fixture
    def analyzer(self):
        return ConfigAnalyzer()

    def test_analyzer_initialization(self, analyzer):
        """Test analyzer initialization."""
        assert analyzer is not None

    def test_analyze_empty_directory(self, analyzer):
        """Test analyzing empty directory."""
        with tempfile.TemporaryDirectory() as tmpdir:
            count = analyzer.analyze_directory(Path(tmpdir))
            assert count == 0

    def test_analyze_yaml_config(self, analyzer):
        """Test analyzing YAML config files."""
        with tempfile.TemporaryDirectory() as tmpdir:
            (Path(tmpdir) / "config.yaml").write_text("setting: value")
            count = analyzer.analyze_directory(Path(tmpdir))
            assert count >= 1


class TestDependencyAnalyzer:
    """Test DependencyAnalyzer class."""

    @pytest.fixture
    def analyzer(self):
        return DependencyAnalyzer()

    def test_analyzer_initialization(self, analyzer):
        """Test analyzer initialization."""
        assert analyzer is not None

    def test_analyze_empty_directory(self, analyzer):
        """Test analyzing empty directory."""
        with tempfile.TemporaryDirectory() as tmpdir:
            count = analyzer.analyze_directory(Path(tmpdir))
            assert count == 0

    def test_analyze_requirements(self, analyzer):
        """Test analyzing requirements.txt."""
        with tempfile.TemporaryDirectory() as tmpdir:
            (Path(tmpdir) / "requirements.txt").write_text("flask>=2.0.0\nrequests==2.28.0")
            count = analyzer.analyze_directory(Path(tmpdir))
            assert count >= 1


class TestAuditEngine:
    """Test AuditEngine class."""

    @pytest.fixture
    def engine(self):
        return AuditEngine(verbose=False)

    def test_engine_initialization(self, engine):
        """Test engine initialization."""
        assert engine is not None
        assert hasattr(engine, 'ast_analyzer')
        assert hasattr(engine, 'config_analyzer')
        assert hasattr(engine, 'dependency_analyzer')

    def test_engine_verbose_mode(self):
        """Test engine verbose mode."""
        engine = AuditEngine(verbose=True)
        assert engine.verbose is True

    def test_run_on_nonexistent_path(self, engine):
        """Test running on nonexistent path."""
        with pytest.raises(ValueError):
            engine.run(Path("/nonexistent/path"))

    def test_run_on_empty_directory(self, engine):
        """Test running on empty directory."""
        with tempfile.TemporaryDirectory() as tmpdir:
            result = engine.run(Path(tmpdir))
            assert isinstance(result, AuditResult)
            assert result.files_scanned == 0

    def test_run_on_python_project(self, engine):
        """Test running on Python project."""
        with tempfile.TemporaryDirectory() as tmpdir:
            (Path(tmpdir) / "app.py").write_text('''
from openai import OpenAI
client = OpenAI()

def process(data):
    return client.chat.completions.create(
        model="gpt-4",
        messages=[{"role": "user", "content": data}]
    )
''')
            result = engine.run(Path(tmpdir))
            assert isinstance(result, AuditResult)
            assert result.files_scanned >= 1
            assert 0 <= result.overall_score <= 100

    def test_run_returns_categories(self, engine):
        """Test that run returns category scores."""
        with tempfile.TemporaryDirectory() as tmpdir:
            (Path(tmpdir) / "test.py").write_text("print('hello')")
            result = engine.run(Path(tmpdir))
            assert isinstance(result.categories, dict)

    def test_audit_result_has_audit_id(self, engine):
        """Test that result has audit ID."""
        with tempfile.TemporaryDirectory() as tmpdir:
            result = engine.run(Path(tmpdir))
            assert result.audit_id is not None
            assert len(result.audit_id) > 0
