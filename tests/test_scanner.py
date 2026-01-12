"""
Unit tests for aisentry scanner module.
"""

import tempfile
from pathlib import Path

import pytest

from aisentry.config import ScanConfig
from aisentry.core.scanner import (
    StaticScanner,
    is_remote_url,
    normalize_git_url,
)
from aisentry.models.finding import Finding, Severity


class TestIsRemoteUrl:
    """Test is_remote_url function."""

    def test_github_https(self):
        """Test GitHub HTTPS URL."""
        assert is_remote_url("https://github.com/owner/repo")
        assert is_remote_url("https://github.com/owner/repo.git")
        assert is_remote_url("https://github.com/owner/repo/tree/main")

    def test_github_ssh(self):
        """Test GitHub SSH URL."""
        assert is_remote_url("git@github.com:owner/repo.git")
        assert is_remote_url("git@github.com:owner/repo")

    def test_gitlab_https(self):
        """Test GitLab HTTPS URL."""
        assert is_remote_url("https://gitlab.com/owner/repo")
        assert is_remote_url("https://gitlab.com/owner/repo.git")

    def test_gitlab_ssh(self):
        """Test GitLab SSH URL."""
        assert is_remote_url("git@gitlab.com:owner/repo.git")

    def test_bitbucket_https(self):
        """Test Bitbucket HTTPS URL."""
        assert is_remote_url("https://bitbucket.org/owner/repo")
        assert is_remote_url("https://bitbucket.org/owner/repo.git")

    def test_bitbucket_ssh(self):
        """Test Bitbucket SSH URL."""
        assert is_remote_url("git@bitbucket.org:owner/repo.git")

    def test_generic_git_url(self):
        """Test generic .git URL."""
        assert is_remote_url("https://example.com/repo.git")

    def test_local_path_not_remote(self):
        """Test that local paths are not detected as remote."""
        assert not is_remote_url("/path/to/local/repo")
        assert not is_remote_url("./relative/path")
        assert not is_remote_url("../parent/path")
        assert not is_remote_url("path/to/repo")

    def test_case_insensitive(self):
        """Test URL matching is case insensitive."""
        assert is_remote_url("HTTPS://GITHUB.COM/owner/repo")


class TestNormalizeGitUrl:
    """Test normalize_git_url function."""

    def test_add_git_extension(self):
        """Test adding .git extension."""
        result = normalize_git_url("https://github.com/owner/repo")
        assert result == "https://github.com/owner/repo.git"

    def test_preserve_git_extension(self):
        """Test preserving existing .git extension."""
        result = normalize_git_url("https://github.com/owner/repo.git")
        assert result == "https://github.com/owner/repo.git"

    def test_remove_tree_branch(self):
        """Test removing /tree/branch path."""
        result = normalize_git_url("https://github.com/owner/repo/tree/main")
        assert result == "https://github.com/owner/repo.git"

    def test_remove_blob_path(self):
        """Test removing /blob/file path."""
        result = normalize_git_url("https://github.com/owner/repo/blob/main/file.py")
        assert result == "https://github.com/owner/repo.git"

    def test_strip_trailing_slash(self):
        """Test stripping trailing slash."""
        result = normalize_git_url("https://github.com/owner/repo/")
        assert result == "https://github.com/owner/repo.git"

    def test_gitlab_normalization(self):
        """Test GitLab URL normalization."""
        result = normalize_git_url("https://gitlab.com/owner/repo/tree/develop")
        assert result == "https://gitlab.com/owner/repo.git"


class TestStaticScannerInit:
    """Test StaticScanner initialization."""

    def test_default_initialization(self):
        """Test default scanner initialization."""
        scanner = StaticScanner()
        assert scanner.verbose is False
        assert scanner.filter_categories is None
        assert len(scanner.detectors) == 11  # 10 OWASP categories + SQL injection

    def test_verbose_mode(self):
        """Test verbose mode initialization."""
        scanner = StaticScanner(verbose=True)
        assert scanner.verbose is True

    def test_confidence_threshold(self):
        """Test custom confidence threshold."""
        scanner = StaticScanner(confidence_threshold=0.5)
        assert scanner.config.global_threshold == 0.5

    def test_category_filter(self):
        """Test category filtering."""
        scanner = StaticScanner(categories=["LLM01", "LLM02"])
        assert len(scanner.detectors) == 2
        detector_ids = [d.detector_id for d in scanner.detectors]
        assert "LLM01" in detector_ids
        assert "LLM02" in detector_ids

    def test_single_category_filter(self):
        """Test single category filtering."""
        scanner = StaticScanner(categories=["LLM01"])
        assert len(scanner.detectors) == 1
        assert scanner.detectors[0].detector_id == "LLM01"

    def test_exclude_dirs(self):
        """Test exclude directories."""
        scanner = StaticScanner(exclude_dirs=["custom_dir", "another_dir"])
        assert "custom_dir" in scanner.skip_dirs
        assert "another_dir" in scanner.skip_dirs
        # Default dirs should still be present
        assert "__pycache__" in scanner.skip_dirs
        assert ".git" in scanner.skip_dirs

    def test_dedup_mode(self):
        """Test deduplication mode."""
        scanner = StaticScanner(dedup='off')
        assert scanner.config.dedup == 'off'

        scanner = StaticScanner(dedup='exact')
        assert scanner.config.dedup == 'exact'

    def test_config_object(self):
        """Test initialization with ScanConfig object."""
        config = ScanConfig(
            mode='strict',
            global_threshold=0.8,
            exclude_dirs=['custom'],
            dedup='off',
        )
        scanner = StaticScanner(config=config)
        assert scanner.config.mode == 'strict'
        assert scanner.config.global_threshold == 0.8
        assert scanner.config.dedup == 'off'


class TestIsTestFile:
    """Test StaticScanner._is_test_file method."""

    @pytest.fixture
    def scanner(self):
        """Create scanner instance."""
        return StaticScanner()

    def test_test_prefix(self, scanner):
        """Test files with test_ prefix."""
        assert scanner._is_test_file(Path("test_module.py"))
        assert scanner._is_test_file(Path("src/test_utils.py"))

    def test_test_suffix(self, scanner):
        """Test files with _test.py suffix."""
        assert scanner._is_test_file(Path("module_test.py"))
        assert scanner._is_test_file(Path("src/utils_test.py"))

    def test_test_directory(self, scanner):
        """Test files in test directories."""
        assert scanner._is_test_file(Path("tests/module.py"))
        assert scanner._is_test_file(Path("test/module.py"))
        assert scanner._is_test_file(Path("src/tests/module.py"))

    def test_conftest(self, scanner):
        """Test conftest files."""
        assert scanner._is_test_file(Path("conftest.py"))
        assert scanner._is_test_file(Path("tests/conftest.py"))

    def test_regular_files(self, scanner):
        """Test regular files are not marked as test files."""
        assert not scanner._is_test_file(Path("module.py"))
        assert not scanner._is_test_file(Path("src/utils.py"))
        assert not scanner._is_test_file(Path("testimony.py"))  # Not a test file

    def test_testbed_not_test(self, scanner):
        """Test that testbed is not considered a test directory."""
        # 'testbed' should not match as it's not in exact match list
        assert not scanner._is_test_file(Path("testbed/vulnerable.py"))


class TestShouldSkipPath:
    """Test StaticScanner._should_skip_path method."""

    @pytest.fixture
    def scanner(self):
        """Create scanner instance."""
        return StaticScanner()

    def test_skip_pycache(self, scanner):
        """Test skipping __pycache__ directory."""
        assert scanner._should_skip_path(Path("src/__pycache__/module.pyc"))

    def test_skip_git(self, scanner):
        """Test skipping .git directory."""
        assert scanner._should_skip_path(Path(".git/config"))

    def test_skip_node_modules(self, scanner):
        """Test skipping node_modules directory."""
        assert scanner._should_skip_path(Path("node_modules/package/index.js"))

    def test_skip_venv(self, scanner):
        """Test skipping venv directory."""
        assert scanner._should_skip_path(Path("venv/lib/python3.9/site-packages/module.py"))
        assert scanner._should_skip_path(Path(".venv/lib/module.py"))

    def test_skip_egg_info(self, scanner):
        """Test skipping .egg-info directories."""
        assert scanner._should_skip_path(Path("package.egg-info/PKG-INFO"))

    def test_not_skip_regular_files(self, scanner):
        """Test not skipping regular files."""
        assert not scanner._should_skip_path(Path("src/module.py"))
        assert not scanner._should_skip_path(Path("app.py"))

    def test_skip_custom_dirs(self):
        """Test skipping custom directories."""
        scanner = StaticScanner(exclude_dirs=["custom_dir"])
        assert scanner._should_skip_path(Path("custom_dir/module.py"))

    def test_skip_tests_when_configured(self):
        """Test skipping test files when exclude_tests is enabled."""
        config = ScanConfig(exclude_tests=True)
        scanner = StaticScanner(config=config)
        assert scanner._should_skip_path(Path("tests/test_module.py"))

    def test_not_skip_tests_by_default(self):
        """Test not skipping test files by default."""
        scanner = StaticScanner()
        assert not scanner._should_skip_path(Path("tests/test_module.py"))


class TestDeduplication:
    """Test StaticScanner._deduplicate_exact method."""

    @pytest.fixture
    def scanner(self):
        """Create scanner instance."""
        return StaticScanner()

    def test_no_duplicates(self, scanner):
        """Test no deduplication when no duplicates."""
        findings = [
            Finding(
                id="1",
                category="LLM01: Prompt Injection",
                severity=Severity.HIGH,
                confidence=0.8,
                title="Finding 1",
                description="Description 1",
                file_path="file1.py",
                line_number=10,
            ),
            Finding(
                id="2",
                category="LLM01: Prompt Injection",
                severity=Severity.HIGH,
                confidence=0.7,
                title="Finding 2",
                description="Description 2",
                file_path="file2.py",
                line_number=20,
            ),
        ]
        result = scanner._deduplicate_exact(findings)
        assert len(result) == 2

    def test_merge_duplicates(self, scanner):
        """Test merging duplicate findings."""
        findings = [
            Finding(
                id="1",
                category="LLM01: Prompt Injection",
                severity=Severity.MEDIUM,
                confidence=0.6,
                title="Finding 1",
                description="Description 1",
                file_path="file.py",
                line_number=10,
                evidence={"sink_function": "execute"},
            ),
            Finding(
                id="2",
                category="LLM01: Prompt Injection",
                severity=Severity.HIGH,
                confidence=0.8,
                title="Finding 2",
                description="Description 2",
                file_path="file.py",
                line_number=10,
                evidence={"sink_function": "execute"},
            ),
        ]
        result = scanner._deduplicate_exact(findings)
        assert len(result) == 1
        # Should keep highest confidence
        assert result[0].confidence == 0.8

    def test_different_lines_not_merged(self, scanner):
        """Test that findings on different lines are not merged."""
        findings = [
            Finding(
                id="1",
                category="LLM01: Prompt Injection",
                severity=Severity.HIGH,
                confidence=0.8,
                title="Finding 1",
                description="Description 1",
                file_path="file.py",
                line_number=10,
            ),
            Finding(
                id="2",
                category="LLM01: Prompt Injection",
                severity=Severity.HIGH,
                confidence=0.7,
                title="Finding 2",
                description="Description 2",
                file_path="file.py",
                line_number=20,
            ),
        ]
        result = scanner._deduplicate_exact(findings)
        assert len(result) == 2


class TestScanFile:
    """Test StaticScanner file scanning."""

    @pytest.fixture
    def scanner(self):
        """Create scanner instance."""
        return StaticScanner()

    def test_scan_nonexistent_file(self, scanner):
        """Test scanning nonexistent file raises error."""
        with pytest.raises(FileNotFoundError):
            scanner.scan("/nonexistent/file.py")

    def test_scan_non_python_file(self, scanner):
        """Test scanning non-Python file."""
        with tempfile.NamedTemporaryFile(suffix=".txt", delete=False) as f:
            f.write(b"This is not Python code")
            f.flush()
            result = scanner.scan(f.name)
            assert result.files_scanned == 0

    def test_scan_empty_python_file(self, scanner):
        """Test scanning empty Python file."""
        with tempfile.NamedTemporaryFile(suffix=".py", delete=False) as f:
            f.write(b"")
            f.flush()
            result = scanner.scan(f.name)
            assert result.files_scanned == 1
            assert len(result.findings) == 0

    def test_scan_valid_python_file(self, scanner):
        """Test scanning valid Python file."""
        code = '''
def hello():
    print("Hello, World!")
'''
        with tempfile.NamedTemporaryFile(suffix=".py", delete=False, mode='w') as f:
            f.write(code)
            f.flush()
            result = scanner.scan(f.name)
            assert result.files_scanned == 1

    def test_scan_vulnerable_code(self):
        """Test scanning code with vulnerabilities."""
        code = '''
from openai import OpenAI

client = OpenAI()

def vulnerable_prompt(user_input):
    response = client.chat.completions.create(
        model="gpt-4",
        messages=[{"role": "user", "content": f"Process: {user_input}"}]
    )
    return response.choices[0].message.content
'''
        scanner = StaticScanner(categories=["LLM01"])
        with tempfile.NamedTemporaryFile(suffix=".py", delete=False, mode='w') as f:
            f.write(code)
            f.flush()
            result = scanner.scan(f.name)
            assert result.files_scanned == 1
            # Should find prompt injection vulnerability
            assert len(result.findings) > 0


class TestScanDirectory:
    """Test StaticScanner directory scanning."""

    @pytest.fixture
    def scanner(self):
        """Create scanner instance."""
        return StaticScanner()

    def test_scan_empty_directory(self, scanner):
        """Test scanning empty directory."""
        with tempfile.TemporaryDirectory() as tmpdir:
            result = scanner.scan(tmpdir)
            assert result.files_scanned == 0

    def test_scan_directory_with_files(self, scanner):
        """Test scanning directory with Python files."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create a Python file
            file1 = Path(tmpdir) / "module.py"
            file1.write_text('def hello(): pass')

            # Create another Python file
            file2 = Path(tmpdir) / "utils.py"
            file2.write_text('def helper(): pass')

            result = scanner.scan(tmpdir)
            assert result.files_scanned == 2

    def test_scan_skips_pycache(self, scanner):
        """Test scanning skips __pycache__ directory."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create pycache directory
            pycache = Path(tmpdir) / "__pycache__"
            pycache.mkdir()
            (pycache / "module.pyc").write_bytes(b"compiled")

            # Create regular file
            (Path(tmpdir) / "module.py").write_text('def hello(): pass')

            result = scanner.scan(tmpdir)
            assert result.files_scanned == 1

    def test_scan_nested_directories(self, scanner):
        """Test scanning nested directory structure."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create nested structure
            src = Path(tmpdir) / "src"
            src.mkdir()
            (src / "module.py").write_text('def hello(): pass')

            lib = src / "lib"
            lib.mkdir()
            (lib / "utils.py").write_text('def helper(): pass')

            result = scanner.scan(tmpdir)
            assert result.files_scanned == 2


class TestTestFileDemotion:
    """Test test file confidence demotion."""

    def test_demote_test_findings(self):
        """Test that test file findings are demoted."""
        config = ScanConfig(demote_tests=True, test_confidence_penalty=0.25)
        scanner = StaticScanner(config=config)

        findings = [
            Finding(
                id="1",
                category="LLM01: Prompt Injection",
                severity=Severity.HIGH,
                confidence=0.9,
                title="Finding",
                description="Description",
                file_path="tests/test_module.py",
                line_number=10,
            ),
        ]

        demoted = scanner._apply_test_demotion(findings)
        assert len(demoted) == 1
        assert demoted[0].confidence == 0.65  # 0.9 - 0.25

    def test_no_demotion_when_disabled(self):
        """Test no demotion when demote_tests is False."""
        config = ScanConfig(demote_tests=False)
        scanner = StaticScanner(config=config)

        findings = [
            Finding(
                id="1",
                category="LLM01: Prompt Injection",
                severity=Severity.HIGH,
                confidence=0.9,
                title="Finding",
                description="Description",
                file_path="tests/test_module.py",
                line_number=10,
            ),
        ]

        result = scanner._apply_test_demotion(findings)
        assert result[0].confidence == 0.9

    def test_demotion_floor_at_zero(self):
        """Test demotion doesn't go below zero."""
        config = ScanConfig(demote_tests=True, test_confidence_penalty=0.5)
        scanner = StaticScanner(config=config)

        findings = [
            Finding(
                id="1",
                category="LLM01: Prompt Injection",
                severity=Severity.HIGH,
                confidence=0.3,  # 0.3 - 0.5 would be negative
                title="Finding",
                description="Description",
                file_path="tests/test_module.py",
                line_number=10,
            ),
        ]

        demoted = scanner._apply_test_demotion(findings)
        assert demoted[0].confidence == 0.0  # Floored at 0

    def test_regular_files_not_demoted(self):
        """Test regular files are not demoted."""
        config = ScanConfig(demote_tests=True, test_confidence_penalty=0.25)
        scanner = StaticScanner(config=config)

        findings = [
            Finding(
                id="1",
                category="LLM01: Prompt Injection",
                severity=Severity.HIGH,
                confidence=0.9,
                title="Finding",
                description="Description",
                file_path="src/module.py",
                line_number=10,
            ),
        ]

        result = scanner._apply_test_demotion(findings)
        assert result[0].confidence == 0.9
