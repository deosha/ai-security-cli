"""
Static Code Scanner - Orchestrates parsing, detection, and scoring

Supports configurable deduplication, per-category thresholds, and directory exclusions.
"""

import os
import re
import time
import shutil
import logging
import tempfile
import subprocess
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple
from urllib.parse import urlparse
from collections import defaultdict

from ai_security.parsers.python.ast_parser import PythonASTParser
from ai_security.static_detectors import (
    PromptInjectionDetector,
    InsecureOutputDetector,
    TrainingPoisoningDetector,
    ModelDOSDetector,
    SupplyChainDetector,
    SecretsDetector,
    InsecurePluginDetector,
    ExcessiveAgencyDetector,
    OverrelianceDetector,
    ModelTheftDetector,
)
from ai_security.scorers.prompt_security_scorer import PromptSecurityScorer
from ai_security.scorers.model_security_scorer import ModelSecurityScorer
from ai_security.scorers.data_privacy_scorer import DataPrivacyScorer
from ai_security.scorers.hallucination_scorer import HallucinationScorer
from ai_security.scorers.ethical_ai_scorer import EthicalAIScorer
from ai_security.scorers.governance_scorer import GovernanceScorer
from ai_security.scorers.owasp_scorer import OWASPScorer
from ai_security.models.finding import Finding, Severity
from ai_security.models.result import ScanResult, CategoryScore
from ai_security.utils.scoring import calculate_overall_score, get_severity_counts
from ai_security.config import ScanConfig, load_config

logger = logging.getLogger(__name__)


# Patterns for detecting remote Git URLs
GIT_URL_PATTERNS = [
    r'^https?://github\.com/[\w\-\.]+/[\w\-\.]+',
    r'^https?://gitlab\.com/[\w\-\.]+/[\w\-\.]+',
    r'^https?://bitbucket\.org/[\w\-\.]+/[\w\-\.]+',
    r'^git@github\.com:[\w\-\.]+/[\w\-\.]+',
    r'^git@gitlab\.com:[\w\-\.]+/[\w\-\.]+',
    r'^git@bitbucket\.org:[\w\-\.]+/[\w\-\.]+',
    r'^https?://.*\.git$',
]


def is_remote_url(path: str) -> bool:
    """Check if a path is a remote Git URL."""
    for pattern in GIT_URL_PATTERNS:
        if re.match(pattern, path, re.IGNORECASE):
            return True
    return False


def normalize_git_url(url: str) -> str:
    """Normalize a Git URL to be clonable."""
    url = url.rstrip('/')

    if 'github.com' in url or 'gitlab.com' in url or 'bitbucket.org' in url:
        url = re.sub(r'/(tree|blob)/[^/]+.*$', '', url)
        if not url.endswith('.git'):
            url = url + '.git'

    return url


def clone_repository(url: str, depth: int = 1) -> Tuple[str, bool]:
    """Clone a remote Git repository to a temporary directory."""
    temp_dir = tempfile.mkdtemp(prefix="ai-security-scan-")

    try:
        normalized_url = normalize_git_url(url)
        logger.info(f"Cloning repository: {normalized_url}")

        result = subprocess.run(
            ["git", "clone", "--depth", str(depth), normalized_url, temp_dir],
            capture_output=True,
            text=True,
            timeout=300,
        )

        if result.returncode != 0:
            logger.error(f"Git clone failed: {result.stderr}")
            shutil.rmtree(temp_dir, ignore_errors=True)
            return "", False

        logger.info(f"Successfully cloned to: {temp_dir}")
        return temp_dir, True

    except subprocess.TimeoutExpired:
        logger.error("Git clone timed out")
        shutil.rmtree(temp_dir, ignore_errors=True)
        return "", False
    except FileNotFoundError:
        logger.error("Git is not installed or not in PATH")
        shutil.rmtree(temp_dir, ignore_errors=True)
        return "", False
    except Exception as e:
        logger.error(f"Error cloning repository: {e}")
        shutil.rmtree(temp_dir, ignore_errors=True)
        return "", False


class StaticScanner:
    """
    Static code scanner for OWASP LLM Top 10 vulnerabilities.

    Architecture:
    1. Parse: Extract code structure from files (AST)
    2. Detect: Find OWASP vulnerabilities (per-file findings)
    3. Score: Calculate framework security posture (aggregated)
    4. Report: Generate results matching schema

    Configuration:
    - Supports .ai-security.yaml config files
    - Per-category confidence thresholds
    - Configurable deduplication (exact, off)
    - Opt-in directory exclusions
    """

    # Minimal default skip dirs (only build artifacts, not test/docs)
    ALWAYS_SKIP_DIRS = {
        '__pycache__',
        '.git',
        '.svn',
        '.hg',
        'node_modules',
        'venv',
        '.venv',
        'env',
        '.env',
        '.tox',
        '.pytest_cache',
        '.mypy_cache',
        'htmlcov',
        'dist',
        'build',
    }

    def __init__(
        self,
        verbose: bool = False,
        confidence_threshold: float = 0.7,  # Recall-friendly default
        categories: Optional[List[str]] = None,
        config: Optional[ScanConfig] = None,
        exclude_dirs: Optional[List[str]] = None,
        dedup: str = 'exact',  # 'exact' or 'off'
    ):
        """
        Initialize scanner.

        Args:
            verbose: Enable verbose logging
            confidence_threshold: Global minimum confidence (0.0-1.0)
            categories: Filter to specific OWASP categories (e.g., ["LLM01", "LLM02"])
            config: ScanConfig object (overrides other settings)
            exclude_dirs: Additional directories to skip
            dedup: Deduplication mode ('exact' or 'off')
        """
        self.verbose = verbose
        self.filter_categories = categories

        # Use config if provided, otherwise use direct parameters
        if config:
            self.config = config
        else:
            self.config = ScanConfig(
                global_threshold=confidence_threshold,
                exclude_dirs=exclude_dirs or [],
                dedup=dedup,
            )

        # Build skip directories set
        self.skip_dirs = set(self.ALWAYS_SKIP_DIRS)
        if self.config.exclude_dirs:
            self.skip_dirs.update(self.config.exclude_dirs)

        # Initialize detectors with per-category thresholds
        self.detectors = self._init_detectors()

        # Filter detectors by category if specified
        if self.filter_categories:
            self.detectors = [
                d for d in self.detectors
                if d.detector_id in self.filter_categories
            ]

        # Initialize scorers
        self.scorers = [
            PromptSecurityScorer(verbose=verbose),
            ModelSecurityScorer(verbose=verbose),
            DataPrivacyScorer(verbose=verbose),
            HallucinationScorer(verbose=verbose),
            EthicalAIScorer(verbose=verbose),
            GovernanceScorer(verbose=verbose),
        ]

        self.owasp_scorer = OWASPScorer(verbose=verbose)

    def _init_detectors(self) -> List:
        """Initialize detectors with per-category thresholds from config."""
        detector_classes = [
            ('LLM01', PromptInjectionDetector),
            ('LLM02', InsecureOutputDetector),
            ('LLM03', TrainingPoisoningDetector),
            ('LLM04', ModelDOSDetector),
            ('LLM05', SupplyChainDetector),
            ('LLM06', SecretsDetector),
            ('LLM07', InsecurePluginDetector),
            ('LLM08', ExcessiveAgencyDetector),
            ('LLM09', OverrelianceDetector),
            ('LLM10', ModelTheftDetector),
        ]

        detectors = []
        for cat_id, detector_class in detector_classes:
            threshold = self.config.get_threshold(cat_id)
            detectors.append(
                detector_class(
                    verbose=self.verbose,
                    confidence_threshold=threshold
                )
            )

        return detectors

    def scan(self, path: str) -> ScanResult:
        """
        Scan a file, directory, or remote Git URL for security issues.

        Args:
            path: Path to file/directory or Git URL

        Returns:
            ScanResult with all findings and scores
        """
        if is_remote_url(path):
            return self._scan_remote(path)

        target_path = Path(path).resolve()

        if target_path.is_file():
            return self._scan_file(target_path)
        elif target_path.is_dir():
            return self._scan_directory(target_path)
        else:
            raise FileNotFoundError(f"Path not found: {path}")

    def _scan_remote(self, url: str) -> ScanResult:
        """Scan a remote Git repository."""
        logger.info(f"Scanning remote repository: {url}")

        temp_dir, success = clone_repository(url)

        if not success:
            raise RuntimeError(f"Failed to clone repository: {url}")

        try:
            result = self._scan_directory(Path(temp_dir))
            result.target_path = url
            result.metadata = result.metadata or {}
            result.metadata["source"] = "remote"
            result.metadata["cloned_to"] = temp_dir
            return result
        finally:
            logger.info(f"Cleaning up temporary directory: {temp_dir}")
            shutil.rmtree(temp_dir, ignore_errors=True)

    def _scan_file(self, file_path: Path) -> ScanResult:
        """Scan a single file."""
        start_time = time.time()

        if file_path.suffix != ".py":
            logger.warning(f"Skipping non-Python file: {file_path}")
            return ScanResult(
                target_path=str(file_path),
                files_scanned=0,
                duration_seconds=time.time() - start_time,
            )

        parser = PythonASTParser(str(file_path))
        parsed_data = parser.parse()

        if not parsed_data.get("parsable", False):
            logger.warning(f"Could not parse file: {file_path}")
            return ScanResult(
                target_path=str(file_path),
                files_scanned=1,
                duration_seconds=time.time() - start_time,
                metadata={"parse_error": True},
            )

        all_findings = []
        for detector in self.detectors:
            findings = detector.detect(parsed_data)
            all_findings.extend(findings)

        # Apply deduplication
        if self.config.dedup == 'exact':
            all_findings = self._deduplicate_exact(all_findings)

        category_scores = self._run_scorers(parsed_data, all_findings)

        overall_score = calculate_overall_score(
            findings=all_findings,
            category_scores=list(category_scores.values()),
        )

        duration = time.time() - start_time

        return ScanResult(
            target_path=str(file_path),
            findings=all_findings,
            category_scores=category_scores,
            overall_score=overall_score,
            confidence=self._calculate_scan_confidence(all_findings, category_scores),
            files_scanned=1,
            duration_seconds=duration,
        )

    def _should_skip_path(self, file_path: Path) -> bool:
        """Check if a file path should be skipped."""
        path_parts = file_path.parts

        for part in path_parts:
            if part in self.skip_dirs:
                return True
            if part.endswith('.egg-info'):
                return True

        # Skip test files if configured
        if self.config.exclude_tests and self._is_test_file(file_path):
            return True

        return False

    def _is_test_file(self, file_path: Path) -> bool:
        """Check if a file is a test file based on path/name patterns."""
        file_name = file_path.name.lower()

        # Test directory patterns - must be exact match or specific patterns
        test_dir_exact = {'test', 'tests', 'testing', 'spec', 'specs', 'unit_tests', 'integration_tests'}
        test_dir_prefixes = {'test_', 'tests_'}  # test_ directories but not 'testbed', 'testimony', etc.

        for part in file_path.parts:
            part_lower = part.lower()
            # Exact match
            if part_lower in test_dir_exact:
                return True
            # Prefix match (test_something but not testbed)
            for prefix in test_dir_prefixes:
                if part_lower.startswith(prefix):
                    return True

        # Test file name patterns
        if file_name.startswith('test_') or file_name.endswith('_test.py'):
            return True
        # test*.py but not testimony.py, testament.py, etc.
        if file_name.startswith('test_') and file_name.endswith('.py'):
            return True
        if 'conftest' in file_name:
            return True

        return False

    def _apply_test_demotion(self, findings: List[Finding]) -> List[Finding]:
        """Apply confidence penalty to findings in test files."""
        if not self.config.demote_tests:
            return findings

        demoted = []
        for finding in findings:
            if finding.file_path and self._is_test_file(Path(finding.file_path)):
                # Create new finding with reduced confidence
                new_confidence = max(0.0, finding.confidence - self.config.test_confidence_penalty)
                demoted_finding = Finding(
                    id=finding.id,
                    category=finding.category,
                    severity=finding.severity,
                    confidence=new_confidence,
                    title=finding.title,
                    description=finding.description,
                    file_path=finding.file_path,
                    line_number=finding.line_number,
                    code_snippet=finding.code_snippet,
                    recommendation=finding.recommendation,
                    evidence={**(finding.evidence or {}), 'test_file_demoted': True},
                )
                demoted.append(demoted_finding)
            else:
                demoted.append(finding)

        return demoted

    def _deduplicate_exact(self, findings: List[Finding]) -> List[Finding]:
        """
        Exact deduplication: merge findings with same key, don't drop.

        Key: (detector_id, file_path, line_number, sink_function, sink_type)

        Merge behavior:
        - Keep highest confidence
        - Keep highest severity
        - Union evidence dicts
        - Concatenate unique recommendations
        """
        # Group by dedup key
        grouped: Dict[tuple, List[Finding]] = defaultdict(list)

        for finding in findings:
            # Extract key components
            cat_id = finding.category.split(':')[0].strip() if finding.category else ''
            sink_func = finding.evidence.get('sink_function') if finding.evidence else None
            sink_type = finding.evidence.get('sink_type') if finding.evidence else None

            key = (cat_id, finding.file_path, finding.line_number, sink_func, sink_type)
            grouped[key].append(finding)

        # Merge each group
        merged_findings = []
        for key, group in grouped.items():
            if len(group) == 1:
                merged_findings.append(group[0])
            else:
                merged = self._merge_findings(group)
                merged_findings.append(merged)

        return merged_findings

    def _merge_findings(self, findings: List[Finding]) -> Finding:
        """Merge multiple findings into one, preserving best evidence."""
        if len(findings) == 1:
            return findings[0]

        # Sort by confidence (descending) to use best as base
        sorted_findings = sorted(findings, key=lambda f: f.confidence, reverse=True)
        base = sorted_findings[0]

        # Merge evidence from all findings
        merged_evidence = {}
        for f in findings:
            if f.evidence:
                for k, v in f.evidence.items():
                    if k not in merged_evidence:
                        merged_evidence[k] = v
                    elif isinstance(v, list) and isinstance(merged_evidence[k], list):
                        # Merge lists, dedupe
                        merged_evidence[k] = list(set(merged_evidence[k] + v))

        # Collect unique recommendations
        recommendations = []
        seen_recs = set()
        for f in findings:
            if f.recommendation and f.recommendation not in seen_recs:
                recommendations.append(f.recommendation)
                seen_recs.add(f.recommendation)

        # Find max severity
        severity_order = [Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]
        max_severity = max(findings, key=lambda f: severity_order.index(f.severity)).severity

        # Create merged finding
        return Finding(
            id=base.id,
            category=base.category,
            severity=max_severity,
            confidence=max(f.confidence for f in findings),
            title=base.title,
            description=base.description,
            file_path=base.file_path,
            line_number=base.line_number,
            code_snippet=base.code_snippet,
            recommendation='\n\n'.join(recommendations) if len(recommendations) > 1 else base.recommendation,
            evidence=merged_evidence,
        )

    def _scan_directory(self, directory: Path) -> ScanResult:
        """Scan all Python files in a directory."""
        start_time = time.time()

        python_files = list(directory.rglob("*.py"))

        if not python_files:
            logger.warning(f"No Python files found in {directory}")
            return ScanResult(
                target_path=str(directory),
                files_scanned=0,
                duration_seconds=time.time() - start_time,
            )

        all_parsed_data = []
        all_findings = []
        skipped_count = 0

        for file_path in python_files:
            if self._should_skip_path(file_path):
                skipped_count += 1
                continue

            try:
                parser = PythonASTParser(str(file_path))
                parsed_data = parser.parse()

                if parsed_data.get("parsable", False):
                    all_parsed_data.append(parsed_data)

                    for detector in self.detectors:
                        findings = detector.detect(parsed_data)
                        all_findings.extend(findings)

            except Exception as e:
                logger.warning(f"Error scanning {file_path}: {e}")

        # Apply deduplication
        if self.config.dedup == 'exact':
            all_findings = self._deduplicate_exact(all_findings)

        # Apply test file confidence demotion
        all_findings = self._apply_test_demotion(all_findings)

        # Filter by threshold after demotion
        all_findings = [f for f in all_findings if f.confidence >= self.config.global_threshold]

        if self.verbose and skipped_count > 0:
            logger.info(f"Skipped {skipped_count} files (excluded directories)")

        aggregated_data = self._aggregate_parsed_data(all_parsed_data)
        category_scores = self._run_scorers(aggregated_data, all_findings)

        overall_score = calculate_overall_score(
            findings=all_findings,
            category_scores=list(category_scores.values()),
        )

        duration = time.time() - start_time

        return ScanResult(
            target_path=str(directory),
            findings=all_findings,
            category_scores=category_scores,
            overall_score=overall_score,
            confidence=self._calculate_scan_confidence(all_findings, category_scores),
            files_scanned=len(all_parsed_data),
            duration_seconds=duration,
        )

    def _aggregate_parsed_data(self, parsed_data_list: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Aggregate parsed data from multiple files."""
        if not parsed_data_list:
            return {}

        aggregated = {
            "file_path": "project",
            "parsable": True,
            "imports": [],
            "functions": [],
            "classes": [],
            "assignments": [],
            "string_operations": [],
            "llm_api_calls": [],
            "source_lines": [],
        }

        for parsed_data in parsed_data_list:
            aggregated["imports"].extend(parsed_data.get("imports", []))
            aggregated["functions"].extend(parsed_data.get("functions", []))
            aggregated["classes"].extend(parsed_data.get("classes", []))
            aggregated["assignments"].extend(parsed_data.get("assignments", []))
            aggregated["string_operations"].extend(parsed_data.get("string_operations", []))
            aggregated["llm_api_calls"].extend(parsed_data.get("llm_api_calls", []))
            aggregated["source_lines"].extend(parsed_data.get("source_lines", []))

        return aggregated

    def _run_scorers(
        self, parsed_data: Dict[str, Any], findings: List[Finding]
    ) -> Dict[str, CategoryScore]:
        """Run all scorers and return category scores."""
        category_scores = {}

        for scorer in self.scorers:
            try:
                score = scorer.calculate_score(parsed_data)
                category_scores[score.category_id] = score
            except Exception as e:
                logger.warning(f"Scorer {scorer.__class__.__name__} failed: {e}")

        try:
            self.owasp_scorer.set_findings(findings)
            owasp_score = self.owasp_scorer.calculate_score(parsed_data)
            category_scores[owasp_score.category_id] = owasp_score
        except Exception as e:
            logger.warning(f"OWASP scorer failed: {e}")

        return category_scores

    def _calculate_scan_confidence(
        self, findings: List[Finding], category_scores: Dict[str, CategoryScore]
    ) -> float:
        """Calculate overall scan confidence."""
        if findings:
            finding_confidence = sum(f.confidence for f in findings) / len(findings)
        else:
            finding_confidence = 0.8

        if category_scores:
            scorer_confidence = sum(
                s.confidence for s in category_scores.values()
            ) / len(category_scores)
        else:
            scorer_confidence = 0.5

        return (finding_confidence * 0.4 + scorer_confidence * 0.6)
