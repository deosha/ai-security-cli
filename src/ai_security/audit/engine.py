"""
Audit Engine - Main orchestrator for security audits.
"""

import time
import uuid
from pathlib import Path
from typing import Dict, List, Optional

from .analyzers import ASTAnalyzer, ConfigAnalyzer, DependencyAnalyzer
from .controls import (
    PromptSecurityControls,
    ModelSecurityControls,
    DataPrivacyControls,
    OWASPLLMControls,
    BlueTeamControls,
    GovernanceControls,
    SupplyChainControls,
    HallucinationControls,
    EthicalAIControls,
    IncidentResponseControls,
)
from .models import AuditResult, CategoryScore, ControlEvidence
from .scoring import MaturityScorer
from .reports import JSONAuditReporter, HTMLAuditReporter


class AuditEngine:
    """
    Main engine for running security audits.

    Coordinates analyzers, control detectors, scoring, and reporting.
    """

    def __init__(self, verbose: bool = False):
        """Initialize audit engine."""
        self.verbose = verbose
        self.ast_analyzer = ASTAnalyzer()
        self.config_analyzer = ConfigAnalyzer()
        self.dependency_analyzer = DependencyAnalyzer()
        self.scorer = MaturityScorer()

    def run(self, path: Path) -> AuditResult:
        """
        Run a complete security audit on the given path.

        Args:
            path: Path to audit (file or directory)

        Returns:
            Complete AuditResult
        """
        start_time = time.time()
        audit_id = str(uuid.uuid4())[:8]

        # Ensure path exists
        if not path.exists():
            raise ValueError(f"Path does not exist: {path}")

        # Determine target directory
        target_dir = path if path.is_dir() else path.parent

        if self.verbose:
            print(f"Starting audit of {target_dir}")

        # Run analyzers
        files_scanned = self._run_analyzers(target_dir)

        if self.verbose:
            print(f"Analyzed {files_scanned} files")

        # Run control detectors
        categories = self._run_detectors()

        if self.verbose:
            print(f"Evaluated {sum(len(c.controls) for c in categories.values())} controls")

        # Calculate scores and create result
        scan_duration = time.time() - start_time
        result = self.scorer.create_audit_result(
            audit_id=audit_id,
            project_path=str(target_dir),
            categories=categories,
            files_scanned=files_scanned,
            scan_duration=scan_duration,
        )

        return result

    def _run_analyzers(self, directory: Path) -> int:
        """Run all analyzers on the directory."""
        total_files = 0

        # AST analysis for Python files
        py_files = self.ast_analyzer.analyze_directory(directory)
        total_files += py_files

        # Config file analysis
        config_files = self.config_analyzer.analyze_directory(directory)
        total_files += config_files

        # Dependency analysis
        dep_files = self.dependency_analyzer.analyze_directory(directory)
        total_files += dep_files

        return total_files

    def _run_detectors(self) -> Dict[str, CategoryScore]:
        """Run all control detectors."""
        categories = {}

        # Initialize control categories
        control_categories = [
            PromptSecurityControls(
                self.ast_analyzer, self.config_analyzer, self.dependency_analyzer
            ),
            ModelSecurityControls(
                self.ast_analyzer, self.config_analyzer, self.dependency_analyzer
            ),
            DataPrivacyControls(
                self.ast_analyzer, self.config_analyzer, self.dependency_analyzer
            ),
            OWASPLLMControls(
                self.ast_analyzer, self.config_analyzer, self.dependency_analyzer
            ),
            BlueTeamControls(
                self.ast_analyzer, self.config_analyzer, self.dependency_analyzer
            ),
            GovernanceControls(
                self.ast_analyzer, self.config_analyzer, self.dependency_analyzer
            ),
            SupplyChainControls(
                self.ast_analyzer, self.config_analyzer, self.dependency_analyzer
            ),
            HallucinationControls(
                self.ast_analyzer, self.config_analyzer, self.dependency_analyzer
            ),
            EthicalAIControls(
                self.ast_analyzer, self.config_analyzer, self.dependency_analyzer
            ),
            IncidentResponseControls(
                self.ast_analyzer, self.config_analyzer, self.dependency_analyzer
            ),
        ]

        # Run detectors for each category
        for category in control_categories:
            controls = category.detect_all()
            cat_score = self.scorer.score_category(
                category_id=category.category_id,
                category_name=category.category_name,
                controls=controls,
            )
            categories[category.category_id] = cat_score

        return categories

    def generate_report(
        self,
        result: AuditResult,
        format: str = "html",
        output_path: Optional[Path] = None,
    ) -> str:
        """
        Generate report from audit result.

        Args:
            result: Audit result to report
            format: Output format (html, json)
            output_path: Optional path to save report

        Returns:
            Report content as string
        """
        if format == "json":
            reporter = JSONAuditReporter()
        else:
            reporter = HTMLAuditReporter()

        content = reporter.generate(result)

        if output_path:
            output_path.write_text(content)

        return content

    def print_summary(self, result: AuditResult) -> None:
        """Print audit summary to console."""
        print()
        print("=" * 60)
        print("AI SECURITY AUDIT REPORT")
        print("=" * 60)
        print()
        print(f"Project: {result.project_path}")
        print(f"Audit ID: {result.audit_id}")
        print(f"Date: {result.timestamp.strftime('%Y-%m-%d %H:%M:%S')}")
        print()
        print("-" * 60)
        print("OVERALL SCORE")
        print("-" * 60)
        print(f"Score: {result.overall_score:.0f}/100")
        print(f"Maturity Level: {result.maturity_level.value}")
        print(f"Controls Detected: {result.detected_controls_count}/{result.total_controls_count}")
        print()
        print("-" * 60)
        print("CATEGORY SCORES")
        print("-" * 60)

        for cat_id, cat_score in result.categories.items():
            bar_len = int(cat_score.percentage / 5)
            bar = "█" * bar_len + "░" * (20 - bar_len)
            print(f"{cat_score.category_name:25} [{bar}] {cat_score.score:.0f}/100")

        print()

        if result.recommendations:
            print("-" * 60)
            print("TOP RECOMMENDATIONS")
            print("-" * 60)
            for i, rec in enumerate(result.recommendations[:5], 1):
                print(f"{i}. [{rec.priority.upper()}] {rec.title}")
                print(f"   {rec.remediation}")
                print()

        print("-" * 60)
        print(f"Files Scanned: {result.files_scanned}")
        print(f"Scan Duration: {result.scan_duration_seconds:.2f}s")
        print("=" * 60)
