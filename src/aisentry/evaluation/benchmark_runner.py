"""
Benchmark Runner for Detector Evaluation.

Runs AISentry detectors against benchmark datasets and compares results
against ground truth labels.

Usage:
    runner = BenchmarkRunner(benchmark_dir='benchmarks/')
    results = runner.run_evaluation(
        detectors=['pattern', 'ml', 'taint', 'ensemble'],
        categories=['prompt_injection', 'semantic_taint']
    )
"""

import json
import logging
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from aisentry.config import ScanConfig
from aisentry.core.scanner import StaticScanner
from aisentry.evaluation.metrics import GroundTruth, MetricsReport, SecurityMetrics
from aisentry.models.finding import Finding

logger = logging.getLogger(__name__)


@dataclass
class BenchmarkConfig:
    """Configuration for benchmark run."""
    # Detection modes to test
    use_pattern_detection: bool = True
    use_ml_detection: bool = False
    use_taint_analysis: bool = False
    use_ensemble: bool = True

    # Thresholds
    confidence_threshold: float = 0.5

    # Categories to evaluate
    categories: Optional[List[str]] = None


class BenchmarkRunner:
    """
    Run detectors against benchmark datasets.

    Expected benchmark directory structure:
        benchmarks/
        ├── prompt_injection/
        │   ├── vulnerable/
        │   │   ├── direct/
        │   │   │   ├── sample_001.py
        │   │   │   └── ...
        │   │   ├── indirect/
        │   │   └── stored/
        │   └── safe/
        │       └── safe_001.py
        ├── semantic_taint/
        │   ├── vulnerable/
        │   │   ├── llm_to_exec/
        │   │   ├── llm_to_sql/
        │   │   └── llm_to_command/
        │   └── safe/
        └── ground_truth.json
    """

    def __init__(self, benchmark_dir: str):
        """
        Initialize benchmark runner.

        Args:
            benchmark_dir: Path to benchmark directory
        """
        self.benchmark_dir = Path(benchmark_dir)
        self.ground_truth: List[GroundTruth] = []

        # Load ground truth if available
        gt_path = self.benchmark_dir / "ground_truth.json"
        if gt_path.exists():
            self._load_ground_truth(gt_path)

    def _load_ground_truth(self, path: Path) -> None:
        """Load ground truth labels from JSON file."""
        with open(path, 'r') as f:
            data = json.load(f)

        self.ground_truth = [GroundTruth.from_dict(item) for item in data.get('labels', [])]
        logger.info(f"Loaded {len(self.ground_truth)} ground truth labels")

    def run_evaluation(
        self,
        configs: Optional[Dict[str, BenchmarkConfig]] = None,
    ) -> Dict[str, MetricsReport]:
        """
        Run evaluation with multiple detector configurations.

        Args:
            configs: Dict mapping config name to BenchmarkConfig

        Returns:
            Dict mapping config name to MetricsReport
        """
        if configs is None:
            configs = self._get_default_configs()

        results = {}

        for name, config in configs.items():
            logger.info(f"Running evaluation: {name}")
            findings, scan_time, files = self._run_scan(config)
            metrics = SecurityMetrics.calculate(
                findings=findings,
                ground_truth=self.ground_truth,
                scan_time_seconds=scan_time,
                files_scanned=files,
            )
            results[name] = metrics
            logger.info(f"  F1: {metrics.f1_score:.3f}, Recall: {metrics.recall:.3f}")

        return results

    def _get_default_configs(self) -> Dict[str, BenchmarkConfig]:
        """Get default evaluation configurations."""
        return {
            'pattern_only': BenchmarkConfig(
                use_pattern_detection=True,
                use_ml_detection=False,
                use_taint_analysis=False,
            ),
            'ml_only': BenchmarkConfig(
                use_pattern_detection=False,
                use_ml_detection=True,
                use_taint_analysis=False,
            ),
            'taint_only': BenchmarkConfig(
                use_pattern_detection=False,
                use_ml_detection=False,
                use_taint_analysis=True,
            ),
            'ensemble': BenchmarkConfig(
                use_pattern_detection=True,
                use_ml_detection=True,
                use_taint_analysis=True,
                use_ensemble=True,
            ),
        }

    def _run_scan(self, config: BenchmarkConfig) -> Tuple[List[Finding], float, int]:
        """
        Run scanner with given configuration.

        Returns:
            Tuple of (findings, scan_time_seconds, files_scanned)
        """
        scan_config = ScanConfig(
            global_threshold=config.confidence_threshold,
            ml_detection=config.use_ml_detection,
            taint_analysis=config.use_taint_analysis,
            ensemble=config.use_ensemble,
        )

        scanner = StaticScanner(
            verbose=False,
            config=scan_config,
        )

        start_time = time.time()

        # Scan all Python files in benchmark directory
        all_findings = []
        files_scanned = 0

        for py_file in self.benchmark_dir.rglob("*.py"):
            try:
                result = scanner.scan(str(py_file))
                all_findings.extend(result.findings)
                files_scanned += result.files_scanned
            except Exception as e:
                logger.warning(f"Error scanning {py_file}: {e}")

        scan_time = time.time() - start_time

        return all_findings, scan_time, files_scanned

    def generate_ground_truth_template(self, output_path: Optional[str] = None) -> Dict[str, Any]:
        """
        Generate ground truth template from benchmark files.

        Scans benchmark directory and creates template JSON with file paths
        that need to be labeled.

        Args:
            output_path: Optional path to save template

        Returns:
            Ground truth template dictionary
        """
        template = {
            'description': 'Ground truth labels for AISentry benchmark evaluation',
            'labeling_instructions': (
                'For each file, set is_vulnerable to true/false. '
                'For vulnerable files, specify category (LLM01, TAINT01, etc.), '
                'severity (CRITICAL, HIGH, MEDIUM, LOW), and attack_vector if applicable.'
            ),
            'labels': []
        }

        for py_file in sorted(self.benchmark_dir.rglob("*.py")):
            rel_path = py_file.relative_to(self.benchmark_dir)
            path_parts = rel_path.parts

            # Infer vulnerability from directory structure
            is_vulnerable = 'vulnerable' in path_parts
            category = self._infer_category(path_parts)
            attack_vector = self._infer_attack_vector(path_parts)
            severity = 'HIGH' if is_vulnerable else 'INFO'

            template['labels'].append({
                'file_path': str(py_file),
                'line_number': 1,  # To be filled in
                'is_vulnerable': is_vulnerable,
                'category': category,
                'severity': severity,
                'attack_vector': attack_vector,
                'description': f'From {rel_path}',
            })

        if output_path:
            with open(output_path, 'w') as f:
                json.dump(template, f, indent=2)
            logger.info(f"Saved ground truth template to {output_path}")

        return template

    def _infer_category(self, path_parts: Tuple[str, ...]) -> str:
        """Infer vulnerability category from path."""
        if 'prompt_injection' in path_parts:
            return 'LLM01'
        elif 'semantic_taint' in path_parts:
            return 'TAINT01'
        elif 'insecure_output' in path_parts:
            return 'LLM02'
        return 'unknown'

    def _infer_attack_vector(self, path_parts: Tuple[str, ...]) -> Optional[str]:
        """Infer attack vector from path."""
        for part in path_parts:
            if part in ('direct', 'indirect', 'stored'):
                return part
        return None

    def create_comparison_report(
        self,
        results: Dict[str, MetricsReport],
        output_path: Optional[str] = None
    ) -> str:
        """
        Create detailed comparison report.

        Args:
            results: Dict mapping method name to MetricsReport
            output_path: Optional path to save report

        Returns:
            Markdown report string
        """
        report = [
            "# AISentry Detector Evaluation Report\n",
            "## Summary Comparison\n",
            SecurityMetrics.compare_methods(results, baseline_name='pattern_only'),
            "\n## Detailed Results\n",
        ]

        for name, metrics in results.items():
            report.append(f"\n### {name}\n")
            report.append(metrics.to_markdown())

        report_str = "\n".join(report)

        if output_path:
            with open(output_path, 'w') as f:
                f.write(report_str)
            logger.info(f"Saved comparison report to {output_path}")

        return report_str


def create_sample_benchmarks(output_dir: str) -> None:
    """
    Create sample benchmark files for testing.

    Args:
        output_dir: Directory to create benchmarks in
    """
    from aisentry.ml.training import SyntheticDataGenerator

    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)

    generator = SyntheticDataGenerator(seed=42)

    # Create directory structure
    categories = [
        ('prompt_injection/vulnerable/direct', 'direct'),
        ('prompt_injection/vulnerable/indirect', 'indirect'),
        ('prompt_injection/vulnerable/stored', 'stored'),
        ('prompt_injection/safe', 'safe'),
    ]

    ground_truth = []

    for subdir, vuln_type in categories:
        dir_path = output_path / subdir
        dir_path.mkdir(parents=True, exist_ok=True)

        # Generate samples
        if vuln_type == 'safe':
            for i in range(10):
                sample = generator._generate_safe_sample()
                file_path = dir_path / f"safe_{i:03d}.py"
                file_path.write_text(sample.code)
                ground_truth.append({
                    'file_path': str(file_path),
                    'line_number': 1,
                    'is_vulnerable': False,
                    'category': 'none',
                    'severity': 'INFO',
                })
        else:
            from aisentry.ml.training import VulnerabilityLabel
            label_map = {
                'direct': VulnerabilityLabel.DIRECT,
                'indirect': VulnerabilityLabel.INDIRECT,
                'stored': VulnerabilityLabel.STORED,
            }
            for i in range(10):
                sample = generator._generate_vulnerable_sample(label_map[vuln_type], has_mitigation=False)
                file_path = dir_path / f"{vuln_type}_{i:03d}.py"
                file_path.write_text(sample.code)
                ground_truth.append({
                    'file_path': str(file_path),
                    'line_number': 5,  # Approximate
                    'is_vulnerable': True,
                    'category': 'LLM01',
                    'severity': 'HIGH',
                    'attack_vector': vuln_type,
                })

    # Save ground truth
    gt_path = output_path / "ground_truth.json"
    with open(gt_path, 'w') as f:
        json.dump({'labels': ground_truth}, f, indent=2)

    logger.info(f"Created sample benchmarks in {output_dir}")
    logger.info(f"  - {len(ground_truth)} samples total")
    logger.info(f"  - Ground truth saved to {gt_path}")
