"""
Evaluation Framework for AISentry Detectors.

Provides tools for:
- Running detectors against benchmark datasets
- Calculating precision, recall, F1, and security-specific metrics
- Comparing against baselines (pattern-only, Semgrep, Bandit)
- Generating evaluation reports for research papers

Usage:
    from aisentry.evaluation import BenchmarkRunner, SecurityMetrics

    runner = BenchmarkRunner(benchmark_dir='benchmarks/')
    results = runner.run_all_detectors()
    metrics = SecurityMetrics.calculate(results, ground_truth)
    metrics.to_latex()  # For paper tables
"""

from aisentry.evaluation.metrics import SecurityMetrics, MetricsReport
from aisentry.evaluation.benchmark_runner import BenchmarkRunner

__all__ = [
    "SecurityMetrics",
    "MetricsReport",
    "BenchmarkRunner",
]
