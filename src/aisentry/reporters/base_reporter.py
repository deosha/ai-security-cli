"""Base reporter for security scan results"""

from abc import ABC, abstractmethod
from pathlib import Path
from typing import Union

from aisentry.models.result import ScanResult, TestResult, UnifiedResult


class BaseReporter(ABC):
    """
    Abstract base class for security report generation.

    Supports both static scan results and live test results.
    """

    def __init__(self, verbose: bool = False):
        self.verbose = verbose

    @abstractmethod
    def generate_scan_report(self, result: ScanResult) -> str:
        """
        Generate report for static code scan results.

        Args:
            result: ScanResult from static scanner

        Returns:
            Formatted report string
        """
        raise NotImplementedError

    @abstractmethod
    def generate_test_report(self, result: TestResult) -> str:
        """
        Generate report for live model test results.

        Args:
            result: TestResult from live tester

        Returns:
            Formatted report string
        """
        raise NotImplementedError

    @abstractmethod
    def generate_unified_report(self, result: UnifiedResult) -> str:
        """
        Generate combined report for both static and live results.

        Args:
            result: UnifiedResult combining both types

        Returns:
            Formatted report string
        """
        raise NotImplementedError

    def generate_report(
        self,
        result: Union[ScanResult, TestResult, UnifiedResult]
    ) -> str:
        """
        Generate appropriate report based on result type.

        Args:
            result: Any supported result type

        Returns:
            Formatted report string
        """
        if isinstance(result, UnifiedResult):
            return self.generate_unified_report(result)
        elif isinstance(result, ScanResult):
            return self.generate_scan_report(result)
        elif isinstance(result, TestResult):
            return self.generate_test_report(result)
        else:
            raise TypeError(f"Unsupported result type: {type(result)}")

    def save_report(
        self,
        result: Union[ScanResult, TestResult, UnifiedResult],
        output_path: str,
    ) -> str:
        """
        Generate and save report to file.

        Args:
            result: Result to generate report for
            output_path: Path to save the report

        Returns:
            Path to the saved report
        """
        report = self.generate_report(result)
        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(report, encoding="utf-8")
        return str(path)
