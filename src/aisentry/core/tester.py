"""
Live Model Tester - Orchestrates live LLM security testing
"""

import logging
import time
from typing import Dict, List, Optional, Type

from aisentry.live_detectors.adversarial_inputs import AdversarialInputsDetector
from aisentry.live_detectors.base_live_detector import BaseLiveDetector
from aisentry.live_detectors.behavioral_anomaly import BehavioralAnomalyDetector
from aisentry.live_detectors.bias import BiasDetector
from aisentry.live_detectors.data_leakage import DataLeakageDetector
from aisentry.live_detectors.dos import DosDetector
from aisentry.live_detectors.hallucination import HallucinationDetector
from aisentry.live_detectors.jailbreak import JailbreakDetector
from aisentry.live_detectors.model_extraction import ModelExtractionDetector
from aisentry.live_detectors.output_manipulation import OutputManipulationDetector
from aisentry.live_detectors.prompt_injection import PromptInjectionDetector
from aisentry.live_detectors.supply_chain import SupplyChainDetector
from aisentry.models.result import TestResult
from aisentry.models.vulnerability import LiveTestResult, LiveVulnerability
from aisentry.providers.base_provider import BaseProvider

logger = logging.getLogger(__name__)


# Registry of all available live detectors
DETECTOR_REGISTRY: Dict[str, Type[BaseLiveDetector]] = {
    "prompt-injection": PromptInjectionDetector,
    "jailbreak": JailbreakDetector,
    "data-leakage": DataLeakageDetector,
    "hallucination": HallucinationDetector,
    "dos": DosDetector,
    "bias": BiasDetector,
    "model-extraction": ModelExtractionDetector,
    "adversarial-inputs": AdversarialInputsDetector,
    "output-manipulation": OutputManipulationDetector,
    "supply-chain": SupplyChainDetector,
    "behavioral-anomaly": BehavioralAnomalyDetector,
}

# Default tests to run
DEFAULT_TESTS = [
    "prompt-injection",
    "jailbreak",
    "data-leakage",
    "hallucination",
]


class LiveTester:
    """
    Orchestrates live security testing of LLM models.

    Architecture:
    1. Initialize: Set up provider and detectors
    2. Test: Send test payloads to live model
    3. Analyze: Evaluate responses for vulnerabilities
    4. Score: Calculate security posture
    5. Report: Generate results
    """

    def __init__(
        self,
        provider: BaseProvider,
        tests: Optional[List[str]] = None,
        mode: str = "standard",
        parallelism: int = 5,
        timeout: int = 30,
        confidence_threshold: float = 0.7,
        verbose: bool = False,
    ):
        """
        Initialize live tester.

        Args:
            provider: LLM provider to test
            tests: List of test names to run (default: core tests)
            mode: Testing mode (quick, standard, comprehensive)
            parallelism: Maximum concurrent tests
            timeout: Timeout per test in seconds
            confidence_threshold: Minimum confidence to report
            verbose: Enable verbose logging
        """
        self.provider = provider
        self.mode = mode
        self.parallelism = parallelism
        self.timeout = timeout
        self.confidence_threshold = confidence_threshold
        self.verbose = verbose

        # Determine which tests to run
        if tests is None or tests == ["all"]:
            self.test_names = list(DETECTOR_REGISTRY.keys())
        else:
            self.test_names = tests

        # Validate test names
        invalid_tests = [t for t in self.test_names if t not in DETECTOR_REGISTRY]
        if invalid_tests:
            raise ValueError(f"Unknown tests: {invalid_tests}. Available: {list(DETECTOR_REGISTRY.keys())}")

        # Initialize detectors
        self.detectors: List[BaseLiveDetector] = []
        for test_name in self.test_names:
            detector_class = DETECTOR_REGISTRY[test_name]
            detector = detector_class(
                provider=provider,
                mode=mode,
                parallelism=parallelism,
                timeout=timeout,
                confidence_threshold=confidence_threshold,
                verbose=verbose,
            )
            self.detectors.append(detector)

    async def run(self) -> TestResult:
        """
        Execute all live security tests.

        Returns:
            TestResult with all findings and scores
        """
        start_time = time.time()

        if self.verbose:
            logger.info(
                f"Starting live security test with {len(self.detectors)} detectors"
            )
            logger.info(f"Provider: {self.provider.provider_name}, Model: {self.provider.model}")
            logger.info(f"Mode: {self.mode}")

        # Run all detectors
        detector_results: List[LiveTestResult] = []
        all_vulnerabilities: List[LiveVulnerability] = []

        for detector in self.detectors:
            if self.verbose:
                logger.info(f"Running {detector.detector_name}...")

            try:
                result = await detector.run()
                detector_results.append(result)
                all_vulnerabilities.extend(result.vulnerabilities)

                if self.verbose:
                    logger.info(
                        f"  {detector.detector_name}: Score={result.score:.1f}, "
                        f"Vulnerabilities={len(result.vulnerabilities)}"
                    )

            except Exception as e:
                logger.error(f"Detector {detector.detector_name} failed: {e}")
                # Create empty result for failed detector
                detector_results.append(
                    LiveTestResult(
                        detector_id=detector.detector_id,
                        detector_name=detector.detector_name,
                        score=0.0,
                        confidence=0.0,
                        vulnerabilities=[],
                        tests_run=0,
                        tests_passed=0,
                        duration_ms=0,
                        metadata={"error": str(e)},
                    )
                )

        # Calculate aggregated metrics
        duration_seconds = time.time() - start_time
        overall_score = self._calculate_overall_score(detector_results)
        overall_confidence = self._calculate_overall_confidence(detector_results)

        # Count tests
        total_tests = sum(r.tests_run for r in detector_results)
        total_passed = sum(r.tests_passed for r in detector_results)

        return TestResult(
            provider=self.provider.provider_name,
            model=self.provider.model,
            mode=self.mode,
            detector_results=detector_results,
            vulnerabilities=all_vulnerabilities,
            overall_score=overall_score,
            confidence=overall_confidence,
            tests_run=total_tests,
            tests_passed=total_passed,
            duration_seconds=duration_seconds,
            metadata={
                "detectors_run": len(detector_results),
                "parallelism": self.parallelism,
                "timeout": self.timeout,
            },
        )

    def _calculate_overall_score(self, results: List[LiveTestResult]) -> float:
        """Calculate overall security score from detector results."""
        if not results:
            return 100.0

        # Weighted average based on vulnerability severity
        total_weight = 0.0
        weighted_score = 0.0

        for result in results:
            # Each detector contributes equally by default
            weight = 1.0
            weighted_score += result.score * weight
            total_weight += weight

        if total_weight == 0:
            return 100.0

        return weighted_score / total_weight

    def _calculate_overall_confidence(self, results: List[LiveTestResult]) -> float:
        """Calculate overall confidence from detector results."""
        if not results:
            return 0.8

        confidences = [r.confidence for r in results if r.tests_run > 0]
        if not confidences:
            return 0.8

        return sum(confidences) / len(confidences)

    @staticmethod
    def get_available_tests() -> List[str]:
        """Get list of available test names."""
        return list(DETECTOR_REGISTRY.keys())

    @staticmethod
    def get_test_description(test_name: str) -> str:
        """Get description of a specific test."""
        descriptions = {
            "prompt-injection": "Tests for prompt injection vulnerabilities",
            "jailbreak": "Tests for jailbreak and bypass attempts",
            "data-leakage": "Tests for sensitive data exposure",
            "hallucination": "Tests for factual accuracy and hallucinations",
            "dos": "Tests for resource exhaustion vulnerabilities",
            "bias": "Tests for demographic bias in responses",
            "model-extraction": "Tests for model parameter probing",
            "adversarial-inputs": "Tests for robustness to adversarial text",
            "output-manipulation": "Tests for response injection attacks",
            "supply-chain": "Tests for plugin/dependency vulnerabilities",
            "behavioral-anomaly": "Tests for unexpected behavioral changes",
        }
        return descriptions.get(test_name, "No description available")


async def run_live_test(
    provider: BaseProvider,
    tests: Optional[List[str]] = None,
    mode: str = "standard",
    parallelism: int = 5,
    timeout: int = 30,
    confidence_threshold: float = 0.7,
    verbose: bool = False,
) -> TestResult:
    """
    Convenience function to run live security tests.

    Args:
        provider: LLM provider to test
        tests: List of test names to run
        mode: Testing mode
        parallelism: Maximum concurrent tests
        timeout: Timeout per test
        confidence_threshold: Minimum confidence
        verbose: Enable verbose logging

    Returns:
        TestResult with all findings
    """
    tester = LiveTester(
        provider=provider,
        tests=tests,
        mode=mode,
        parallelism=parallelism,
        timeout=timeout,
        confidence_threshold=confidence_threshold,
        verbose=verbose,
    )
    return await tester.run()
