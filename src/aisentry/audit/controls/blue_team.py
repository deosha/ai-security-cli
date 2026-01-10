"""
AI Blue Team Operations control detectors.
"""

from typing import List

from ..models import ControlEvidence, ControlLevel, EvidenceItem
from .base_control import BaseControlDetector, ControlCategory


class ModelMonitoringDetector(BaseControlDetector):
    """Detect model performance monitoring."""

    control_id = "BT-01"
    control_name = "Model Monitoring"
    category = "blue_team"
    description = "Monitoring of model performance and behavior"
    recommendations = [
        "Implement model performance metrics tracking",
        "Set up alerting for performance degradation",
        "Use tools like Prometheus or DataDog for monitoring",
    ]

    def detect(self) -> ControlEvidence:
        evidence_items: List[EvidenceItem] = []

        # Check for monitoring libraries
        monitoring_libs = [
            "prometheus-client", "datadog", "newrelic",
            "opentelemetry-sdk", "sentry-sdk"
        ]
        for lib in monitoring_libs:
            if self.deps.has_package(lib):
                evidence_items.append(self._evidence_from_dependency(
                    "", lib, f"Monitoring library: {lib}"
                ))

        # Check for metrics patterns
        metrics_patterns = ["metric", "gauge", "counter", "histogram", "track"]
        for pattern in metrics_patterns:
            matches = self.ast.find_function_calls(pattern)
            for match in matches[:2]:
                evidence_items.append(self._evidence_from_ast(
                    match.file_path, match.line_number, match.snippet,
                    f"Metrics tracking: {match.name}"
                ))

        # Determine level
        if not evidence_items:
            level = ControlLevel.NONE
        elif len(evidence_items) >= 4:
            level = ControlLevel.ADVANCED
        elif len(evidence_items) >= 2:
            level = ControlLevel.INTERMEDIATE
        else:
            level = ControlLevel.BASIC

        return self._create_evidence(
            detected=len(evidence_items) > 0,
            level=level,
            evidence_items=evidence_items,
        )


class DriftDetectionDetector(BaseControlDetector):
    """Detect model drift monitoring."""

    control_id = "BT-02"
    control_name = "Drift Detection"
    category = "blue_team"
    description = "Detection of data and model drift"
    recommendations = [
        "Implement drift detection with evidently or alibi-detect",
        "Monitor input data distribution changes",
        "Set up automated alerts for drift events",
    ]

    def detect(self) -> ControlEvidence:
        evidence_items: List[EvidenceItem] = []

        # Check for drift detection libraries
        drift_libs = [
            "evidently", "alibi-detect", "deepchecks",
            "whylogs", "nannyml"
        ]
        for lib in drift_libs:
            if self.deps.has_package(lib):
                evidence_items.append(self._evidence_from_dependency(
                    "", lib, f"Drift detection library: {lib}"
                ))

        # Check for drift-related imports
        drift_imports = ["evidently", "alibi_detect", "drift"]
        for pattern in drift_imports:
            matches = self.ast.find_imports(pattern)
            for match in matches[:2]:
                evidence_items.append(self._evidence_from_import(
                    match.file_path, match.line_number, match.name,
                    f"Drift detection import: {match.name}"
                ))

        # Check for drift function calls
        drift_patterns = ["detect_drift", "drift_score", "calculate_drift"]
        for pattern in drift_patterns:
            matches = self.ast.find_function_calls(pattern)
            for match in matches[:2]:
                evidence_items.append(self._evidence_from_ast(
                    match.file_path, match.line_number, match.snippet,
                    f"Drift detection: {match.name}"
                ))

        # Determine level
        if not evidence_items:
            level = ControlLevel.NONE
        elif len(evidence_items) >= 3:
            level = ControlLevel.ADVANCED
        elif len(evidence_items) >= 2:
            level = ControlLevel.INTERMEDIATE
        else:
            level = ControlLevel.BASIC

        return self._create_evidence(
            detected=len(evidence_items) > 0,
            level=level,
            evidence_items=evidence_items,
        )


class AnomalyDetectionDetector(BaseControlDetector):
    """Detect anomaly detection capabilities."""

    control_id = "BT-03"
    control_name = "Anomaly Detection"
    category = "blue_team"
    description = "Detection of anomalous model inputs or outputs"
    recommendations = [
        "Implement anomaly detection on model inputs",
        "Monitor for unusual query patterns",
        "Use statistical methods or ML-based detection",
    ]

    def detect(self) -> ControlEvidence:
        evidence_items: List[EvidenceItem] = []

        # Check for anomaly detection patterns
        anomaly_patterns = [
            "anomaly", "outlier", "isolation_forest",
            "detect_anomaly", "is_anomaly"
        ]
        for pattern in anomaly_patterns:
            matches = self.ast.find_function_calls(pattern)
            for match in matches[:2]:
                evidence_items.append(self._evidence_from_ast(
                    match.file_path, match.line_number, match.snippet,
                    f"Anomaly detection: {match.name}"
                ))

        # Check for sklearn anomaly detection
        sklearn_imports = self.ast.find_imports("sklearn")
        for match in sklearn_imports:
            if "isolation" in match.snippet.lower() or "outlier" in match.snippet.lower():
                evidence_items.append(self._evidence_from_import(
                    match.file_path, match.line_number, match.name,
                    "Sklearn anomaly detection"
                ))

        # Check for pyod library
        if self.deps.has_package("pyod"):
            evidence_items.append(self._evidence_from_dependency(
                "", "pyod", "PyOD anomaly detection library"
            ))

        # Determine level
        if not evidence_items:
            level = ControlLevel.NONE
        elif len(evidence_items) >= 3:
            level = ControlLevel.ADVANCED
        elif len(evidence_items) >= 2:
            level = ControlLevel.INTERMEDIATE
        else:
            level = ControlLevel.BASIC

        return self._create_evidence(
            detected=len(evidence_items) > 0,
            level=level,
            evidence_items=evidence_items,
        )


class AdversarialDetectionDetector(BaseControlDetector):
    """Detect adversarial attack detection capabilities."""

    control_id = "BT-04"
    control_name = "Adversarial Attack Detection"
    category = "blue_team"
    description = "Detection of adversarial inputs and attacks"
    recommendations = [
        "Implement adversarial input detection",
        "Use adversarial robustness toolkits",
        "Add input perturbation analysis",
    ]

    def detect(self) -> ControlEvidence:
        evidence_items: List[EvidenceItem] = []

        # Check for adversarial ML libraries
        adv_libs = [
            "adversarial-robustness-toolbox", "cleverhans",
            "foolbox", "textattack"
        ]
        for lib in adv_libs:
            if self.deps.has_package(lib):
                evidence_items.append(self._evidence_from_dependency(
                    "", lib, f"Adversarial ML library: {lib}"
                ))

        # Check for adversarial patterns
        adv_patterns = ["adversarial", "perturbation", "attack_detect"]
        for pattern in adv_patterns:
            matches = self.ast.find_function_calls(pattern)
            for match in matches[:2]:
                evidence_items.append(self._evidence_from_ast(
                    match.file_path, match.line_number, match.snippet,
                    f"Adversarial detection: {match.name}"
                ))

        # Determine level
        if not evidence_items:
            level = ControlLevel.NONE
        elif len(evidence_items) >= 3:
            level = ControlLevel.ADVANCED
        elif len(evidence_items) >= 2:
            level = ControlLevel.INTERMEDIATE
        else:
            level = ControlLevel.BASIC

        return self._create_evidence(
            detected=len(evidence_items) > 0,
            level=level,
            evidence_items=evidence_items,
        )


class IncidentResponseDetector(BaseControlDetector):
    """Detect AI incident response capabilities."""

    control_id = "BT-05"
    control_name = "AI Incident Response"
    category = "blue_team"
    description = "Incident response procedures for AI systems"
    recommendations = [
        "Create AI-specific incident response playbooks",
        "Implement model rollback capabilities",
        "Set up automated incident alerting",
    ]

    def detect(self) -> ControlEvidence:
        evidence_items: List[EvidenceItem] = []

        # Check for rollback capabilities
        rollback_patterns = ["rollback", "revert", "restore_model", "fallback"]
        for pattern in rollback_patterns:
            matches = self.ast.find_function_calls(pattern)
            for match in matches[:2]:
                evidence_items.append(self._evidence_from_ast(
                    match.file_path, match.line_number, match.snippet,
                    f"Rollback capability: {match.name}"
                ))

        # Check for alerting
        alert_patterns = ["alert", "notify", "incident", "pagerduty", "slack"]
        for pattern in alert_patterns:
            matches = self.ast.find_function_calls(pattern)
            for match in matches[:2]:
                evidence_items.append(self._evidence_from_ast(
                    match.file_path, match.line_number, match.snippet,
                    f"Incident alerting: {match.name}"
                ))

        # Check for incident response config
        ir_patterns = ["incident", "playbook", "runbook"]
        for pattern in ir_patterns:
            config_matches = self.config.find_key(pattern)
            for match in config_matches[:2]:
                evidence_items.append(self._evidence_from_config(
                    match.file_path, match.key, str(match.value),
                    f"Incident response config: {match.key}"
                ))

        # Determine level
        if not evidence_items:
            level = ControlLevel.NONE
        elif len(evidence_items) >= 4:
            level = ControlLevel.ADVANCED
        elif len(evidence_items) >= 2:
            level = ControlLevel.INTERMEDIATE
        else:
            level = ControlLevel.BASIC

        return self._create_evidence(
            detected=len(evidence_items) > 0,
            level=level,
            evidence_items=evidence_items,
        )


class ModelDriftMonitoringDetector(BaseControlDetector):
    """Detect model drift monitoring."""

    control_id = "BT-06"
    control_name = "Model Drift Monitoring"
    category = "blue_team"
    description = "Monitoring for model drift and automatic retraining triggers"
    recommendations = [
        "Use Evidently or alibi-detect for drift monitoring",
        "Set up automated alerts for significant drift",
        "Implement automatic retraining pipelines",
    ]

    def detect(self) -> ControlEvidence:
        evidence_items: List[EvidenceItem] = []

        # Check for drift detection libraries
        drift_libs = ["evidently", "alibi-detect", "nannyml", "deepchecks"]
        for lib in drift_libs:
            if self.deps.has_package(lib):
                evidence_items.append(self._evidence_from_dependency(
                    "", lib, f"Drift monitoring library {lib} found"
                ))

        # Check for drift detection patterns
        drift_patterns = [
            "drift", "distribution_shift", "data_drift", "concept_drift",
            "DriftReport", "DataDriftTab"
        ]
        for pattern in drift_patterns:
            matches = self.ast.find_function_calls(pattern)
            for match in matches[:2]:
                evidence_items.append(self._evidence_from_ast(
                    match.file_path, match.line_number, match.snippet,
                    f"Drift monitoring: {match.name}"
                ))

        # Determine level
        if not evidence_items:
            level = ControlLevel.NONE
        elif len(evidence_items) >= 2:
            level = ControlLevel.ADVANCED
        elif len(evidence_items) >= 1:
            level = ControlLevel.INTERMEDIATE
        else:
            level = ControlLevel.BASIC

        return self._create_evidence(
            detected=len(evidence_items) > 0,
            level=level,
            evidence_items=evidence_items,
        )


class DataQualityMonitoringDetector(BaseControlDetector):
    """Detect data quality monitoring."""

    control_id = "BT-07"
    control_name = "Data Quality Monitoring"
    category = "blue_team"
    description = "Monitoring input data quality for AI systems"
    recommendations = [
        "Use Great Expectations for data validation",
        "Implement data quality checks in pipeline",
        "Set up alerts for data quality issues",
    ]

    def detect(self) -> ControlEvidence:
        evidence_items: List[EvidenceItem] = []

        # Check for data quality libraries
        quality_libs = ["great_expectations", "pandera", "cerberus", "pydantic"]
        for lib in quality_libs:
            if self.deps.has_package(lib):
                evidence_items.append(self._evidence_from_dependency(
                    "", lib, f"Data quality library {lib} found"
                ))

        # Check for data validation patterns
        validation_patterns = [
            "validate_data", "data_quality", "expect_column", "DataContract",
            "check_data", "quality_check"
        ]
        for pattern in validation_patterns:
            matches = self.ast.find_function_calls(pattern)
            for match in matches[:2]:
                evidence_items.append(self._evidence_from_ast(
                    match.file_path, match.line_number, match.snippet,
                    f"Data quality check: {match.name}"
                ))

        # Check for Great Expectations usage
        ge_patterns = ["ExpectationSuite", "expect_", "checkpoint"]
        for pattern in ge_patterns:
            matches = self.ast.find_function_calls(pattern)
            for match in matches[:2]:
                evidence_items.append(self._evidence_from_ast(
                    match.file_path, match.line_number, match.snippet,
                    f"Great Expectations: {match.name}"
                ))

        # Determine level
        if not evidence_items:
            level = ControlLevel.NONE
        elif len(evidence_items) >= 3:
            level = ControlLevel.ADVANCED
        elif len(evidence_items) >= 1:
            level = ControlLevel.INTERMEDIATE
        else:
            level = ControlLevel.BASIC

        return self._create_evidence(
            detected=len(evidence_items) > 0,
            level=level,
            evidence_items=evidence_items,
        )


class BlueTeamControls(ControlCategory):
    """AI Blue Team Operations control category."""

    category_id = "blue_team"
    category_name = "Blue Team Operations"
    weight = 0.10

    def _create_detectors(self) -> List[BaseControlDetector]:
        return [
            ModelMonitoringDetector(self.ast, self.config, self.deps),
            DriftDetectionDetector(self.ast, self.config, self.deps),
            AnomalyDetectionDetector(self.ast, self.config, self.deps),
            AdversarialDetectionDetector(self.ast, self.config, self.deps),
            IncidentResponseDetector(self.ast, self.config, self.deps),
            ModelDriftMonitoringDetector(self.ast, self.config, self.deps),
            DataQualityMonitoringDetector(self.ast, self.config, self.deps),
        ]
