"""
Incident Response Controls.

Detects controls for AI-specific incident response and monitoring.
"""

from typing import List

from ..models import ControlEvidence, ControlLevel, EvidenceItem
from .base_control import BaseControlDetector, ControlCategory


class MonitoringIntegrationDetector(BaseControlDetector):
    """IR-01: Monitoring Integration - Real-time monitoring of AI systems."""

    control_id = "IR-01"
    control_name = "Monitoring Integration"
    category = "incident_response"
    description = "Real-time monitoring and alerting for AI system health"
    recommendations = [
        "Use Prometheus or DataDog for metrics collection",
        "Set up alerts for model latency and error rates",
        "Implement health checks for AI endpoints",
    ]

    def detect(self) -> ControlEvidence:
        evidence_items: List[EvidenceItem] = []

        # Check for monitoring tools in dependencies
        monitoring_tools = [
            "prometheus_client", "prometheus-client",
            "datadog", "newrelic", "sentry-sdk",
            "opentelemetry-api", "statsd", "cloudwatch",
        ]
        for tool in monitoring_tools:
            if self.deps.has_package(tool):
                evidence_items.append(self._evidence_from_dependency(
                    "", tool, f"Monitoring tool {tool} found"
                ))

        # Check for monitoring patterns in code
        monitoring_patterns = ["Counter", "Gauge", "Histogram", "metrics", "prometheus"]
        for pattern in monitoring_patterns:
            matches = self.ast.find_function_calls(pattern)
            for match in matches[:2]:
                evidence_items.append(self._evidence_from_ast(
                    match.file_path, match.line_number, match.snippet,
                    f"Monitoring pattern: {match.name}"
                ))

        # Check config for monitoring settings
        config_patterns = ["monitoring", "alerting", "metrics", "prometheus", "datadog"]
        for pattern in config_patterns:
            config_matches = self.config.find_key(pattern)
            for match in config_matches[:2]:
                evidence_items.append(self._evidence_from_config(
                    match.file_path, match.key, str(match.value),
                    f"Monitoring config: {match.key}"
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


class AuditLoggingDetector(BaseControlDetector):
    """IR-02: Audit Logging - Comprehensive logging for forensics."""

    control_id = "IR-02"
    control_name = "Audit Logging"
    category = "incident_response"
    description = "Comprehensive logging of AI interactions for forensic analysis"
    recommendations = [
        "Use structlog or python-json-logger for structured logs",
        "Log all AI model inputs and outputs",
        "Implement log retention policies",
    ]

    def detect(self) -> ControlEvidence:
        evidence_items: List[EvidenceItem] = []

        # Check for structured logging libraries
        logging_libs = ["structlog", "python-json-logger", "loguru"]
        for lib in logging_libs:
            if self.deps.has_package(lib):
                evidence_items.append(self._evidence_from_dependency(
                    "", lib, f"Structured logging library {lib} found"
                ))

        # Check for logging patterns in code
        logging_patterns = ["audit", "logger", "logging", "log_event"]
        for pattern in logging_patterns:
            matches = self.ast.find_function_calls(pattern)
            for match in matches[:2]:
                evidence_items.append(self._evidence_from_ast(
                    match.file_path, match.line_number, match.snippet,
                    f"Logging pattern: {match.name}"
                ))

        # Check for logging configuration
        log_config_patterns = ["logging", "log_level", "log_format"]
        for pattern in log_config_patterns:
            config_matches = self.config.find_key(pattern)
            for match in config_matches[:2]:
                evidence_items.append(self._evidence_from_config(
                    match.file_path, match.key, str(match.value),
                    f"Logging config: {match.key}"
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


class RollbackCapabilityDetector(BaseControlDetector):
    """IR-03: Rollback Capability - Ability to rollback to previous versions."""

    control_id = "IR-03"
    control_name = "Rollback Capability"
    category = "incident_response"
    description = "Ability to quickly rollback models to previous versions"
    recommendations = [
        "Use MLflow or DVC for model versioning",
        "Implement blue-green deployments for models",
        "Maintain rollback procedures documentation",
    ]

    def detect(self) -> ControlEvidence:
        evidence_items: List[EvidenceItem] = []

        # Check for versioning tools that support rollback
        versioning_tools = ["mlflow", "dvc", "wandb", "neptune"]
        for tool in versioning_tools:
            if self.deps.has_package(tool):
                evidence_items.append(self._evidence_from_dependency(
                    "", tool, f"Model versioning tool {tool} found"
                ))

        # Check for rollback patterns in code
        rollback_patterns = ["rollback", "restore", "revert", "fallback", "version"]
        for pattern in rollback_patterns:
            matches = self.ast.find_function_calls(pattern)
            for match in matches[:2]:
                evidence_items.append(self._evidence_from_ast(
                    match.file_path, match.line_number, match.snippet,
                    f"Rollback pattern: {match.name}"
                ))

        # Check for deployment strategy configs
        deployment_patterns = ["blue_green", "canary", "rollback", "deployment_strategy"]
        for pattern in deployment_patterns:
            config_matches = self.config.find_key(pattern)
            for match in config_matches[:2]:
                evidence_items.append(self._evidence_from_config(
                    match.file_path, match.key, str(match.value),
                    f"Deployment config: {match.key}"
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


class IncidentResponseControls(ControlCategory):
    """Incident Response control category."""

    category_id = "incident_response"
    category_name = "Incident Response"
    weight = 0.10

    def _create_detectors(self) -> List[BaseControlDetector]:
        return [
            MonitoringIntegrationDetector(self.ast, self.config, self.deps),
            AuditLoggingDetector(self.ast, self.config, self.deps),
            RollbackCapabilityDetector(self.ast, self.config, self.deps),
        ]
