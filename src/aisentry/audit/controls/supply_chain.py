"""
Supply Chain Security Controls.

Detects security controls for AI/ML supply chain protection.
"""

from typing import List

from ..models import ControlEvidence, ControlLevel, EvidenceItem
from .base_control import BaseControlDetector, ControlCategory


class DependencyScanningDetector(BaseControlDetector):
    """SC-01: Dependency Scanning - Continuous scanning for vulnerabilities."""

    control_id = "SC-01"
    control_name = "Dependency Scanning"
    category = "supply_chain"
    description = "Continuous scanning of dependencies for known vulnerabilities"
    recommendations = [
        "Add safety or pip-audit to your dependencies",
        "Configure CI/CD to run security scans on every commit",
        "Set up Dependabot or Renovate for automatic updates",
    ]

    def detect(self) -> ControlEvidence:
        evidence_items: List[EvidenceItem] = []

        # Check for security scanning tools in dependencies
        security_tools = ["safety", "pip-audit", "bandit", "semgrep", "snyk"]
        for tool in security_tools:
            if self.deps.has_package(tool):
                evidence_items.append(self._evidence_from_dependency(
                    "", tool, f"Security scanning tool {tool} found"
                ))

        # Check CI configs for security scanning
        ci_patterns = ["safety", "pip-audit", "bandit", "snyk", "security"]
        for pattern in ci_patterns:
            matches = self.config.find_key(pattern)
            for match in matches[:2]:
                evidence_items.append(self._evidence_from_config(
                    match.file_path, match.key, str(match.value),
                    f"Security scan config: {match.key}"
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


class ModelProvenanceDetector(BaseControlDetector):
    """SC-02: Model Provenance Tracking - Track model lineage and origin."""

    control_id = "SC-02"
    control_name = "Model Provenance Tracking"
    category = "supply_chain"
    description = "Track model lineage, versioning, and origin"
    recommendations = [
        "Use MLflow, DVC, or Weights & Biases for model tracking",
        "Implement model versioning with metadata",
        "Maintain model registry with provenance information",
    ]

    def detect(self) -> ControlEvidence:
        evidence_items: List[EvidenceItem] = []

        # Check for ML versioning tools
        versioning_tools = ["mlflow", "dvc", "wandb", "neptune", "comet-ml", "clearml"]
        for tool in versioning_tools:
            if self.deps.has_package(tool):
                evidence_items.append(self._evidence_from_dependency(
                    "", tool, f"Model versioning tool {tool} found"
                ))

        # Check for MLflow/DVC usage in code
        provenance_patterns = ["mlflow", "dvc", "wandb", "log_model", "register_model"]
        for pattern in provenance_patterns:
            matches = self.ast.find_function_calls(pattern)
            for match in matches[:2]:
                evidence_items.append(self._evidence_from_ast(
                    match.file_path, match.line_number, match.snippet,
                    f"Model tracking: {match.name}"
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


class ModelIntegrityDetector(BaseControlDetector):
    """SC-03: Model Integrity Verification - Cryptographic verification of models."""

    control_id = "SC-03"
    control_name = "Model Integrity Verification"
    category = "supply_chain"
    description = "Cryptographic signature and hash verification of model files"
    recommendations = [
        "Verify model checksums before loading",
        "Use safetensors for safe model serialization",
        "Implement cryptographic signatures for model files",
    ]

    def detect(self) -> ControlEvidence:
        evidence_items: List[EvidenceItem] = []

        # Check for safetensors library
        if self.deps.has_package("safetensors"):
            evidence_items.append(self._evidence_from_dependency(
                "", "safetensors", "Safe model serialization library found"
            ))

        # Check for hash verification in code
        hash_patterns = ["hashlib", "sha256", "verify", "checksum"]
        for pattern in hash_patterns:
            matches = self.ast.find_imports(pattern)
            for match in matches[:2]:
                evidence_items.append(self._evidence_from_import(
                    match.file_path, match.line_number, match.name,
                    f"Hash library: {match.name}"
                ))

        # Check for verification function calls
        verify_patterns = ["verify", "validate", "check_hash", "check_integrity"]
        for pattern in verify_patterns:
            matches = self.ast.find_function_calls(pattern)
            for match in matches[:2]:
                evidence_items.append(self._evidence_from_ast(
                    match.file_path, match.line_number, match.snippet,
                    f"Verification: {match.name}"
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


class SupplyChainControls(ControlCategory):
    """Supply Chain Security control category."""

    category_id = "supply_chain"
    category_name = "Supply Chain Security"
    weight = 0.10

    def _create_detectors(self) -> List[BaseControlDetector]:
        return [
            DependencyScanningDetector(self.ast, self.config, self.deps),
            ModelProvenanceDetector(self.ast, self.config, self.deps),
            ModelIntegrityDetector(self.ast, self.config, self.deps),
        ]
