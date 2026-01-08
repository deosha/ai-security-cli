"""
AI Governance and Compliance control detectors.
"""

from typing import List

from ..models import ControlEvidence, ControlLevel, EvidenceItem
from .base_control import BaseControlDetector, ControlCategory


class ExplainabilityDetector(BaseControlDetector):
    """Detect model explainability controls."""

    control_id = "GV-01"
    control_name = "Model Explainability"
    category = "governance"
    description = "Explainability and interpretability of model decisions"
    recommendations = [
        "Use SHAP or LIME for model explanations",
        "Provide decision explanations in outputs",
        "Implement feature attribution tracking",
    ]

    def detect(self) -> ControlEvidence:
        evidence_items: List[EvidenceItem] = []

        # Check for explainability libraries
        explain_libs = ["shap", "lime", "alibi", "captum", "interpret"]
        for lib in explain_libs:
            if self.deps.has_package(lib):
                evidence_items.append(self._evidence_from_dependency(
                    "", lib, f"Explainability library: {lib}"
                ))

        # Check for explainability imports
        for lib in ["shap", "lime", "alibi"]:
            matches = self.ast.find_imports(lib)
            for match in matches[:2]:
                evidence_items.append(self._evidence_from_import(
                    match.file_path, match.line_number, match.name,
                    f"Explainability import: {match.name}"
                ))

        # Check for explanation function calls
        explain_patterns = ["explain", "shap_values", "feature_importance"]
        for pattern in explain_patterns:
            matches = self.ast.find_function_calls(pattern)
            for match in matches[:2]:
                evidence_items.append(self._evidence_from_ast(
                    match.file_path, match.line_number, match.snippet,
                    f"Explanation function: {match.name}"
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


class BiasDetectionDetector(BaseControlDetector):
    """Detect bias detection and fairness controls."""

    control_id = "GV-02"
    control_name = "Bias Detection"
    category = "governance"
    description = "Detection and mitigation of model bias"
    recommendations = [
        "Use Fairlearn or AIF360 for bias detection",
        "Implement fairness metrics tracking",
        "Test for demographic parity and equalized odds",
    ]

    def detect(self) -> ControlEvidence:
        evidence_items: List[EvidenceItem] = []

        # Check for bias/fairness libraries
        bias_libs = ["fairlearn", "aequitas", "aif360", "responsibleai"]
        for lib in bias_libs:
            if self.deps.has_package(lib):
                evidence_items.append(self._evidence_from_dependency(
                    "", lib, f"Fairness library: {lib}"
                ))

        # Check for fairness imports
        fairness_imports = ["fairlearn", "aequitas", "aif360"]
        for pattern in fairness_imports:
            matches = self.ast.find_imports(pattern)
            for match in matches[:2]:
                evidence_items.append(self._evidence_from_import(
                    match.file_path, match.line_number, match.name,
                    f"Fairness import: {match.name}"
                ))

        # Check for bias-related function calls
        bias_patterns = ["bias", "fairness", "demographic_parity", "equalized_odds"]
        for pattern in bias_patterns:
            matches = self.ast.find_function_calls(pattern)
            for match in matches[:2]:
                evidence_items.append(self._evidence_from_ast(
                    match.file_path, match.line_number, match.snippet,
                    f"Bias detection: {match.name}"
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


class ModelDocumentationDetector(BaseControlDetector):
    """Detect model documentation controls."""

    control_id = "GV-03"
    control_name = "Model Documentation"
    category = "governance"
    description = "Documentation of model behavior and limitations"
    recommendations = [
        "Create model cards for all production models",
        "Document model limitations and known issues",
        "Maintain changelog for model updates",
    ]

    def detect(self) -> ControlEvidence:
        evidence_items: List[EvidenceItem] = []

        # Check for model card patterns
        doc_patterns = ["model_card", "modelcard", "documentation"]
        for pattern in doc_patterns:
            config_matches = self.config.find_key(pattern)
            for match in config_matches[:2]:
                evidence_items.append(self._evidence_from_config(
                    match.file_path, match.key, str(match.value),
                    f"Model documentation: {match.key}"
                ))

        # Check for docstring presence (basic documentation)
        # This is a simple heuristic - checking for classes with docstrings
        model_classes = self.ast.find_classes("Model")
        for match in model_classes[:2]:
            evidence_items.append(self._evidence_from_ast(
                match.file_path, match.line_number, match.snippet,
                f"Model class with documentation: {match.name}"
            ))

        # Check for README or docs
        readme_patterns = ["readme", "docs", "documentation"]
        for pattern in readme_patterns:
            config_matches = self.config.find_key(pattern)
            if config_matches:
                evidence_items.append(self._evidence_from_file(
                    config_matches[0].file_path,
                    "Documentation files present"
                ))
                break

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


class ComplianceTrackingDetector(BaseControlDetector):
    """Detect compliance tracking controls."""

    control_id = "GV-04"
    control_name = "Compliance Tracking"
    category = "governance"
    description = "Tracking of regulatory compliance requirements"
    recommendations = [
        "Implement compliance checklists for AI systems",
        "Track EU AI Act and other regulatory requirements",
        "Maintain audit logs for compliance evidence",
    ]

    def detect(self) -> ControlEvidence:
        evidence_items: List[EvidenceItem] = []

        # Check for compliance-related config
        compliance_patterns = [
            "compliance", "gdpr", "hipaa", "eu_ai_act",
            "regulatory", "audit"
        ]
        for pattern in compliance_patterns:
            config_matches = self.config.find_key(pattern)
            for match in config_matches[:2]:
                evidence_items.append(self._evidence_from_config(
                    match.file_path, match.key, str(match.value),
                    f"Compliance configuration: {match.key}"
                ))

        # Check for audit logging
        audit_patterns = ["audit", "compliance_log", "regulatory"]
        for pattern in audit_patterns:
            matches = self.ast.find_function_calls(pattern)
            for match in matches[:2]:
                evidence_items.append(self._evidence_from_ast(
                    match.file_path, match.line_number, match.snippet,
                    f"Compliance tracking: {match.name}"
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


class HumanOversightDetector(BaseControlDetector):
    """Detect human oversight controls."""

    control_id = "GV-05"
    control_name = "Human Oversight"
    category = "governance"
    description = "Human oversight and intervention capabilities"
    recommendations = [
        "Implement human-in-the-loop for critical decisions",
        "Add manual review workflows for high-risk outputs",
        "Create escalation procedures for edge cases",
    ]

    def detect(self) -> ControlEvidence:
        evidence_items: List[EvidenceItem] = []

        # Check for human oversight patterns
        oversight_patterns = [
            "human_review", "manual_review", "human_in_the_loop",
            "escalate", "require_approval", "manual_approval"
        ]
        for pattern in oversight_patterns:
            matches = self.ast.find_function_calls(pattern)
            for match in matches[:2]:
                evidence_items.append(self._evidence_from_ast(
                    match.file_path, match.line_number, match.snippet,
                    f"Human oversight: {match.name}"
                ))

        # Check for review config
        review_patterns = ["review", "approval", "oversight"]
        for pattern in review_patterns:
            config_matches = self.config.find_key(pattern)
            for match in config_matches[:2]:
                evidence_items.append(self._evidence_from_config(
                    match.file_path, match.key, str(match.value),
                    f"Review configuration: {match.key}"
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


class GovernanceControls(ControlCategory):
    """AI Governance control category."""

    category_id = "governance"
    category_name = "AI Governance"
    weight = 0.10

    def _create_detectors(self) -> List[BaseControlDetector]:
        return [
            ExplainabilityDetector(self.ast, self.config, self.deps),
            BiasDetectionDetector(self.ast, self.config, self.deps),
            ModelDocumentationDetector(self.ast, self.config, self.deps),
            ComplianceTrackingDetector(self.ast, self.config, self.deps),
            HumanOversightDetector(self.ast, self.config, self.deps),
        ]
