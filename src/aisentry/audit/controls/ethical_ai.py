"""
Ethical AI & Bias Controls.

Detects controls for fairness, bias detection, and ethical AI practices.
"""

from typing import List

from ..models import ControlEvidence, ControlLevel, EvidenceItem
from .base_control import BaseControlDetector, ControlCategory


class FairnessMetricsDetector(BaseControlDetector):
    """EA-01: Fairness Metrics - Measure and monitor fairness metrics."""

    control_id = "EA-01"
    control_name = "Fairness Metrics"
    category = "ethical_ai"
    description = "Measure and monitor fairness metrics across demographic groups"
    recommendations = [
        "Use Fairlearn or AIF360 for fairness metrics",
        "Implement demographic parity testing",
        "Monitor fairness metrics in production",
    ]

    def detect(self) -> ControlEvidence:
        evidence_items: List[EvidenceItem] = []

        # Check for fairness libraries
        fairness_libs = ["fairlearn", "aif360", "aequitas", "responsibly"]
        for lib in fairness_libs:
            if self.deps.has_package(lib):
                evidence_items.append(self._evidence_from_dependency(
                    "", lib, f"Fairness library {lib} found"
                ))

        # Check for fairness metric patterns in code
        fairness_patterns = ["fairness", "demographic_parity", "equalized_odds", "bias"]
        for pattern in fairness_patterns:
            matches = self.ast.find_function_calls(pattern)
            for match in matches[:2]:
                evidence_items.append(self._evidence_from_ast(
                    match.file_path, match.line_number, match.snippet,
                    f"Fairness metric: {match.name}"
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


class ExplainabilityDetector(BaseControlDetector):
    """EA-02: Model Explainability - Explain model decisions."""

    control_id = "EA-02"
    control_name = "Model Explainability"
    category = "ethical_ai"
    description = "Provide explanations for model decisions and outputs"
    recommendations = [
        "Use SHAP or LIME for model explanations",
        "Implement feature attribution for predictions",
        "Provide human-readable explanations",
    ]

    def detect(self) -> ControlEvidence:
        evidence_items: List[EvidenceItem] = []

        # Check for explainability libraries
        explain_libs = ["shap", "lime", "eli5", "captum", "alibi", "interpret"]
        for lib in explain_libs:
            if self.deps.has_package(lib):
                evidence_items.append(self._evidence_from_dependency(
                    "", lib, f"Explainability library {lib} found"
                ))

        # Check for explainability patterns in code
        explain_patterns = ["explain", "shap", "lime", "feature_importance", "attribution"]
        for pattern in explain_patterns:
            matches = self.ast.find_function_calls(pattern)
            for match in matches[:2]:
                evidence_items.append(self._evidence_from_ast(
                    match.file_path, match.line_number, match.snippet,
                    f"Explainability: {match.name}"
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


class BiasTestingDetector(BaseControlDetector):
    """EA-03: Bias Testing - Systematic testing for biased outputs."""

    control_id = "EA-03"
    control_name = "Bias Testing"
    category = "ethical_ai"
    description = "Systematic testing for biased or discriminatory outputs"
    recommendations = [
        "Implement adversarial testing for bias",
        "Test across demographic groups",
        "Use TextAttack or CheckList for NLP bias testing",
    ]

    def detect(self) -> ControlEvidence:
        evidence_items: List[EvidenceItem] = []

        # Check for bias testing tools
        bias_tools = ["textattack", "checklist"]
        for tool in bias_tools:
            if self.deps.has_package(tool):
                evidence_items.append(self._evidence_from_dependency(
                    "", tool, f"Bias testing tool {tool} found"
                ))

        # Check for bias testing patterns
        bias_patterns = ["bias_test", "test_bias", "adversarial", "counterfactual"]
        for pattern in bias_patterns:
            matches = self.ast.find_function_calls(pattern)
            for match in matches[:2]:
                evidence_items.append(self._evidence_from_ast(
                    match.file_path, match.line_number, match.snippet,
                    f"Bias testing: {match.name}"
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


class ModelCardsDetector(BaseControlDetector):
    """EA-04: Model Cards - Document model capabilities and limitations."""

    control_id = "EA-04"
    control_name = "Model Cards"
    category = "ethical_ai"
    description = "Document model capabilities, limitations, and intended use"
    recommendations = [
        "Create model cards for all deployed models",
        "Document intended use and out-of-scope uses",
        "Include performance metrics across demographics",
    ]

    def detect(self) -> ControlEvidence:
        evidence_items: List[EvidenceItem] = []

        # Check for model card files
        model_card_files = ["MODEL_CARD", "model_card", "model-card"]
        for file_pattern in model_card_files:
            if self.config.file_exists(f"{file_pattern}.md") or self.config.file_exists(f"{file_pattern}.yaml"):
                evidence_items.append(self._evidence_from_file(
                    file_pattern, f"Model card file found: {file_pattern}"
                ))

        # Check for model card library usage
        if self.deps.has_package("model-card-toolkit"):
            evidence_items.append(self._evidence_from_dependency(
                "", "model-card-toolkit", "Model card toolkit found"
            ))

        # Check for model documentation in README
        doc_patterns = ["intended_use", "limitations", "ethical", "bias_considerations"]
        for pattern in doc_patterns:
            config_matches = self.config.find_key(pattern)
            for match in config_matches[:2]:
                evidence_items.append(self._evidence_from_config(
                    match.file_path, match.key, str(match.value),
                    f"Model documentation: {match.key}"
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


class EthicalAIControls(ControlCategory):
    """Ethical AI & Bias control category."""

    category_id = "ethical_ai"
    category_name = "Ethical AI & Bias"
    weight = 0.10

    def _create_detectors(self) -> List[BaseControlDetector]:
        return [
            FairnessMetricsDetector(self.ast, self.config, self.deps),
            ExplainabilityDetector(self.ast, self.config, self.deps),
            BiasTestingDetector(self.ast, self.config, self.deps),
            ModelCardsDetector(self.ast, self.config, self.deps),
        ]
