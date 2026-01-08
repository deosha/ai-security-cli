"""
Prompt Security control detectors.
"""

from typing import List

from ..models import ControlEvidence, ControlLevel, EvidenceItem
from .base_control import BaseControlDetector, ControlCategory


class PromptSanitizationDetector(BaseControlDetector):
    """Detect prompt sanitization controls."""

    control_id = "PS-01"
    control_name = "Prompt Sanitization"
    category = "prompt_security"
    description = "Sanitization of user input before inclusion in prompts"
    recommendations = [
        "Implement input sanitization before constructing prompts",
        "Use libraries like bleach or markupsafe for HTML sanitization",
        "Create custom sanitization functions for prompt-specific threats",
    ]

    def detect(self) -> ControlEvidence:
        evidence_items: List[EvidenceItem] = []

        # Check for sanitization libraries
        sanitization_libs = ["bleach", "markupsafe", "html", "defusedxml"]
        for lib in sanitization_libs:
            if self.deps.has_package(lib):
                packages = self.deps.get_packages_by_category("sanitization")
                for pkg in packages:
                    if lib in pkg.package_name:
                        evidence_items.append(self._evidence_from_dependency(
                            pkg.file_path, pkg.package_name,
                            f"Sanitization library {pkg.package_name} found"
                        ))

        # Check for sanitization function calls
        sanitize_patterns = [
            "sanitize", "clean", "filter", "escape", "strip_tags",
            "bleach.clean", "html.escape", "markupsafe.escape"
        ]
        for pattern in sanitize_patterns:
            matches = self.ast.find_function_calls(pattern)
            for match in matches[:3]:  # Limit evidence
                evidence_items.append(self._evidence_from_ast(
                    match.file_path, match.line_number, match.snippet,
                    f"Sanitization function call: {match.name}"
                ))

        # Check for custom sanitization functions
        func_patterns = ["sanitize_prompt", "clean_input", "filter_prompt"]
        for pattern in func_patterns:
            matches = self.ast.find_function_calls(pattern, regex=False)
            for match in matches[:2]:
                evidence_items.append(self._evidence_from_ast(
                    match.file_path, match.line_number, match.snippet,
                    f"Custom sanitization function: {match.name}"
                ))

        # Determine level
        if not evidence_items:
            level = ControlLevel.NONE
        elif len(evidence_items) >= 5:
            level = ControlLevel.ADVANCED
        elif len(evidence_items) >= 3:
            level = ControlLevel.INTERMEDIATE
        else:
            level = ControlLevel.BASIC

        return self._create_evidence(
            detected=len(evidence_items) > 0,
            level=level,
            evidence_items=evidence_items,
        )


class RateLimitingDetector(BaseControlDetector):
    """Detect rate limiting controls."""

    control_id = "PS-02"
    control_name = "Rate Limiting"
    category = "prompt_security"
    description = "Rate limiting on API endpoints to prevent abuse"
    recommendations = [
        "Implement rate limiting using fastapi-limiter, flask-limiter, or slowapi",
        "Configure per-user and per-endpoint rate limits",
        "Add exponential backoff for repeated violations",
    ]

    def detect(self) -> ControlEvidence:
        evidence_items: List[EvidenceItem] = []

        # Check for rate limiting libraries
        rate_limit_libs = [
            "fastapi-limiter", "flask-limiter", "slowapi",
            "ratelimit", "django-ratelimit"
        ]
        for lib in rate_limit_libs:
            if self.deps.has_package(lib):
                packages = self.deps.get_packages_by_category("rate_limiting")
                for pkg in packages:
                    evidence_items.append(self._evidence_from_dependency(
                        pkg.file_path, pkg.package_name,
                        f"Rate limiting library {pkg.package_name} found"
                    ))

        # Check for rate limit decorators
        decorator_patterns = ["ratelimit", "limiter", "throttle", "rate_limit"]
        for pattern in decorator_patterns:
            matches = self.ast.find_decorators(pattern)
            for match in matches[:3]:
                evidence_items.append(self._evidence_from_decorator(
                    match.file_path, match.line_number, match.name,
                    f"Rate limit decorator on {match.context}"
                ))

        # Check for rate limit config
        config_patterns = ["RATELIMIT", "rate_limit", "throttle", "requests_per"]
        for pattern in config_patterns:
            matches = self.config.find_key(pattern)
            for match in matches[:2]:
                evidence_items.append(self._evidence_from_config(
                    match.file_path, match.key, str(match.value),
                    "Rate limiting configuration found"
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


class InputValidationDetector(BaseControlDetector):
    """Detect input validation controls."""

    control_id = "PS-03"
    control_name = "Input Validation"
    category = "prompt_security"
    description = "Validation of user inputs using schemas or type checking"
    recommendations = [
        "Use Pydantic for request/input validation",
        "Implement JSON schema validation for API inputs",
        "Add type hints and runtime type checking",
    ]

    def detect(self) -> ControlEvidence:
        evidence_items: List[EvidenceItem] = []

        # Check for validation libraries
        validation_libs = ["pydantic", "marshmallow", "cerberus", "jsonschema", "voluptuous"]
        for lib in validation_libs:
            if self.deps.has_package(lib):
                evidence_items.append(self._evidence_from_dependency(
                    "", lib, f"Validation library {lib} found"
                ))

        # Check for Pydantic models
        pydantic_imports = self.ast.find_imports("pydantic")
        if pydantic_imports:
            evidence_items.append(self._evidence_from_import(
                pydantic_imports[0].file_path,
                pydantic_imports[0].line_number,
                "pydantic",
                "Pydantic validation library imported"
            ))

        # Check for BaseModel classes
        base_model_classes = self.ast.find_classes("Model")
        for match in base_model_classes[:3]:
            if "model" in match.name.lower():
                evidence_items.append(self._evidence_from_ast(
                    match.file_path, match.line_number, match.snippet,
                    f"Validation model class: {match.name}"
                ))

        # Check for validator decorators
        validator_decorators = self.ast.find_decorators("validator")
        for match in validator_decorators[:2]:
            evidence_items.append(self._evidence_from_decorator(
                match.file_path, match.line_number, match.name,
                "Pydantic validator decorator"
            ))

        # Determine level
        if not evidence_items:
            level = ControlLevel.NONE
        elif len(evidence_items) >= 5:
            level = ControlLevel.ADVANCED
        elif len(evidence_items) >= 3:
            level = ControlLevel.INTERMEDIATE
        else:
            level = ControlLevel.BASIC

        return self._create_evidence(
            detected=len(evidence_items) > 0,
            level=level,
            evidence_items=evidence_items,
        )


class OutputFilteringDetector(BaseControlDetector):
    """Detect output filtering controls."""

    control_id = "PS-04"
    control_name = "Output Filtering"
    category = "prompt_security"
    description = "Filtering and validation of LLM outputs before returning to users"
    recommendations = [
        "Implement output validation after receiving LLM responses",
        "Filter PII and sensitive information from outputs",
        "Add content moderation for harmful content",
    ]

    def detect(self) -> ControlEvidence:
        evidence_items: List[EvidenceItem] = []

        # Check for output filtering patterns
        filter_patterns = [
            "filter_output", "sanitize_response", "validate_output",
            "clean_response", "moderate", "check_output"
        ]
        for pattern in filter_patterns:
            matches = self.ast.find_function_calls(pattern)
            for match in matches[:3]:
                evidence_items.append(self._evidence_from_ast(
                    match.file_path, match.line_number, match.snippet,
                    f"Output filtering function: {match.name}"
                ))

        # Check for content moderation libraries
        moderation_libs = ["transformers", "detoxify", "perspective"]
        for lib in moderation_libs:
            if self.deps.has_package(lib):
                evidence_items.append(self._evidence_from_dependency(
                    "", lib, f"Content moderation capability via {lib}"
                ))

        # Check for response processing patterns
        response_patterns = ["process_response", "post_process", "format_response"]
        for pattern in response_patterns:
            matches = self.ast.find_function_calls(pattern)
            for match in matches[:2]:
                evidence_items.append(self._evidence_from_ast(
                    match.file_path, match.line_number, match.snippet,
                    f"Response processing: {match.name}"
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


class ContextProtectionDetector(BaseControlDetector):
    """Detect context window protection controls."""

    control_id = "PS-05"
    control_name = "Context Window Protection"
    category = "prompt_security"
    description = "Protection against context window exhaustion attacks"
    recommendations = [
        "Implement token counting before sending to LLM",
        "Set maximum input length limits",
        "Use tiktoken or similar for accurate token counting",
    ]

    def detect(self) -> ControlEvidence:
        evidence_items: List[EvidenceItem] = []

        # Check for tiktoken library
        if self.deps.has_package("tiktoken"):
            evidence_items.append(self._evidence_from_dependency(
                "", "tiktoken", "Token counting library tiktoken found"
            ))

        # Check for token counting imports
        tiktoken_imports = self.ast.find_imports("tiktoken")
        for match in tiktoken_imports[:2]:
            evidence_items.append(self._evidence_from_import(
                match.file_path, match.line_number, "tiktoken",
                "tiktoken imported for token counting"
            ))

        # Check for token/length limit patterns
        limit_patterns = [
            "max_tokens", "token_limit", "max_length", "truncate",
            "count_tokens", "num_tokens"
        ]
        for pattern in limit_patterns:
            # Check function calls
            matches = self.ast.find_function_calls(pattern)
            for match in matches[:2]:
                evidence_items.append(self._evidence_from_ast(
                    match.file_path, match.line_number, match.snippet,
                    f"Token/length handling: {match.name}"
                ))

            # Check config
            config_matches = self.config.find_key(pattern)
            for match in config_matches[:2]:
                evidence_items.append(self._evidence_from_config(
                    match.file_path, match.key, str(match.value),
                    f"Token limit configuration: {match.key}"
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


class RedTeamTestingDetector(BaseControlDetector):
    """Detect red team testing for prompts."""

    control_id = "PS-06"
    control_name = "Red Team Testing"
    category = "prompt_security"
    description = "Adversarial testing of prompts using red team tools"
    recommendations = [
        "Use garak or promptfoo for automated prompt testing",
        "Implement regular red team exercises for LLM prompts",
        "Document and track prompt vulnerabilities found",
    ]

    def detect(self) -> ControlEvidence:
        evidence_items: List[EvidenceItem] = []

        # Check for red team testing tools
        red_team_tools = ["garak", "promptfoo", "promptbench", "textattack"]
        for tool in red_team_tools:
            if self.deps.has_package(tool):
                evidence_items.append(self._evidence_from_dependency(
                    "", tool, f"Red team testing tool {tool} found"
                ))

        # Check for config files for these tools
        config_files = ["garak.yaml", "promptfoo.yaml", ".promptfoo"]
        for config_file in config_files:
            if self.config.file_exists(config_file):
                evidence_items.append(self._evidence_from_config(
                    config_file, "config", "exists",
                    f"Red team config file {config_file} found"
                ))

        # Check for adversarial testing patterns in code
        test_patterns = ["adversarial_test", "red_team", "attack_prompt", "jailbreak_test"]
        for pattern in test_patterns:
            matches = self.ast.find_function_calls(pattern)
            for match in matches[:2]:
                evidence_items.append(self._evidence_from_ast(
                    match.file_path, match.line_number, match.snippet,
                    f"Red team testing: {match.name}"
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


class AnomalyDetectionDetector(BaseControlDetector):
    """Detect anomaly detection on prompts."""

    control_id = "PS-07"
    control_name = "Prompt Anomaly Detection"
    category = "prompt_security"
    description = "Detection of anomalous or malicious prompts"
    recommendations = [
        "Implement statistical analysis on prompt patterns",
        "Use ML-based anomaly detection for unusual inputs",
        "Set up alerts for prompt anomaly detection",
    ]

    def detect(self) -> ControlEvidence:
        evidence_items: List[EvidenceItem] = []

        # Check for anomaly detection libraries
        anomaly_libs = ["pyod", "alibi-detect", "sklearn"]
        for lib in anomaly_libs:
            if self.deps.has_package(lib):
                # Check for anomaly-related usage
                anomaly_patterns = ["anomaly", "outlier", "IsolationForest", "LocalOutlierFactor"]
                for pattern in anomaly_patterns:
                    matches = self.ast.find_function_calls(pattern)
                    if matches:
                        evidence_items.append(self._evidence_from_dependency(
                            "", lib, f"Anomaly detection via {lib}"
                        ))
                        break

        # Check for anomaly detection patterns
        detect_patterns = [
            "detect_anomaly", "is_anomalous", "anomaly_score",
            "suspicious_prompt", "malicious_input"
        ]
        for pattern in detect_patterns:
            matches = self.ast.find_function_calls(pattern)
            for match in matches[:2]:
                evidence_items.append(self._evidence_from_ast(
                    match.file_path, match.line_number, match.snippet,
                    f"Anomaly detection: {match.name}"
                ))

        # Check for statistical checks on prompts
        stat_patterns = ["z_score", "standard_deviation", "threshold"]
        for pattern in stat_patterns:
            matches = self.ast.find_function_calls(pattern)
            for match in matches[:2]:
                evidence_items.append(self._evidence_from_ast(
                    match.file_path, match.line_number, match.snippet,
                    f"Statistical analysis: {match.name}"
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


class SystemPromptProtectionDetector(BaseControlDetector):
    """Detect system prompt protection controls."""

    control_id = "PS-08"
    control_name = "System Prompt Protection"
    category = "prompt_security"
    description = "Protection of system prompts from extraction or override"
    recommendations = [
        "Never expose system prompts in error messages or logs",
        "Implement instruction hierarchy to prevent override",
        "Monitor for system prompt extraction attempts",
    ]

    def detect(self) -> ControlEvidence:
        evidence_items: List[EvidenceItem] = []

        # Check for system prompt protection patterns
        protection_patterns = [
            "system_prompt", "SYSTEM_PROMPT", "instruction_hierarchy",
            "protect_system", "hide_instructions"
        ]
        for pattern in protection_patterns:
            # Check environment variables
            config_matches = self.config.find_key(pattern)
            for match in config_matches[:2]:
                evidence_items.append(self._evidence_from_config(
                    match.file_path, match.key, "[PROTECTED]",
                    "System prompt stored securely in config"
                ))

        # Check for extraction prevention patterns
        prevent_patterns = [
            "ignore.*previous", "do not reveal", "never disclose",
            "instruction.*override"
        ]
        for pattern in prevent_patterns:
            matches = self.ast.find_string_literals(pattern)
            for match in matches[:2]:
                evidence_items.append(self._evidence_from_ast(
                    match.file_path, match.line_number, match.snippet,
                    "System prompt protection instruction"
                ))

        # Check for secrets management usage for prompts
        secrets_patterns = ["secrets.", "vault.", "ssm.", "getenv"]
        for pattern in secrets_patterns:
            matches = self.ast.find_function_calls(pattern)
            for match in matches[:2]:
                if "prompt" in str(match.context).lower():
                    evidence_items.append(self._evidence_from_ast(
                        match.file_path, match.line_number, match.snippet,
                        f"Secure prompt storage: {match.name}"
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


class PromptSecurityControls(ControlCategory):
    """Prompt security control category."""

    category_id = "prompt_security"
    category_name = "Prompt Security"
    weight = 0.15

    def _create_detectors(self) -> List[BaseControlDetector]:
        return [
            PromptSanitizationDetector(self.ast, self.config, self.deps),
            RateLimitingDetector(self.ast, self.config, self.deps),
            InputValidationDetector(self.ast, self.config, self.deps),
            OutputFilteringDetector(self.ast, self.config, self.deps),
            ContextProtectionDetector(self.ast, self.config, self.deps),
            RedTeamTestingDetector(self.ast, self.config, self.deps),
            AnomalyDetectionDetector(self.ast, self.config, self.deps),
            SystemPromptProtectionDetector(self.ast, self.config, self.deps),
        ]
