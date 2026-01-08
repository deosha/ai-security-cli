"""
OWASP LLM Top 10 control detectors.
"""

from typing import List

from ..models import ControlEvidence, ControlLevel, EvidenceItem
from .base_control import BaseControlDetector, ControlCategory


class LLM01PromptInjectionDetector(BaseControlDetector):
    """Detect LLM01 Prompt Injection defenses."""

    control_id = "OWASP-01"
    control_name = "LLM01: Prompt Injection Defense"
    category = "owasp_llm"
    description = "Defenses against prompt injection attacks"
    recommendations = [
        "Implement input validation and sanitization",
        "Use parameterized prompts instead of string interpolation",
        "Add output filtering to detect injected instructions",
    ]

    def detect(self) -> ControlEvidence:
        evidence_items: List[EvidenceItem] = []

        # Check for sanitization
        sanitize_patterns = ["sanitize", "escape", "filter", "clean"]
        for pattern in sanitize_patterns:
            matches = self.ast.find_function_calls(pattern)
            for match in matches[:2]:
                evidence_items.append(self._evidence_from_ast(
                    match.file_path, match.line_number, match.snippet,
                    f"Input sanitization: {match.name}"
                ))

        # Check for input validation
        if self.deps.has_package("pydantic"):
            evidence_items.append(self._evidence_from_dependency(
                "", "pydantic", "Input validation with Pydantic"
            ))

        # Check for prompt templates (safer than f-strings)
        template_patterns = ["PromptTemplate", "ChatPromptTemplate", "template"]
        for pattern in template_patterns:
            matches = self.ast.find_function_calls(pattern)
            for match in matches[:2]:
                evidence_items.append(self._evidence_from_ast(
                    match.file_path, match.line_number, match.snippet,
                    f"Prompt template usage: {match.name}"
                ))

        # Determine level based on evidence
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


class LLM02InsecureOutputDetector(BaseControlDetector):
    """Detect LLM02 Insecure Output Handling defenses."""

    control_id = "OWASP-02"
    control_name = "LLM02: Insecure Output Handling"
    category = "owasp_llm"
    description = "Validation and sanitization of LLM outputs"
    recommendations = [
        "Escape LLM output before rendering in HTML",
        "Never use eval() or exec() with LLM output",
        "Use parameterized queries for database operations",
    ]

    def detect(self) -> ControlEvidence:
        evidence_items: List[EvidenceItem] = []

        # Check for output escaping
        escape_patterns = ["escape", "html.escape", "markupsafe", "bleach"]
        for pattern in escape_patterns:
            matches = self.ast.find_function_calls(pattern)
            for match in matches[:2]:
                evidence_items.append(self._evidence_from_ast(
                    match.file_path, match.line_number, match.snippet,
                    f"Output escaping: {match.name}"
                ))

        # Check for sanitization libraries
        if self.deps.has_package("bleach"):
            evidence_items.append(self._evidence_from_dependency(
                "", "bleach", "HTML sanitization with bleach"
            ))

        if self.deps.has_package("markupsafe"):
            evidence_items.append(self._evidence_from_dependency(
                "", "markupsafe", "Safe markup handling"
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


class LLM03TrainingPoisoningDetector(BaseControlDetector):
    """Detect LLM03 Training Data Poisoning defenses."""

    control_id = "OWASP-03"
    control_name = "LLM03: Training Data Poisoning"
    category = "owasp_llm"
    description = "Validation and integrity checks for training data"
    recommendations = [
        "Implement data validation pipelines",
        "Verify data source integrity",
        "Monitor for anomalies in training data",
    ]

    def detect(self) -> ControlEvidence:
        evidence_items: List[EvidenceItem] = []

        # Check for data validation
        validation_patterns = ["validate_data", "data_validation", "quality_check"]
        for pattern in validation_patterns:
            matches = self.ast.find_function_calls(pattern)
            for match in matches[:2]:
                evidence_items.append(self._evidence_from_ast(
                    match.file_path, match.line_number, match.snippet,
                    f"Data validation: {match.name}"
                ))

        # Check for data quality libraries
        quality_libs = ["great_expectations", "pandera", "deepchecks"]
        for lib in quality_libs:
            if self.deps.has_package(lib):
                evidence_items.append(self._evidence_from_dependency(
                    "", lib, f"Data quality library: {lib}"
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


class LLM04ModelDoSDetector(BaseControlDetector):
    """Detect LLM04 Model DoS defenses."""

    control_id = "OWASP-04"
    control_name = "LLM04: Model Denial of Service"
    category = "owasp_llm"
    description = "Protection against resource exhaustion attacks"
    recommendations = [
        "Implement rate limiting on API endpoints",
        "Set maximum token limits for inputs and outputs",
        "Add timeout mechanisms for LLM calls",
    ]

    def detect(self) -> ControlEvidence:
        evidence_items: List[EvidenceItem] = []

        # Check for rate limiting
        rate_limit_libs = ["fastapi-limiter", "flask-limiter", "slowapi", "ratelimit"]
        for lib in rate_limit_libs:
            if self.deps.has_package(lib):
                evidence_items.append(self._evidence_from_dependency(
                    "", lib, f"Rate limiting: {lib}"
                ))

        # Check for timeout configuration
        timeout_patterns = ["timeout", "max_tokens", "token_limit"]
        for pattern in timeout_patterns:
            config_matches = self.config.find_key(pattern)
            for match in config_matches[:2]:
                evidence_items.append(self._evidence_from_config(
                    match.file_path, match.key, str(match.value),
                    f"Resource limit: {match.key}"
                ))

        # Check for rate limit decorators
        limit_decorators = ["ratelimit", "limiter", "throttle"]
        for pattern in limit_decorators:
            matches = self.ast.find_decorators(pattern)
            for match in matches[:2]:
                evidence_items.append(self._evidence_from_decorator(
                    match.file_path, match.line_number, match.name,
                    f"Rate limiting decorator"
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


class LLM05SupplyChainDetector(BaseControlDetector):
    """Detect LLM05 Supply Chain defenses."""

    control_id = "OWASP-05"
    control_name = "LLM05: Supply Chain Vulnerabilities"
    category = "owasp_llm"
    description = "Verification of model and dependency sources"
    recommendations = [
        "Scan dependencies for vulnerabilities",
        "Verify model checksums before loading",
        "Use only trusted model sources",
    ]

    def detect(self) -> ControlEvidence:
        evidence_items: List[EvidenceItem] = []

        # Check for security scanning tools
        scan_tools = ["safety", "pip-audit", "bandit", "snyk"]
        for tool in scan_tools:
            if self.deps.has_package(tool):
                evidence_items.append(self._evidence_from_dependency(
                    "", tool, f"Security scanner: {tool}"
                ))

        # Check for checksum verification
        hash_patterns = ["hashlib", "checksum", "verify"]
        for pattern in hash_patterns:
            matches = self.ast.find_imports(pattern)
            for match in matches[:2]:
                evidence_items.append(self._evidence_from_import(
                    match.file_path, match.line_number, match.name,
                    f"Integrity verification: {match.name}"
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


class LLM06SensitiveInfoDetector(BaseControlDetector):
    """Detect LLM06 Sensitive Information Disclosure defenses."""

    control_id = "OWASP-06"
    control_name = "LLM06: Sensitive Information Disclosure"
    category = "owasp_llm"
    description = "Protection against data leakage"
    recommendations = [
        "Implement PII detection and filtering",
        "Never include secrets in prompts",
        "Add output filtering for sensitive patterns",
    ]

    def detect(self) -> ControlEvidence:
        evidence_items: List[EvidenceItem] = []

        # Check for PII detection
        pii_libs = ["presidio", "scrubadub", "spacy"]
        for lib in pii_libs:
            if self.deps.has_package(lib):
                evidence_items.append(self._evidence_from_dependency(
                    "", lib, f"PII detection: {lib}"
                ))

        # Check for secret detection
        secret_patterns = ["detect_secrets", "secret", "credential"]
        for pattern in secret_patterns:
            if self.deps.has_package(pattern):
                evidence_items.append(self._evidence_from_dependency(
                    "", pattern, f"Secret detection"
                ))

        # Check for filtering functions
        filter_patterns = ["filter_pii", "redact", "mask", "sanitize"]
        for pattern in filter_patterns:
            matches = self.ast.find_function_calls(pattern)
            for match in matches[:2]:
                evidence_items.append(self._evidence_from_ast(
                    match.file_path, match.line_number, match.snippet,
                    f"Data filtering: {match.name}"
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


class LLM07InsecurePluginDetector(BaseControlDetector):
    """Detect LLM07 Insecure Plugin Design defenses."""

    control_id = "OWASP-07"
    control_name = "LLM07: Insecure Plugin Design"
    category = "owasp_llm"
    description = "Security controls for LLM plugins and tools"
    recommendations = [
        "Validate all inputs to plugins",
        "Implement allowlists for permitted operations",
        "Sandbox plugin execution environments",
    ]

    def detect(self) -> ControlEvidence:
        evidence_items: List[EvidenceItem] = []

        # Check for input validation on tools
        validation_patterns = ["validate", "check_input", "allowed_operations"]
        for pattern in validation_patterns:
            matches = self.ast.find_function_calls(pattern)
            for match in matches[:2]:
                evidence_items.append(self._evidence_from_ast(
                    match.file_path, match.line_number, match.snippet,
                    f"Plugin validation: {match.name}"
                ))

        # Check for sandboxing
        sandbox_patterns = ["sandbox", "restrict", "permission"]
        for pattern in sandbox_patterns:
            matches = self.ast.find_function_calls(pattern)
            for match in matches[:2]:
                evidence_items.append(self._evidence_from_ast(
                    match.file_path, match.line_number, match.snippet,
                    f"Sandboxing: {match.name}"
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


class LLM08ExcessiveAgencyDetector(BaseControlDetector):
    """Detect LLM08 Excessive Agency defenses."""

    control_id = "OWASP-08"
    control_name = "LLM08: Excessive Agency"
    category = "owasp_llm"
    description = "Controls limiting LLM autonomy and permissions"
    recommendations = [
        "Implement human-in-the-loop for critical actions",
        "Use principle of least privilege for LLM access",
        "Add approval workflows for sensitive operations",
    ]

    def detect(self) -> ControlEvidence:
        evidence_items: List[EvidenceItem] = []

        # Check for approval/confirmation patterns
        approval_patterns = [
            "require_approval", "human_review", "confirm",
            "approval_required", "human_in_the_loop"
        ]
        for pattern in approval_patterns:
            matches = self.ast.find_function_calls(pattern)
            for match in matches[:2]:
                evidence_items.append(self._evidence_from_ast(
                    match.file_path, match.line_number, match.snippet,
                    f"Approval workflow: {match.name}"
                ))

        # Check for permission checks
        permission_patterns = ["check_permission", "authorize", "has_permission"]
        for pattern in permission_patterns:
            matches = self.ast.find_function_calls(pattern)
            for match in matches[:2]:
                evidence_items.append(self._evidence_from_ast(
                    match.file_path, match.line_number, match.snippet,
                    f"Permission check: {match.name}"
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


class LLM09OverrelianceDetector(BaseControlDetector):
    """Detect LLM09 Overreliance defenses."""

    control_id = "OWASP-09"
    control_name = "LLM09: Overreliance"
    category = "owasp_llm"
    description = "Safeguards against over-trusting LLM outputs"
    recommendations = [
        "Add confidence scores to LLM outputs",
        "Implement human review for critical decisions",
        "Provide source citations where possible",
    ]

    def detect(self) -> ControlEvidence:
        evidence_items: List[EvidenceItem] = []

        # Check for confidence scoring
        confidence_patterns = ["confidence", "score", "certainty", "probability"]
        for pattern in confidence_patterns:
            matches = self.ast.find_function_calls(pattern)
            for match in matches[:2]:
                evidence_items.append(self._evidence_from_ast(
                    match.file_path, match.line_number, match.snippet,
                    f"Confidence scoring: {match.name}"
                ))

        # Check for verification patterns
        verify_patterns = ["verify", "fact_check", "validate_output", "review"]
        for pattern in verify_patterns:
            matches = self.ast.find_function_calls(pattern)
            for match in matches[:2]:
                evidence_items.append(self._evidence_from_ast(
                    match.file_path, match.line_number, match.snippet,
                    f"Output verification: {match.name}"
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


class LLM10ModelTheftDetector(BaseControlDetector):
    """Detect LLM10 Model Theft defenses."""

    control_id = "OWASP-10"
    control_name = "LLM10: Model Theft"
    category = "owasp_llm"
    description = "Protection against model extraction attacks"
    recommendations = [
        "Implement rate limiting on API endpoints",
        "Add query logging and anomaly detection",
        "Monitor for extraction patterns",
    ]

    def detect(self) -> ControlEvidence:
        evidence_items: List[EvidenceItem] = []

        # Check for rate limiting (also helps prevent extraction)
        rate_limit_libs = ["fastapi-limiter", "flask-limiter", "slowapi"]
        for lib in rate_limit_libs:
            if self.deps.has_package(lib):
                evidence_items.append(self._evidence_from_dependency(
                    "", lib, f"Rate limiting: {lib}"
                ))

        # Check for logging/monitoring
        logging_libs = ["structlog", "loguru", "sentry-sdk"]
        for lib in logging_libs:
            if self.deps.has_package(lib):
                evidence_items.append(self._evidence_from_dependency(
                    "", lib, f"Monitoring: {lib}"
                ))

        # Check for anomaly detection
        anomaly_patterns = ["anomaly", "detect_abuse", "suspicious"]
        for pattern in anomaly_patterns:
            matches = self.ast.find_function_calls(pattern)
            for match in matches[:2]:
                evidence_items.append(self._evidence_from_ast(
                    match.file_path, match.line_number, match.snippet,
                    f"Anomaly detection: {match.name}"
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


class OWASPLLMControls(ControlCategory):
    """OWASP LLM Top 10 control category."""

    category_id = "owasp_llm"
    category_name = "OWASP LLM Top 10"
    weight = 0.15

    def _create_detectors(self) -> List[BaseControlDetector]:
        return [
            LLM01PromptInjectionDetector(self.ast, self.config, self.deps),
            LLM02InsecureOutputDetector(self.ast, self.config, self.deps),
            LLM03TrainingPoisoningDetector(self.ast, self.config, self.deps),
            LLM04ModelDoSDetector(self.ast, self.config, self.deps),
            LLM05SupplyChainDetector(self.ast, self.config, self.deps),
            LLM06SensitiveInfoDetector(self.ast, self.config, self.deps),
            LLM07InsecurePluginDetector(self.ast, self.config, self.deps),
            LLM08ExcessiveAgencyDetector(self.ast, self.config, self.deps),
            LLM09OverrelianceDetector(self.ast, self.config, self.deps),
            LLM10ModelTheftDetector(self.ast, self.config, self.deps),
        ]
