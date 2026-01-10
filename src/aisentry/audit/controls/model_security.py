"""
Model Security control detectors.
"""

from typing import List

from ..models import ControlEvidence, ControlLevel, EvidenceItem
from .base_control import BaseControlDetector, ControlCategory


class AccessControlDetector(BaseControlDetector):
    """Detect access control on model endpoints."""

    control_id = "MS-01"
    control_name = "Access Control"
    category = "model_security"
    description = "Authentication and authorization on model API endpoints"
    recommendations = [
        "Implement authentication on all model endpoints",
        "Use OAuth 2.0 or API keys for access control",
        "Implement role-based access control (RBAC)",
    ]

    def detect(self) -> ControlEvidence:
        evidence_items: List[EvidenceItem] = []

        # Check for auth libraries
        auth_libs = [
            "pyjwt", "python-jose", "authlib", "oauthlib",
            "fastapi-users", "flask-login", "django-rest-framework"
        ]
        for lib in auth_libs:
            if self.deps.has_package(lib):
                evidence_items.append(self._evidence_from_dependency(
                    "", lib, f"Authentication library {lib} found"
                ))

        # Check for auth decorators
        auth_decorators = ["login_required", "authenticated", "requires_auth", "jwt_required", "oauth"]
        for pattern in auth_decorators:
            matches = self.ast.find_decorators(pattern)
            for match in matches[:3]:
                evidence_items.append(self._evidence_from_decorator(
                    match.file_path, match.line_number, match.name,
                    f"Auth decorator: {match.name}"
                ))

        # Check for API key patterns
        api_key_patterns = ["api_key", "apikey", "x-api-key", "authorization"]
        for pattern in api_key_patterns:
            config_matches = self.config.find_key(pattern)
            for match in config_matches[:2]:
                evidence_items.append(self._evidence_from_config(
                    match.file_path, match.key, "[REDACTED]",
                    f"API key configuration: {match.key}"
                ))

        # Check for auth middleware imports
        auth_imports = self.ast.find_imports("auth")
        for match in auth_imports[:2]:
            evidence_items.append(self._evidence_from_import(
                match.file_path, match.line_number, match.name,
                f"Auth module imported: {match.name}"
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


class ModelVersioningDetector(BaseControlDetector):
    """Detect model versioning controls."""

    control_id = "MS-02"
    control_name = "Model Versioning"
    category = "model_security"
    description = "Version control and tracking for ML models"
    recommendations = [
        "Use MLflow or DVC for model versioning",
        "Implement model registry for production models",
        "Track model lineage and metadata",
    ]

    def detect(self) -> ControlEvidence:
        evidence_items: List[EvidenceItem] = []

        # Check for versioning libraries
        versioning_libs = ["mlflow", "dvc", "wandb", "neptune", "comet-ml"]
        for lib in versioning_libs:
            if self.deps.has_package(lib):
                evidence_items.append(self._evidence_from_dependency(
                    "", lib, f"Model versioning library {lib} found"
                ))

        # Check for MLflow imports
        mlflow_imports = self.ast.find_imports("mlflow")
        for match in mlflow_imports[:2]:
            evidence_items.append(self._evidence_from_import(
                match.file_path, match.line_number, "mlflow",
                "MLflow imported for model tracking"
            ))

        # Check for DVC files
        dvc_patterns = ["*.dvc", "dvc.yaml", "dvc.lock"]
        for pattern in dvc_patterns:
            config_matches = self.config.find_key(pattern.replace("*", ""))
            if config_matches:
                evidence_items.append(self._evidence_from_file(
                    config_matches[0].file_path,
                    "DVC configuration file found"
                ))

        # Check for model version patterns
        version_patterns = ["model_version", "model_id", "register_model", "log_model"]
        for pattern in version_patterns:
            matches = self.ast.find_function_calls(pattern)
            for match in matches[:2]:
                evidence_items.append(self._evidence_from_ast(
                    match.file_path, match.line_number, match.snippet,
                    f"Model versioning function: {match.name}"
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


class DependencyScanningDetector(BaseControlDetector):
    """Detect dependency vulnerability scanning."""

    control_id = "MS-03"
    control_name = "Dependency Scanning"
    category = "model_security"
    description = "Scanning dependencies for known vulnerabilities"
    recommendations = [
        "Use safety or pip-audit for dependency scanning",
        "Integrate vulnerability scanning in CI/CD",
        "Set up automated dependency updates with Dependabot",
    ]

    def detect(self) -> ControlEvidence:
        evidence_items: List[EvidenceItem] = []

        # Check for security scanning tools
        scan_tools = ["safety", "pip-audit", "bandit", "semgrep", "snyk"]
        for tool in scan_tools:
            if self.deps.has_package(tool):
                evidence_items.append(self._evidence_from_dependency(
                    "", tool, f"Security scanning tool {tool} found"
                ))

        # Check for pre-commit config
        precommit_patterns = ["pre-commit", "pre_commit"]
        for pattern in precommit_patterns:
            if self.deps.has_package(pattern) or self.config.has_key(pattern):
                evidence_items.append(self._evidence_from_file(
                    ".pre-commit-config.yaml",
                    "Pre-commit hooks configured"
                ))
                break

        # Check for CI/CD security scanning
        ci_patterns = ["safety", "pip-audit", "bandit", "snyk"]
        for pattern in ci_patterns:
            config_matches = self.config.find_value(pattern)
            for match in config_matches[:2]:
                if "workflow" in match.file_path or "ci" in match.file_path.lower():
                    evidence_items.append(self._evidence_from_config(
                        match.file_path, match.key, str(match.value),
                        f"Security scanning in CI: {pattern}"
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


class APISecurityDetector(BaseControlDetector):
    """Detect API security controls."""

    control_id = "MS-04"
    control_name = "API Security"
    category = "model_security"
    description = "Security controls on API endpoints (TLS, headers, etc.)"
    recommendations = [
        "Enforce HTTPS for all API endpoints",
        "Implement proper CORS configuration",
        "Add security headers (CSP, HSTS, etc.)",
    ]

    def detect(self) -> ControlEvidence:
        evidence_items: List[EvidenceItem] = []

        # Check for HTTPS/TLS configuration
        tls_patterns = ["https", "ssl", "tls", "certificate"]
        for pattern in tls_patterns:
            config_matches = self.config.find_key(pattern)
            for match in config_matches[:2]:
                evidence_items.append(self._evidence_from_config(
                    match.file_path, match.key, str(match.value),
                    f"TLS/SSL configuration: {match.key}"
                ))

        # Check for CORS configuration
        cors_patterns = ["cors", "cross_origin", "access-control"]
        for pattern in cors_patterns:
            matches = self.ast.find_function_calls(pattern)
            for match in matches[:2]:
                evidence_items.append(self._evidence_from_ast(
                    match.file_path, match.line_number, match.snippet,
                    f"CORS configuration: {match.name}"
                ))

        # Check for security headers
        header_patterns = ["security_headers", "helmet", "csp", "hsts"]
        for pattern in header_patterns:
            if self.ast.has_import(pattern) or self.config.has_key(pattern):
                evidence_items.append(self._evidence_from_file(
                    "", f"Security headers configuration ({pattern})"
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


class ModelSourceVerificationDetector(BaseControlDetector):
    """Detect model source verification controls."""

    control_id = "MS-05"
    control_name = "Model Source Verification"
    category = "model_security"
    description = "Verification of model integrity via checksums or signatures"
    recommendations = [
        "Verify model checksums before loading",
        "Use cryptographic signatures for model files",
        "Download models only from trusted sources",
    ]

    def detect(self) -> ControlEvidence:
        evidence_items: List[EvidenceItem] = []

        # Check for hash/checksum usage
        hash_patterns = ["hashlib", "checksum", "sha256", "md5", "verify_hash"]
        for pattern in hash_patterns:
            matches = self.ast.find_imports(pattern)
            for match in matches[:2]:
                evidence_items.append(self._evidence_from_import(
                    match.file_path, match.line_number, match.name,
                    f"Hash verification library: {match.name}"
                ))

        # Check for verification function calls
        verify_patterns = ["verify", "validate_model", "check_integrity", "verify_signature"]
        for pattern in verify_patterns:
            matches = self.ast.find_function_calls(pattern)
            for match in matches[:2]:
                evidence_items.append(self._evidence_from_ast(
                    match.file_path, match.line_number, match.snippet,
                    f"Verification function: {match.name}"
                ))

        # Check for model loading with verification
        load_patterns = ["from_pretrained", "load_model"]
        for pattern in load_patterns:
            matches = self.ast.find_function_calls(pattern)
            for match in matches[:2]:
                # Check if revision or checksum parameter is used
                if "revision" in match.snippet or "checksum" in match.snippet:
                    evidence_items.append(self._evidence_from_ast(
                        match.file_path, match.line_number, match.snippet,
                        f"Model loading with verification: {match.name}"
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


class DifferentialPrivacyDetector(BaseControlDetector):
    """Detect differential privacy implementation."""

    control_id = "MS-06"
    control_name = "Differential Privacy"
    category = "model_security"
    description = "Differential privacy for model training and inference"
    recommendations = [
        "Use Opacus or TensorFlow Privacy for differential privacy",
        "Implement privacy budgets for model queries",
        "Monitor epsilon values for privacy guarantees",
    ]

    def detect(self) -> ControlEvidence:
        evidence_items: List[EvidenceItem] = []

        # Check for differential privacy libraries
        dp_libs = ["opacus", "tensorflow-privacy", "diffprivlib", "pydp"]
        for lib in dp_libs:
            if self.deps.has_package(lib):
                evidence_items.append(self._evidence_from_dependency(
                    "", lib, f"Differential privacy library {lib} found"
                ))

        # Check for DP patterns in code
        dp_patterns = ["PrivacyEngine", "epsilon", "privacy_budget", "differential_privacy", "dp_"]
        for pattern in dp_patterns:
            matches = self.ast.find_function_calls(pattern)
            for match in matches[:2]:
                evidence_items.append(self._evidence_from_ast(
                    match.file_path, match.line_number, match.snippet,
                    f"Differential privacy: {match.name}"
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


class ModelWatermarkingDetector(BaseControlDetector):
    """Detect model watermarking for IP protection."""

    control_id = "MS-07"
    control_name = "Model Watermarking"
    category = "model_security"
    description = "Watermarking for model intellectual property protection"
    recommendations = [
        "Implement watermarking for model outputs",
        "Use cryptographic watermarks for model weights",
        "Track watermark verification for model theft detection",
    ]

    def detect(self) -> ControlEvidence:
        evidence_items: List[EvidenceItem] = []

        # Check for watermarking libraries/patterns
        watermark_patterns = [
            "watermark", "model_signature", "embed_watermark",
            "extract_watermark", "verify_watermark"
        ]
        for pattern in watermark_patterns:
            matches = self.ast.find_function_calls(pattern)
            for match in matches[:2]:
                evidence_items.append(self._evidence_from_ast(
                    match.file_path, match.line_number, match.snippet,
                    f"Watermarking: {match.name}"
                ))

        # Check for text watermarking
        text_watermark_libs = ["watermark-gpt", "text-watermark"]
        for lib in text_watermark_libs:
            if self.deps.has_package(lib):
                evidence_items.append(self._evidence_from_dependency(
                    "", lib, f"Text watermarking library {lib} found"
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


class SecureModelLoadingDetector(BaseControlDetector):
    """Detect secure model loading practices."""

    control_id = "MS-08"
    control_name = "Secure Model Loading"
    category = "model_security"
    description = "Safe loading of model files to prevent code execution"
    recommendations = [
        "Use safetensors instead of pickle for model weights",
        "Set weights_only=True when using torch.load",
        "Validate model files before loading",
    ]

    def detect(self) -> ControlEvidence:
        evidence_items: List[EvidenceItem] = []

        # Check for safetensors library
        if self.deps.has_package("safetensors"):
            evidence_items.append(self._evidence_from_dependency(
                "", "safetensors", "Safe model loading library safetensors found"
            ))

        # Check for safe loading patterns
        safe_patterns = ["safetensors", "weights_only=True", "safe_load"]
        for pattern in safe_patterns:
            matches = self.ast.find_function_calls(pattern)
            for match in matches[:2]:
                evidence_items.append(self._evidence_from_ast(
                    match.file_path, match.line_number, match.snippet,
                    f"Safe loading: {match.name}"
                ))

        # Check for torch.load without weights_only (negative pattern)
        unsafe_patterns = self.ast.find_function_calls("torch.load")
        unsafe_count = 0
        for match in unsafe_patterns:
            if "weights_only" not in match.snippet:
                unsafe_count += 1

        if unsafe_count == 0 and unsafe_patterns:
            evidence_items.append(self._evidence_from_ast(
                "", 0, "", "All torch.load calls use safe parameters"
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


class ModelSecurityControls(ControlCategory):
    """Model security control category."""

    category_id = "model_security"
    category_name = "Model Security"
    weight = 0.12

    def _create_detectors(self) -> List[BaseControlDetector]:
        return [
            AccessControlDetector(self.ast, self.config, self.deps),
            ModelVersioningDetector(self.ast, self.config, self.deps),
            DependencyScanningDetector(self.ast, self.config, self.deps),
            APISecurityDetector(self.ast, self.config, self.deps),
            ModelSourceVerificationDetector(self.ast, self.config, self.deps),
            DifferentialPrivacyDetector(self.ast, self.config, self.deps),
            ModelWatermarkingDetector(self.ast, self.config, self.deps),
            SecureModelLoadingDetector(self.ast, self.config, self.deps),
        ]
