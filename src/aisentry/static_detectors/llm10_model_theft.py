"""
LLM10: Model Theft Detector

Detects vulnerabilities that could lead to unauthorized access to ML models.
"""

from typing import Any, Dict, List

from aisentry.models.finding import Severity
from aisentry.static_detectors.base_detector import BaseDetector, Finding


class ModelTheftDetector(BaseDetector):
    """
    Detects model theft vulnerabilities

    Key vulnerabilities:
    1. Unrestricted API access without rate limiting
    2. Model artifacts exposed without access control
    3. Missing monitoring for extraction attempts
    4. Lack of output obfuscation/watermarking
    """

    detector_id = "LLM10"
    name = "Model Theft"

    # Model access patterns
    MODEL_ACCESS_PATTERNS = [
        'load_model', 'torch.load', 'tf.keras.models.load_model',
        'joblib.load', 'pickle.load', 'model.load', 'from_pretrained',
        'model.predict', 'model.generate', 'model.forward',
        'inference', 'predict', 'generate'
    ]

    # API endpoint patterns
    API_PATTERNS = [
        '@app.route', '@api.route', '@app.post', '@app.get',
        'app.route', 'api.route', 'app.post', 'app.get',  # Without @ for parsed decorators
        'router.get', 'router.post',
        'FastAPI', 'Flask', 'create_app', 'APIRouter'
    ]

    # Rate limiting patterns
    RATE_LIMIT_PATTERNS = [
        'rate_limit', 'ratelimit', 'limiter', 'throttle',
        '@limiter', 'RateLimiter', 'rate_limiter'
    ]

    # Authentication patterns
    AUTH_PATTERNS = [
        'authenticate', 'authorization', 'check_auth', 'require_auth',
        '@login_required', '@auth_required', 'verify_token',
        'check_permission', 'api_key', 'bearer'
    ]

    # Monitoring patterns
    MONITORING_PATTERNS = [
        'log_access', 'audit_log', 'track_usage', 'monitor',
        'logging', 'logger.info', 'logger.warning'
    ]

    # Model artifact patterns
    MODEL_ARTIFACT_PATTERNS = {
        'pytorch': ['.pt', '.pth', 'torch.save', 'state_dict'],
        'tensorflow': ['.h5', '.pb', 'save_model', 'SavedModel'],
        'sklearn': ['.pkl', 'joblib.dump', 'pickle.dump'],
        'huggingface': ['save_pretrained', 'push_to_hub']
    }

    # Sensitive model info patterns
    SENSITIVE_INFO = [
        'model_weights', 'parameters', 'architecture',
        'training_data', 'hyperparameters', 'config'
    ]

    # Watermarking/protection patterns
    PROTECTION_PATTERNS = [
        'watermark', 'fingerprint', 'obfuscate',
        'differential_privacy', 'noise', 'perturbation'
    ]

    def _gather_potential_findings(self, parsed_data: Dict[str, Any]) -> List[Finding]:
        """Gather all potential model theft findings"""
        findings = []

        findings.extend(self._check_unrestricted_api(parsed_data))
        findings.extend(self._check_exposed_model_artifacts(parsed_data))
        findings.extend(self._check_missing_monitoring(parsed_data))
        findings.extend(self._check_missing_protection(parsed_data))

        return findings

    def calculate_confidence(self, evidence: Dict[str, Any]) -> float:
        """Calculate confidence based on evidence"""
        confidence_scores = [0.7]  # Base confidence

        # High confidence for exposed APIs without rate limiting
        if evidence.get('is_api_endpoint') and not evidence.get('has_rate_limiting'):
            confidence_scores.append(0.85)

        # High confidence for exposed model files
        if evidence.get('exposes_model_artifacts') and not evidence.get('has_access_control'):
            confidence_scores.append(0.9)

        # Medium-high for missing monitoring
        if evidence.get('is_api_endpoint') and not evidence.get('has_monitoring'):
            confidence_scores.append(0.75)

        # Medium for missing protection
        if not evidence.get('has_protection'):
            confidence_scores.append(0.65)

        return min(max(confidence_scores), 1.0)

    def _check_unrestricted_api(self, parsed_data: Dict[str, Any]) -> List[Finding]:
        """Check for unrestricted API access to model"""
        findings = []
        functions = parsed_data.get('functions', [])
        source_lines = parsed_data.get('source_lines', [])
        llm_calls = parsed_data.get('llm_api_calls', [])

        # Map LLM calls to their locations
        llm_call_lines = {call.get('line', 0) for call in llm_calls}

        for func in functions:
            func_name = func.get('name', '').lower()
            func_start = func.get('line', 0)
            func_end = func.get('end_line', func_start + 10)

            # Get function body
            func_body = '\n'.join(source_lines[func_start-1:func_end])
            func_lower = func_body.lower()

            # Check if this is an API endpoint (check decorators)
            decorators = func.get('decorators', [])
            decorators_str = ' '.join(decorators).lower()
            is_api_endpoint = any(
                pattern.lower() in decorators_str or pattern.lower() in func_lower
                for pattern in self.API_PATTERNS
            )

            if not is_api_endpoint:
                continue

            # Check if it accesses LLM/model
            has_llm_call = any(func_start <= line <= func_end for line in llm_call_lines)
            has_model_access = any(
                pattern in func_lower for pattern in self.MODEL_ACCESS_PATTERNS
            )

            if not (has_llm_call or has_model_access):
                continue

            # Check for rate limiting (check both decorators and function body)
            has_rate_limiting = any(
                pattern in func_lower or pattern in decorators_str
                for pattern in self.RATE_LIMIT_PATTERNS
            )

            # Check for authentication (check both decorators and function body)
            has_auth = any(
                pattern in func_lower or pattern in decorators_str
                for pattern in self.AUTH_PATTERNS
            )

            # Check for monitoring
            has_monitoring = any(
                pattern in func_lower for pattern in self.MONITORING_PATTERNS
            )

            # Create finding if API lacks proper protections
            if not has_rate_limiting:
                severity = Severity.HIGH if not has_auth else Severity.MEDIUM

                finding = Finding(
                    id=f"{self.detector_id}_{parsed_data.get('file_path', '')}_{func_start}_unrestricted_api",
                    category=f"{self.detector_id}: {self.name}",
                    severity=severity,
                    confidence=0.0,  # Will be set by BaseDetector
                    title=f"Model API without rate limiting in '{func.get('name')}'",
                    description=(
                        f"API endpoint '{func.get('name')}' on line {func_start} provides model access "
                        f"without rate limiting. This allows attackers to make unlimited queries to extract "
                        f"model knowledge, potentially stealing intellectual property or sensitive training data."
                    ),
                    file_path=parsed_data.get('file_path', ''),
                    line_number=func_start,
                    code_snippet=self._get_code_snippet(source_lines, func_start, context=3),
                    recommendation=self._get_rate_limiting_recommendation(),
                    evidence={
                        'function_name': func.get('name'),
                        'is_api_endpoint': True,
                        'has_rate_limiting': False,
                        'has_authentication': has_auth,
                        'has_monitoring': has_monitoring
                    }
                )
                findings.append(finding)

        return findings

    def _check_exposed_model_artifacts(self, parsed_data: Dict[str, Any]) -> List[Finding]:
        """Check for exposed model files/artifacts"""
        findings = []
        functions = parsed_data.get('functions', [])
        source_lines = parsed_data.get('source_lines', [])

        for func in functions:
            func_name = func.get('name', '').lower()
            func_start = func.get('line', 0)
            func_end = func.get('end_line', func_start + 10)

            # Get function body
            func_body = '\n'.join(source_lines[func_start-1:func_end])
            func_lower = func_body.lower()

            # Get decorators
            decorators = func.get('decorators', [])
            decorators_str = ' '.join(decorators).lower()

            # Check if function exposes model artifacts
            artifact_types = []
            for framework, patterns in self.MODEL_ARTIFACT_PATTERNS.items():
                if any(pattern in func_lower for pattern in patterns):
                    artifact_types.append(framework)

            if not artifact_types:
                continue

            # Check if this is a save/export/push function
            is_save_function = any(
                keyword in func_name for keyword in ['save', 'export', 'dump', 'download', 'push']
            )

            if not is_save_function:
                continue

            # Check for access control (check both decorators and function body)
            has_access_control = any(
                pattern in func_lower or pattern in decorators_str
                for pattern in self.AUTH_PATTERNS
            )

            # Check if path is hardcoded or exposed
            exposes_path = any(
                keyword in func_lower for keyword in ['static', 'public', '/tmp', 'uploads']
            )

            if not has_access_control or exposes_path:
                severity = Severity.CRITICAL if exposes_path else Severity.HIGH

                finding = Finding(
                    id=f"{self.detector_id}_{parsed_data.get('file_path', '')}_{func_start}_exposed_artifacts",
                    category=f"{self.detector_id}: {self.name}",
                    severity=severity,
                    confidence=0.0,  # Will be set by BaseDetector
                    title=f"Model artifacts exposed without protection in '{func.get('name')}'",
                    description=(
                        f"Function '{func.get('name')}' on line {func_start} exposes {', '.join(artifact_types)} "
                        f"model artifacts without proper access control. This allows unauthorized users to "
                        f"download the full model, stealing intellectual property and training data."
                    ),
                    file_path=parsed_data.get('file_path', ''),
                    line_number=func_start,
                    code_snippet=self._get_code_snippet(source_lines, func_start, context=3),
                    recommendation=self._get_artifact_protection_recommendation(),
                    evidence={
                        'function_name': func.get('name'),
                        'exposes_model_artifacts': True,
                        'artifact_types': artifact_types,
                        'has_access_control': has_access_control,
                        'exposes_path': exposes_path
                    }
                )
                findings.append(finding)

        return findings

    def _check_missing_monitoring(self, parsed_data: Dict[str, Any]) -> List[Finding]:
        """Check for missing monitoring of model access"""
        findings = []
        functions = parsed_data.get('functions', [])
        source_lines = parsed_data.get('source_lines', [])
        llm_calls = parsed_data.get('llm_api_calls', [])

        # Map LLM calls to their locations
        llm_call_lines = {call.get('line', 0) for call in llm_calls}

        for func in functions:
            func_name = func.get('name', '').lower()
            func_start = func.get('line', 0)
            func_end = func.get('end_line', func_start + 10)

            # Get function body
            func_body = '\n'.join(source_lines[func_start-1:func_end])
            func_lower = func_body.lower()

            # Get decorators
            decorators = func.get('decorators', [])
            decorators_str = ' '.join(decorators).lower()

            # Check if this is an API endpoint with model access (check decorators)
            is_api_endpoint = any(
                pattern.lower() in decorators_str or pattern.lower() in func_lower
                for pattern in self.API_PATTERNS
            )

            if not is_api_endpoint:
                continue

            has_llm_call = any(func_start <= line <= func_end for line in llm_call_lines)
            if not has_llm_call:
                continue

            # Check for monitoring
            has_monitoring = any(
                pattern in func_lower for pattern in self.MONITORING_PATTERNS
            )

            # Check if sensitive info is being accessed
            accesses_sensitive = any(
                pattern in func_lower for pattern in self.SENSITIVE_INFO
            )

            if not has_monitoring and accesses_sensitive:
                finding = Finding(
                    id=f"{self.detector_id}_{parsed_data.get('file_path', '')}_{func_start}_missing_monitoring",
                    category=f"{self.detector_id}: {self.name}",
                    severity=Severity.MEDIUM,
                    confidence=0.0,  # Will be set by BaseDetector
                    title=f"Model access without monitoring in '{func.get('name')}'",
                    description=(
                        f"API endpoint '{func.get('name')}' on line {func_start} accesses model without "
                        f"monitoring or logging. This prevents detection of extraction attempts, "
                        f"making model theft difficult to identify and prevent."
                    ),
                    file_path=parsed_data.get('file_path', ''),
                    line_number=func_start,
                    code_snippet=self._get_code_snippet(source_lines, func_start, context=3),
                    recommendation=self._get_monitoring_recommendation(),
                    evidence={
                        'function_name': func.get('name'),
                        'is_api_endpoint': True,
                        'has_monitoring': False,
                        'accesses_sensitive_info': accesses_sensitive
                    }
                )
                findings.append(finding)

        return findings

    def _check_missing_protection(self, parsed_data: Dict[str, Any]) -> List[Finding]:
        """Check for missing output protection mechanisms"""
        findings = []
        functions = parsed_data.get('functions', [])
        source_lines = parsed_data.get('source_lines', [])
        llm_calls = parsed_data.get('llm_api_calls', [])

        # Map LLM calls to their locations
        llm_call_lines = {call.get('line', 0) for call in llm_calls}

        for func in functions:
            func_name = func.get('name', '').lower()
            func_start = func.get('line', 0)
            func_end = func.get('end_line', func_start + 10)

            # Get function body
            func_body = '\n'.join(source_lines[func_start-1:func_end])
            func_lower = func_body.lower()

            # Check if this is an API endpoint (check decorators)
            decorators = func.get('decorators', [])
            decorators_str = ' '.join(decorators).lower()
            is_api_endpoint = any(
                pattern.lower() in decorators_str or pattern.lower() in func_lower
                for pattern in self.API_PATTERNS
            )

            if not is_api_endpoint:
                continue

            # Check if it returns model output
            has_llm_call = any(func_start <= line <= func_end for line in llm_call_lines)
            returns_output = 'return' in func_lower and has_llm_call

            if not returns_output:
                continue

            # Check for protection mechanisms
            has_protection = any(
                pattern in func_lower for pattern in self.PROTECTION_PATTERNS
            )

            # This is a LOW severity issue - output protection is nice to have
            if not has_protection:
                finding = Finding(
                    id=f"{self.detector_id}_{parsed_data.get('file_path', '')}_{func_start}_missing_protection",
                    category=f"{self.detector_id}: {self.name}",
                    severity=Severity.LOW,
                    confidence=0.0,  # Will be set by BaseDetector
                    title=f"Model output without protection in '{func.get('name')}'",
                    description=(
                        f"API endpoint '{func.get('name')}' on line {func_start} returns model output "
                        f"without watermarking or obfuscation. Consider adding output protection "
                        f"to make model extraction more difficult and traceable."
                    ),
                    file_path=parsed_data.get('file_path', ''),
                    line_number=func_start,
                    code_snippet=self._get_code_snippet(source_lines, func_start, context=3),
                    recommendation=self._get_protection_recommendation(),
                    evidence={
                        'function_name': func.get('name'),
                        'returns_output': True,
                        'has_protection': False
                    }
                )
                findings.append(finding)

        return findings

    def _get_code_snippet(
        self,
        source_lines: List[str],
        line_num: int,
        context: int = 3
    ) -> str:
        """Get code snippet with context"""
        start = max(0, line_num - context)
        end = min(len(source_lines), line_num + context)
        return '\n'.join(source_lines[start:end])

    def _get_rate_limiting_recommendation(self) -> str:
        """Get recommendation for rate limiting"""
        return """Implement rate limiting to prevent model extraction:

1. Add rate limiting:
   - Use Flask-Limiter, fastapi-limiter, or similar
   - Set per-IP and per-user limits
   - Example: @limiter.limit("100/hour")

2. Implement request quotas:
   - Track API usage per user
   - Enforce monthly/daily quotas
   - Alert on suspicious patterns

3. Add authentication:
   - Require API keys for access
   - Track usage by authenticated user
   - Revoke keys for abuse

4. Monitor for extraction attempts:
   - Log all requests with metadata
   - Detect unusual query patterns
   - Alert on high-frequency access

5. Implement CAPTCHA:
   - For public endpoints
   - Triggered after N requests
   - Prevents automated extraction"""

    def _get_artifact_protection_recommendation(self) -> str:
        """Get recommendation for protecting model artifacts"""
        return """Protect model artifacts from unauthorized access:

1. Implement strict access control:
   - Require authentication for model downloads
   - Use role-based access control (RBAC)
   - Log all artifact access attempts

2. Store artifacts securely:
   - Use private S3 buckets with signed URLs
   - Never store in /static or /public directories
   - Encrypt at rest and in transit

3. Model obfuscation:
   - Use model encryption
   - Implement model quantization
   - Remove unnecessary metadata

4. Add legal protection:
   - Include license files with models
   - Add watermarks to model outputs
   - Use model fingerprinting

5. Monitor access:
   - Track who downloads models
   - Alert on unauthorized access
   - Maintain audit logs"""

    def _get_monitoring_recommendation(self) -> str:
        """Get recommendation for monitoring"""
        return """Implement monitoring to detect extraction attempts:

1. Log all model access:
   - Request metadata (IP, user, timestamp)
   - Query patterns and frequency
   - Response characteristics

2. Anomaly detection:
   - Unusual query patterns
   - High-frequency requests from single source
   - Systematic probing of model boundaries

3. Set up alerts:
   - Threshold-based alerts (requests/hour)
   - Pattern-based alerts (systematic extraction)
   - Geographic anomalies

4. Response analysis:
   - Track what outputs are returned
   - Detect if sensitive info is leaked
   - Monitor for data exfiltration patterns

5. Implement honeypots:
   - Fake endpoints to detect scanners
   - Canary tokens in responses
   - Deception techniques"""

    def _get_protection_recommendation(self) -> str:
        """Get recommendation for output protection"""
        return """Add output protection mechanisms:

1. Watermarking:
   - Embed invisible markers in outputs
   - Make responses traceable
   - Detect if outputs are reused

2. Output obfuscation:
   - Add controlled noise to predictions
   - Implement differential privacy
   - Return confidence ranges not exact values

3. Response filtering:
   - Limit information in responses
   - Remove sensitive metadata
   - Aggregate results when possible

4. Query restrictions:
   - Limit types of allowed queries
   - Block probing/extraction patterns
   - Implement query complexity limits

5. Legal notices:
   - Include usage terms in responses
   - Add copyright notices
   - Document intended use only"""
