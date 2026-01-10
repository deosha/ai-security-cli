"""
LLM07: Insecure Plugin Design Detector

Detects security issues in LLM plugin/extension implementations:
1. Plugin input validation failures
2. Missing authentication/authorization for plugins
3. Unsafe plugin loading mechanisms
4. Plugin privilege escalation risks
5. Missing plugin sandboxing
6. Inadequate plugin output validation

References:
- OWASP LLM07: https://owasp.org/www-project-top-10-for-large-language-model-applications/
"""

import logging
from typing import Any, Dict, List

from ai_security.models.finding import Finding, Severity
from ai_security.static_detectors.base_detector import BaseDetector

logger = logging.getLogger(__name__)


class InsecurePluginDetector(BaseDetector):
    """
    Detect LLM07: Insecure Plugin Design vulnerabilities

    Identifies security issues in plugin implementations:
    - Missing input validation for plugin parameters
    - Insufficient authentication/authorization
    - Unsafe plugin loading (dynamic imports, eval)
    - Missing sandboxing for plugin execution
    - Inadequate error handling
    """

    detector_id = "LLM07"
    name = "Insecure Plugin Design"
    default_confidence_threshold = 0.6

    # Plugin-related patterns
    PLUGIN_PATTERNS = {
        'plugin_registration': [
            'register_plugin', 'add_plugin', 'load_plugin',
            'plugin_loader', 'install_plugin', 'enable_plugin'
        ],
        'plugin_execution': [
            'execute_plugin', 'run_plugin', 'call_plugin',
            'invoke_plugin', 'plugin.run', 'plugin.execute'
        ],
        'dynamic_loading': [
            '__import__', 'importlib.import_module', 'import_module',
            'exec(', 'eval(', 'compile('
        ]
    }

    # Validation patterns (positive indicators)
    VALIDATION_PATTERNS = [
        'validate', 'check', 'verify', 'sanitize',
        'is_valid', 'validate_input', 'validate_params',
        'check_type', 'schema', 'pydantic', 'marshmallow'
    ]

    # Authentication/Authorization patterns
    AUTH_PATTERNS = [
        'authenticate', 'authorize', 'check_permission',
        'require_auth', 'verify_token', 'check_access',
        'permission_required', 'login_required'
    ]

    # Sandboxing patterns
    SANDBOX_PATTERNS = [
        'sandbox', 'isolated', 'container', 'jail',
        'chroot', 'seccomp', 'namespace', 'restricted'
    ]

    # Error handling patterns
    ERROR_HANDLING_PATTERNS = [
        'try:', 'except', 'catch', 'error_handler',
        'handle_error', 'on_error'
    ]

    # High-risk plugin operations
    HIGH_RISK_OPERATIONS = {
        'file_system': ['open(', 'read', 'write', 'os.path', 'pathlib'],
        'network': ['requests.', 'urllib', 'socket', 'httpx'],
        'execution': ['subprocess', 'os.system', 'exec', 'eval'],
        'database': ['execute', 'query', 'cursor', 'connection']
    }

    def _gather_potential_findings(self, parsed_data: Dict[str, Any]) -> List[Finding]:
        """
        Gather all potential insecure plugin vulnerabilities

        Args:
            parsed_data: Parsed code structure from AST parser

        Returns:
            List of Finding objects (before confidence filtering)
        """
        findings = []

        # Check for plugin registration without validation
        registration_findings = self._check_plugin_registration(parsed_data)
        findings.extend(registration_findings)

        # Check for dynamic plugin loading
        loading_findings = self._check_dynamic_loading(parsed_data)
        findings.extend(loading_findings)

        # Check for plugin execution without sandboxing
        execution_findings = self._check_plugin_execution(parsed_data)
        findings.extend(execution_findings)

        # Check for missing authentication on plugin endpoints
        auth_findings = self._check_plugin_authentication(parsed_data)
        findings.extend(auth_findings)

        return findings

    def calculate_confidence(self, evidence: Dict[str, Any]) -> float:
        """
        Calculate confidence based on evidence

        High confidence (0.8-1.0):
        - Dynamic loading without validation
        - Missing authentication on plugin endpoints

        Medium confidence (0.6-0.8):
        - Missing input validation
        - No sandboxing detected

        Args:
            evidence: Evidence dictionary from finding

        Returns:
            Confidence score (0.0-1.0)
        """
        confidence = 0.7  # Base confidence

        # Collect all confidence scores and take the maximum
        confidence_scores = [confidence]

        # High confidence for dynamic loading
        if evidence.get('uses_dynamic_loading'):
            confidence_scores.append(0.85)

        # High confidence for missing auth
        if 'has_authentication' in evidence and not evidence['has_authentication']:
            confidence_scores.append(0.75)

        # Medium-high for missing validation
        if 'has_validation' in evidence and not evidence['has_validation']:
            confidence_scores.append(0.70)

        # Medium for missing sandboxing
        if 'has_sandboxing' in evidence and not evidence['has_sandboxing']:
            confidence_scores.append(0.65)

        return min(max(confidence_scores), 1.0)

    def _check_plugin_registration(self, parsed_data: Dict[str, Any]) -> List[Finding]:
        """Check for plugin registration without proper validation"""
        findings = []
        functions = parsed_data.get('functions', [])
        source_lines = parsed_data.get('source_lines', [])

        for func in functions:
            func_name = func.get('name', '').lower()
            func_start = func.get('line', 0)
            func_end = func.get('end_line', func_start + 10)

            # Check if this is a plugin registration function
            is_plugin_registration = any(
                pattern in func_name
                for pattern in self.PLUGIN_PATTERNS['plugin_registration']
            )

            if not is_plugin_registration:
                continue

            # Get function body
            func_body = '\n'.join(source_lines[func_start-1:func_end])
            func_lower = func_body.lower()

            # Check for input validation
            has_validation = any(
                pattern in func_lower
                for pattern in self.VALIDATION_PATTERNS
            )

            # Check for authentication
            has_auth = any(
                pattern in func_lower
                for pattern in self.AUTH_PATTERNS
            )

            if not has_validation:
                severity = Severity.HIGH if not has_auth else Severity.MEDIUM

                finding = Finding(
                    id=f"{self.detector_id}_{parsed_data.get('file_path', '')}_{func_start}_registration",
                    category=f"{self.detector_id}: {self.name}",
                    severity=severity,
                    confidence=0.0,  # Will be set by BaseDetector
                    title=f"Plugin registration without input validation in '{func.get('name')}'",
                    description=(
                        f"Function '{func.get('name')}' on line {func_start} registers or loads plugins "
                        f"without implementing input validation. This allows malicious plugins to be loaded "
                        f"with arbitrary parameters, potentially leading to code injection, privilege escalation, "
                        f"or system compromise."
                    ),
                    file_path=parsed_data.get('file_path', ''),
                    line_number=func_start,
                    code_snippet=self._get_code_snippet(source_lines, func_start, context=3),
                    recommendation=self._get_validation_recommendation(),
                    evidence={
                        'function_name': func.get('name'),
                        'has_validation': False,
                        'has_authentication': has_auth
                    }
                )
                findings.append(finding)

        return findings

    def _check_dynamic_loading(self, parsed_data: Dict[str, Any]) -> List[Finding]:
        """Check for unsafe dynamic plugin loading"""
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

            # Check if function uses dynamic loading
            uses_dynamic_loading = any(
                pattern in func_lower
                for pattern in self.PLUGIN_PATTERNS['dynamic_loading']
            )

            if not uses_dynamic_loading:
                continue

            # Check if it's plugin-related
            is_plugin_related = (
                'plugin' in func_name or 'plugin' in func_lower or
                'extension' in func_name or 'extension' in func_lower
            )

            if not is_plugin_related:
                continue

            # Check for validation
            has_validation = any(
                pattern in func_lower
                for pattern in self.VALIDATION_PATTERNS
            )

            if not has_validation:
                finding = Finding(
                    id=f"{self.detector_id}_{parsed_data.get('file_path', '')}_{func_start}_dynamic",
                    category=f"{self.detector_id}: {self.name}",
                    severity=Severity.CRITICAL,
                    confidence=0.0,  # Will be set by BaseDetector
                    title=f"Unsafe dynamic plugin loading in '{func.get('name')}'",
                    description=(
                        f"Function '{func.get('name')}' on line {func_start} uses dynamic loading "
                        f"(__import__, eval, exec) to load plugins without validation. This creates a "
                        f"critical security risk where attackers can inject malicious code through plugin "
                        f"loading mechanisms, leading to arbitrary code execution."
                    ),
                    file_path=parsed_data.get('file_path', ''),
                    line_number=func_start,
                    code_snippet=self._get_code_snippet(source_lines, func_start, context=5),
                    recommendation=self._get_dynamic_loading_recommendation(),
                    evidence={
                        'function_name': func.get('name'),
                        'uses_dynamic_loading': True,
                        'has_validation': False
                    }
                )
                findings.append(finding)

        return findings

    def _check_plugin_execution(self, parsed_data: Dict[str, Any]) -> List[Finding]:
        """Check for plugin execution without sandboxing"""
        findings = []
        functions = parsed_data.get('functions', [])
        source_lines = parsed_data.get('source_lines', [])

        for func in functions:
            func_name = func.get('name', '').lower()
            func_start = func.get('line', 0)
            func_end = func.get('end_line', func_start + 10)

            # Check if this executes plugins
            is_plugin_execution = any(
                pattern in func_name
                for pattern in self.PLUGIN_PATTERNS['plugin_execution']
            )

            if not is_plugin_execution:
                continue

            # Get function body
            func_body = '\n'.join(source_lines[func_start-1:func_end])
            func_lower = func_body.lower()

            # Check for sandboxing
            has_sandboxing = any(
                pattern in func_lower
                for pattern in self.SANDBOX_PATTERNS
            )

            # Check for error handling
            has_error_handling = any(
                pattern in func_lower
                for pattern in self.ERROR_HANDLING_PATTERNS
            )

            # Check if plugin performs high-risk operations
            risk_categories = []
            for category, patterns in self.HIGH_RISK_OPERATIONS.items():
                if any(pattern in func_lower for pattern in patterns):
                    risk_categories.append(category)

            if not has_sandboxing and risk_categories:
                severity = Severity.HIGH if has_error_handling else Severity.CRITICAL

                finding = Finding(
                    id=f"{self.detector_id}_{parsed_data.get('file_path', '')}_{func_start}_execution",
                    category=f"{self.detector_id}: {self.name}",
                    severity=severity,
                    confidence=0.0,  # Will be set by BaseDetector
                    title=f"Plugin execution without sandboxing in '{func.get('name')}'",
                    description=(
                        f"Function '{func.get('name')}' on line {func_start} executes plugins "
                        f"without sandboxing while performing high-risk operations ({', '.join(risk_categories)}). "
                        f"This allows malicious plugins unrestricted access to system resources, "
                        f"potentially leading to data theft, privilege escalation, or system compromise."
                    ),
                    file_path=parsed_data.get('file_path', ''),
                    line_number=func_start,
                    code_snippet=self._get_code_snippet(source_lines, func_start, context=3),
                    recommendation=self._get_sandboxing_recommendation(),
                    evidence={
                        'function_name': func.get('name'),
                        'has_sandboxing': False,
                        'risk_categories': risk_categories,
                        'has_error_handling': has_error_handling
                    }
                )
                findings.append(finding)

        return findings

    def _check_plugin_authentication(self, parsed_data: Dict[str, Any]) -> List[Finding]:
        """Check for missing authentication on plugin-related endpoints"""
        findings = []
        functions = parsed_data.get('functions', [])
        source_lines = parsed_data.get('source_lines', [])

        for func in functions:
            func_name = func.get('name', '').lower()
            func_start = func.get('line', 0)
            func_end = func.get('end_line', func_start + 10)

            # Check if this is a plugin management function
            is_plugin_management = any(
                keyword in func_name
                for keyword in ['plugin', 'extension', 'addon', 'module']
            )

            if not is_plugin_management:
                continue

            # Get function body
            func_body = '\n'.join(source_lines[func_start-1:func_end])
            func_lower = func_body.lower()

            # Check for authentication
            has_auth = any(
                pattern in func_lower
                for pattern in self.AUTH_PATTERNS
            )

            # Check decorators for auth
            decorators = func.get('decorators', [])
            has_auth_decorator = any(
                'auth' in str(dec).lower() or 'login' in str(dec).lower()
                for dec in decorators
            )

            if not has_auth and not has_auth_decorator:
                # Determine if it's a sensitive operation
                is_sensitive = any(
                    op in func_name
                    for op in ['install', 'enable', 'register', 'add', 'load', 'execute', 'run']
                )

                if is_sensitive:
                    finding = Finding(
                        id=f"{self.detector_id}_{parsed_data.get('file_path', '')}_{func_start}_auth",
                        category=f"{self.detector_id}: {self.name}",
                        severity=Severity.HIGH,
                        confidence=0.0,  # Will be set by BaseDetector
                        title=f"Plugin management function without authentication in '{func.get('name')}'",
                        description=(
                            f"Function '{func.get('name')}' on line {func_start} manages plugins "
                            f"(install/enable/execute) without requiring authentication. This allows "
                            f"unauthorized users to manipulate the plugin system, potentially installing "
                            f"malicious plugins or executing arbitrary code."
                        ),
                        file_path=parsed_data.get('file_path', ''),
                        line_number=func_start,
                        code_snippet=self._get_code_snippet(source_lines, func_start, context=3),
                        recommendation=self._get_authentication_recommendation(),
                        evidence={
                            'function_name': func.get('name'),
                            'has_authentication': False,
                            'is_sensitive_operation': True
                        }
                    )
                    findings.append(finding)

        return findings

    def _get_validation_recommendation(self) -> str:
        """Get recommendation for plugin input validation"""
        return """Plugin Input Validation Best Practices:
1. Validate all plugin parameters against a strict schema
2. Use allowlists for permitted plugin names/sources
3. Verify plugin signatures before loading
4. Check plugin metadata and version compatibility
5. Sanitize all user-provided plugin configuration
6. Implement plugin capability restrictions
7. Use type validation (Pydantic, marshmallow, JSON Schema)
8. Reject plugins with suspicious characteristics
9. Log all plugin registration attempts
10. Implement rate limiting on plugin operations"""

    def _get_dynamic_loading_recommendation(self) -> str:
        """Get recommendation for safe dynamic loading"""
        return """Safe Plugin Loading:
1. NEVER use eval(), exec(), or __import__() for plugins
2. Use importlib with strict module path validation
3. Implement plugin allowlists (approved plugins only)
4. Verify plugin checksums/signatures before loading
5. Load plugins from trusted directories only
6. Use separate Python processes for plugin isolation
7. Implement plugin capability restrictions
8. Validate plugin code with static analysis before loading
9. Use virtual environments for plugin execution
10. Monitor plugin behavior for anomalies"""

    def _get_sandboxing_recommendation(self) -> str:
        """Get recommendation for plugin sandboxing"""
        return """Plugin Sandboxing Best Practices:
1. Execute plugins in isolated containers (Docker, gVisor)
2. Use separate processes with restricted permissions
3. Implement resource limits (CPU, memory, disk, network)
4. Restrict file system access to specific directories
5. Block network access unless explicitly required
6. Use seccomp/AppArmor/SELinux for syscall filtering
7. Implement timeout mechanisms for plugin execution
8. Monitor plugin resource usage
9. Use least-privilege principles
10. Implement kill switches for misbehaving plugins"""

    def _get_authentication_recommendation(self) -> str:
        """Get recommendation for plugin authentication"""
        return """Plugin Authentication & Authorization:
1. Require authentication for all plugin management operations
2. Implement role-based access control (RBAC)
3. Use API keys or OAuth tokens for plugin operations
4. Verify user permissions before plugin actions
5. Audit all plugin management operations
6. Implement rate limiting per user/API key
7. Use multi-factor authentication for sensitive operations
8. Validate plugin ownership before modifications
9. Implement plugin signing with developer keys
10. Log all authentication attempts and failures"""

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
