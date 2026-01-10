"""
LLM07: Insecure Plugin Design Detector

Detects security issues in LLM plugin/extension implementations:
1. Plugin input validation failures
2. Missing authentication/authorization for plugins
3. Unsafe plugin loading mechanisms
4. Plugin privilege escalation risks
5. Missing plugin sandboxing
6. Inadequate plugin output validation

Uses AST-based taint tracking for tool function analysis:
- Tracks LLM output parameters to dangerous sinks
- Sink-specific validation (shell=False, parameterized SQL, URL allowlists)

References:
- OWASP LLM07: https://owasp.org/www-project-top-10-for-large-language-model-applications/
"""

import ast
import logging
from typing import Any, Dict, List

from aisentry.models.finding import Finding, Severity
from aisentry.static_detectors.base_detector import BaseDetector
from aisentry.utils.taint_tracker import (
    TaintTracker,
    TaintSource,
    TaintSink,
    TaintFlow,
    SinkType,
    calculate_flow_confidence,
)

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

    # Tool function patterns (LLM-invokable functions)
    TOOL_PATTERNS = [
        '_tool', 'tool_', '_action', 'action_',
        'execute_', 'run_', 'perform_',
    ]

    # Dangerous operations often found in tools
    DANGEROUS_TOOL_OPS = {
        'shell_exec': ['subprocess.run', 'subprocess.call', 'os.system', 'shell=True'],
        'file_access': ['open(', 'read(', 'write(', 'unlink', 'remove'],
        'sql_exec': ['cursor.execute', '.execute(', 'raw_query'],
        'http_request': ['requests.get', 'requests.post', 'urllib.request', 'httpx.'],
        'code_exec': ['eval(', 'exec(', 'compile('],
    }

    # LLM output parameter patterns
    LLM_OUTPUT_PARAMS = [
        'llm_output', 'model_output', 'ai_output', 'response',
        'llm_response', 'generated', 'completion'
    ]

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

        # Check for insecure tool functions (LLM-invokable with dangerous ops)
        tool_findings = self._check_insecure_tools(parsed_data)
        findings.extend(tool_findings)

        return findings

    def calculate_confidence(self, evidence: Dict[str, Any]) -> float:
        """
        Calculate confidence based on evidence

        High confidence (0.8-1.0):
        - Dynamic loading without validation
        - Tool functions executing dangerous ops on LLM output

        Medium-high confidence (0.7-0.8):
        - Missing authentication on plugin endpoints

        Medium confidence (0.6-0.7):
        - Missing input validation
        - No sandboxing detected

        Args:
            evidence: Evidence dictionary from finding

        Returns:
            Confidence score (0.0-1.0)
        """
        detection_type = evidence.get('detection_type', '')

        # Insecure tool functions - high confidence
        if detection_type == 'insecure_tool':
            dangerous_ops = evidence.get('dangerous_operations', [])
            if 'shell_exec' in dangerous_ops or 'code_exec' in dangerous_ops:
                return 0.90  # Very high for command/code execution
            return 0.85

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

    def _check_insecure_tools(self, parsed_data: Dict[str, Any]) -> List[Finding]:
        """Check for tool functions that execute dangerous operations on LLM output"""
        findings = []
        functions = parsed_data.get('functions', [])
        source_lines = parsed_data.get('source_lines', [])

        # Try AST-based analysis first
        ast_findings = self._analyze_tools_with_taint_tracker(parsed_data)
        findings.extend(ast_findings)

        # Track which functions already have findings to avoid duplicates
        found_funcs = {f.evidence.get('function_name', '').lower() for f in findings}

        for func in functions:
            func_name = func.get('name', '').lower()
            func_start = func.get('line', 0)
            func_end = func.get('end_line', func_start + 30)

            # Skip if already found via AST analysis
            if func_name in found_funcs:
                continue

            # Check if this looks like a tool function
            is_tool_func = any(pattern in func_name for pattern in self.TOOL_PATTERNS)

            if not is_tool_func:
                continue

            # Get function body
            func_body = '\n'.join(source_lines[max(0, func_start-1):min(len(source_lines), func_end)])
            func_lower = func_body.lower()

            # Check if function takes LLM output as parameter
            takes_llm_output = any(
                param in func_lower for param in self.LLM_OUTPUT_PARAMS
            )

            if not takes_llm_output:
                continue

            # Check for dangerous operations
            dangerous_ops_found = []
            for op_type, patterns in self.DANGEROUS_TOOL_OPS.items():
                for pattern in patterns:
                    if pattern in func_body:  # Case-sensitive for code patterns
                        dangerous_ops_found.append((op_type, pattern))
                        break

            if not dangerous_ops_found:
                continue

            # Check for validation/sanitization
            has_validation = any(
                pattern in func_lower for pattern in self.VALIDATION_PATTERNS
            )

            if not has_validation:
                op_types = list(set(op[0] for op in dangerous_ops_found))
                severity = Severity.CRITICAL if 'shell_exec' in op_types or 'code_exec' in op_types else Severity.HIGH

                finding = Finding(
                    id=f"{self.detector_id}_{parsed_data.get('file_path', '')}_{func_start}_tool",
                    category=f"{self.detector_id}: {self.name}",
                    severity=severity,
                    confidence=0.0,
                    title=f"Insecure tool function '{func.get('name')}' executes dangerous operations",
                    description=(
                        f"Tool function '{func.get('name')}' on line {func_start} takes LLM output "
                        f"as a parameter and performs dangerous operations ({', '.join(op_types)}) "
                        f"without proper validation. Attackers can craft malicious LLM outputs to "
                        f"execute arbitrary commands, access files, or perform SQL injection."
                    ),
                    file_path=parsed_data.get('file_path', ''),
                    line_number=func_start,
                    code_snippet=self._get_code_snippet(source_lines, func_start, context=5),
                    recommendation=self._get_tool_security_recommendation(),
                    evidence={
                        'function_name': func.get('name'),
                        'takes_llm_output': True,
                        'dangerous_operations': op_types,
                        'has_validation': False,
                        'detection_type': 'insecure_tool'
                    }
                )
                findings.append(finding)

        return findings

    def _analyze_tools_with_taint_tracker(self, parsed_data: Dict[str, Any]) -> List[Finding]:
        """
        Use AST-based TaintTracker for accurate tool function analysis.

        Traces LLM output parameters to dangerous sinks with:
        - Sink-specific validation (shell=False, parameterized SQL)
        - Proper confidence based on flow type
        """
        findings = []
        source_lines = parsed_data.get('source_lines', [])
        functions = parsed_data.get('functions', [])
        file_path = parsed_data.get('file_path', 'unknown')

        if not source_lines:
            return findings

        # Parse source to AST
        source_code = '\n'.join(source_lines)
        try:
            tree = ast.parse(source_code)
        except SyntaxError:
            return findings

        # Build function node map
        func_nodes: Dict[str, ast.FunctionDef] = {}
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef):
                func_nodes[node.name] = node

        # Analyze each tool function
        for func in functions:
            func_name = func['name']
            func_name_lower = func_name.lower()

            # Check if this looks like a tool function
            is_tool_func = any(pattern in func_name_lower for pattern in self.TOOL_PATTERNS)
            if not is_tool_func:
                continue

            func_node = func_nodes.get(func_name)
            if not func_node:
                continue

            # Identify LLM output parameters as taint sources
            sources = self._identify_llm_param_sources(func_node)
            if not sources:
                continue

            # Initialize taint tracker
            tracker = TaintTracker(func_node, source_lines)

            # Find dangerous sinks in this function
            sinks = self._find_dangerous_sinks(func_node)

            # Trace flows
            for sink in sinks:
                flows = tracker.trace_flows(sources, sink)

                for flow in flows:
                    # Check structural validation
                    has_validation = tracker.check_structural_validation(
                        flow.source, flow.sink
                    )

                    # Calculate confidence
                    confidence = calculate_flow_confidence(flow, has_validation)

                    if confidence < self.confidence_threshold:
                        continue

                    # Create finding
                    finding = self._create_taint_finding(
                        flow=flow,
                        parsed_data=parsed_data,
                        func=func,
                        confidence=confidence
                    )
                    findings.append(finding)

        return findings

    def _identify_llm_param_sources(self, func_node: ast.FunctionDef) -> List[TaintSource]:
        """Identify function parameters that represent LLM output"""
        sources = []

        for arg in func_node.args.args:
            arg_name = arg.arg.lower()
            if any(pattern in arg_name for pattern in self.LLM_OUTPUT_PARAMS):
                sources.append(TaintSource(
                    var_name=arg.arg,
                    line=func_node.lineno,
                    source_type='llm_param',
                    node=arg
                ))

        return sources

    def _find_dangerous_sinks(self, func_node: ast.FunctionDef) -> List[TaintSink]:
        """Find dangerous sink calls in function"""
        sinks = []

        # Map operation types to SinkType
        sink_type_map = {
            'shell_exec': SinkType.COMMAND,
            'sql_exec': SinkType.SQL,
            'file_access': SinkType.FILE,
            'http_request': SinkType.HTTP,
            'code_exec': SinkType.CODE_EXEC,
        }

        for node in ast.walk(func_node):
            if not isinstance(node, ast.Call):
                continue
            if not hasattr(node, 'lineno'):
                continue

            from aisentry.utils.ast_utils import get_full_call_name
            func_name = get_full_call_name(node)

            # Check against dangerous patterns
            for op_type, patterns in self.DANGEROUS_TOOL_OPS.items():
                if any(p.lower() in func_name.lower() for p in patterns):
                    sink_type = sink_type_map.get(op_type, SinkType.PLUGIN)
                    sinks.append(TaintSink(
                        func_name=func_name,
                        line=node.lineno,
                        sink_type=sink_type,
                        node=node
                    ))
                    break

        return sinks

    def _create_taint_finding(
        self,
        flow: 'TaintFlow',
        parsed_data: Dict[str, Any],
        func: Dict[str, Any],
        confidence: float
    ) -> Finding:
        """Create Finding from taint flow analysis"""
        file_path = parsed_data.get('file_path', 'unknown')
        source_lines = parsed_data.get('source_lines', [])

        # Get code snippet
        snippet_start = max(0, flow.sink.line - 2)
        snippet_end = min(len(source_lines), flow.sink.line + 2)
        code_snippet = '\n'.join(source_lines[snippet_start:snippet_end])

        # Determine severity based on sink type
        severity_map = {
            SinkType.COMMAND: Severity.CRITICAL,
            SinkType.CODE_EXEC: Severity.CRITICAL,
            SinkType.SQL: Severity.CRITICAL,
            SinkType.FILE: Severity.HIGH,
            SinkType.HTTP: Severity.HIGH,
        }
        severity = severity_map.get(flow.sink.sink_type, Severity.HIGH)

        sink_type_str = flow.sink.sink_type.value

        return Finding(
            id=f"{self.detector_id}_{file_path}_{flow.sink.line}_taint",
            category=f"{self.detector_id}: {self.name}",
            severity=severity,
            confidence=confidence,
            title=f"LLM output flows to {sink_type_str} sink in tool '{func['name']}'",
            description=(
                f"In tool function '{func['name']}', LLM output parameter "
                f"'{flow.source.var_name}' flows to '{flow.sink.func_name}' "
                f"on line {flow.sink.line} via {flow.flow_type.value} flow. "
                f"This allows LLM-controlled data to reach a dangerous {sink_type_str} sink."
            ),
            file_path=file_path,
            line_number=flow.sink.line,
            code_snippet=code_snippet,
            recommendation=self._get_tool_security_recommendation(),
            evidence={
                'function_name': func['name'],
                'source_var': flow.source.var_name,
                'sink_function': flow.sink.func_name,
                'sink_type': sink_type_str,
                'flow_type': flow.flow_type.value,
                'detection_type': 'insecure_tool',
                'sink_validation': flow.evidence.get('sink_validation'),
            }
        )

    def _get_tool_security_recommendation(self) -> str:
        """Get recommendation for securing LLM tool functions"""
        return """Secure Tool/Plugin Implementation:
1. NEVER execute shell commands from LLM output directly
2. Use allowlists for permitted commands/operations
3. Validate all file paths against allowed directories
4. Use parameterized queries - never raw SQL from LLM
5. Validate URLs against allowlist before HTTP requests
6. Implement strict input schemas (JSON Schema, Pydantic)
7. Add rate limiting and request throttling
8. Log all tool invocations for audit
9. Use principle of least privilege
10. Implement human-in-the-loop for destructive operations"""

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
