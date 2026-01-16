"""
LLM08: Excessive Agency Detector

Detects when LLM systems are granted excessive permissions or autonomy:
1. Tool/Function calling without permission checks
2. Unrestricted API access from LLM outputs
3. Missing confirmation for high-risk operations
4. Broad permission scopes for LLM actions
5. Direct execution of LLM-generated code
6. Lack of action auditing/logging

Uses AST-based taint tracking to detect:
- LLM output flowing directly to high-risk operations
- Missing human-in-the-loop confirmation patterns

References:
- OWASP LLM08: https://owasp.org/www-project-top-10-for-large-language-model-applications/
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
    SinkType,
    calculate_flow_confidence,
)

logger = logging.getLogger(__name__)


class ExcessiveAgencyDetector(BaseDetector):
    """
    Detect LLM08: Excessive Agency vulnerabilities

    Identifies cases where LLMs are given too much autonomy:
    - Tool/function calling without permission checks
    - Direct execution of LLM outputs
    - Missing confirmation for destructive operations
    - Unrestricted API access
    - Lack of action boundaries
    """

    detector_id = "LLM08"
    name = "Excessive Agency"
    default_confidence_threshold = 0.6

    # High-risk operations that should require confirmation
    # Use specific patterns to avoid matching framework infrastructure code
    HIGH_RISK_OPERATIONS = {
        'delete': ['delete_file', 'delete_record', 'drop_table', 'truncate_table', 'destroy_resource', 'rm -', 'unlink('],
        'write': ['write_file', 'save_to_disk', 'overwrite_', 'modify_config'],
        'execute': ['exec(', 'eval(', 'subprocess.run', 'subprocess.call', 'subprocess.Popen', 'os.system(', 'os.popen('],
        'network': ['urlopen(', 'requests.get(', 'requests.post(', 'httpx.get(', 'httpx.post('],
        'financial': ['process_payment', 'charge_card', 'transfer_funds', 'make_purchase'],
        'admin': ['grant_permission', 'revoke_access', 'chmod(', 'sudo ', 'set_admin']
    }

    # Framework infrastructure patterns to exclude (these are not LLM agency issues)
    EXCLUDED_PATTERNS = {
        '_configure', '_get_', '_set_', '_transform', '_stream',
        'with_listeners', 'with_config', 'parse_result', 'serialize',
        '__init__', '__call__', '__enter__', '__exit__',
        'callback', 'handler', 'middleware', 'decorator'
    }

    # Tool/function calling patterns (OpenAI function calling, LangChain tools, etc.)
    TOOL_CALLING_PATTERNS = {
        'openai_functions': ['functions', 'function_call', 'tools', 'tool_choice'],
        'langchain': ['Tool(', 'BaseTool', 'StructuredTool', 'tool_decorator', '@tool'],
        'anthropic': ['tools', 'tool_use'],
        'llamaindex': ['FunctionTool', 'QueryEngineTool'],
        'autogen': ['register_function', 'function_map']
    }

    # Permission/authorization patterns
    PERMISSION_PATTERNS = [
        'check_permission', 'require_permission', 'has_permission',
        'authorize', 'is_authorized', 'check_auth',
        'verify_access', 'check_access', 'can_access',
        'confirm', 'require_confirmation', 'user_approval'
    ]

    # Execution patterns
    EXECUTION_PATTERNS = [
        'exec(', 'eval(', 'compile(',
        'subprocess.', 'os.system', 'os.popen',
        'shell=True', '__import__'
    ]

    # Code generation indicators
    CODE_GEN_PATTERNS = [
        'generate_code', 'code_generation', 'create_function',
        'write_code', 'execute_generated'
    ]

    def _gather_potential_findings(self, parsed_data: Dict[str, Any]) -> List[Finding]:
        """
        Gather all potential excessive agency vulnerabilities

        Args:
            parsed_data: Parsed code structure from AST parser

        Returns:
            List of Finding objects (before confidence filtering)
        """
        findings = []

        # Check for tool/function calling without permission checks
        tool_findings = self._check_tool_calling(parsed_data)
        findings.extend(tool_findings)

        # Check for direct execution of LLM outputs
        exec_findings = self._check_llm_output_execution(parsed_data)
        findings.extend(exec_findings)

        # Check for high-risk operations without confirmation
        risk_findings = self._check_high_risk_operations(parsed_data)
        findings.extend(risk_findings)

        # Check for unrestricted API access from LLM
        api_findings = self._check_unrestricted_api_access(parsed_data)
        findings.extend(api_findings)

        return findings

    def calculate_confidence(self, evidence: Dict[str, Any]) -> float:
        """
        Calculate confidence based on evidence

        High confidence (0.8-1.0):
        - Direct code execution (exec/eval)
        - Clear permission check absence

        Medium confidence (0.6-0.8):
        - Tool calling patterns
        - High-risk operations

        Args:
            evidence: Evidence dictionary from finding

        Returns:
            Confidence score (0.0-1.0)
        """
        confidence = 0.7  # Base confidence

        # High confidence for direct execution
        if evidence.get('execution_type') in ['exec', 'eval', 'subprocess']:
            confidence = 0.85

        # High confidence if we explicitly checked for permissions and found none
        if 'has_permission_check' in evidence and not evidence['has_permission_check']:
            confidence = 0.75

        # Medium-high for missing confirmation
        if 'has_confirmation' in evidence and not evidence['has_confirmation']:
            confidence = 0.70

        # Medium for URL validation issues
        if 'has_url_validation' in evidence and not evidence['has_url_validation']:
            confidence = 0.70

        return min(confidence, 1.0)

    def _check_tool_calling(self, parsed_data: Dict[str, Any]) -> List[Finding]:
        """Check for tool/function calling without permission checks"""
        findings = []
        functions = parsed_data.get('functions', [])
        source_lines = parsed_data.get('source_lines', [])
        source_code = '\n'.join(source_lines)
        llm_calls = parsed_data.get('llm_api_calls', [])

        # Find functions that use tool calling
        for llm_call in llm_calls:
            line_num = llm_call.get('line', 0)
            keywords = llm_call.get('keywords', {})

            # Convert keywords dict to string for pattern matching
            call_code = str(keywords)

            # Check if this LLM call uses tools/functions
            uses_tools = any(
                pattern.lower() in call_code.lower()
                for patterns in self.TOOL_CALLING_PATTERNS.values()
                for pattern in patterns
            )

            if not uses_tools:
                continue

            # Find the function containing this call
            containing_func = self._find_containing_function(functions, line_num)
            if not containing_func:
                continue

            func_name = containing_func.get('name', 'unknown')
            func_start = containing_func.get('line', 0)
            func_end = containing_func.get('end_line', func_start + 10)

            # Get function body
            func_body = '\n'.join(source_lines[func_start-1:func_end])

            # Check for permission checks in the function
            has_permission_check = any(
                pattern in func_body.lower()
                for pattern in self.PERMISSION_PATTERNS
            )

            if not has_permission_check:
                # Check severity based on tool capabilities
                severity = self._assess_tool_risk(call_code)

                finding = Finding(
                    id=f"{self.detector_id}_{parsed_data.get('file_path', '')}_{line_num}_tool_calling",
                    category=f"{self.detector_id}: {self.name}",
                    severity=severity,
                    confidence=0.0,  # Will be set by BaseDetector
                    title=f"LLM tool calling without permission checks in '{func_name}'",
                    description=(
                        f"Function '{func_name}' on line {func_start} enables LLM tool/function calling "
                        f"without implementing permission checks or authorization. This allows the LLM to "
                        f"autonomously execute tools without human oversight, potentially performing "
                        f"unauthorized or harmful actions."
                    ),
                    file_path=parsed_data.get('file_path', ''),
                    line_number=line_num,
                    code_snippet=self._get_code_snippet(source_lines, line_num),
                    recommendation=self._get_tool_calling_recommendation(),
                    evidence={
                        'function_name': func_name,
                        'has_permission_check': False,
                        'tool_calling_type': self._identify_tool_framework(call_code)
                    }
                )
                findings.append(finding)

        return findings

    def _check_llm_output_execution(self, parsed_data: Dict[str, Any]) -> List[Finding]:
        """Check for direct execution of LLM-generated code"""
        findings = []
        functions = parsed_data.get('functions', [])
        source_lines = parsed_data.get('source_lines', [])
        llm_calls = parsed_data.get('llm_api_calls', [])

        # Try AST-based analysis first
        ast_findings = self._analyze_llm_to_exec_flow(parsed_data)
        findings.extend(ast_findings)

        # Track functions already detected to avoid duplicates
        found_funcs = {f.evidence.get('function_name', '').lower() for f in findings}

        for func in functions:
            func_name = func.get('name', '')
            func_start = func.get('line', 0)
            func_end = func.get('end_line', func_start + 10)

            # Skip if already found via AST analysis
            if func_name.lower() in found_funcs:
                continue

            # Get function body
            func_body = '\n'.join(source_lines[func_start-1:func_end])
            func_lower = func_body.lower()

            # Check if function uses exec/eval
            uses_execution = any(
                pattern in func_lower
                for pattern in self.EXECUTION_PATTERNS
            )

            if not uses_execution:
                continue

            # Check if function gets LLM output
            has_llm_call = any(
                func_start <= call.get('line', 0) <= func_end
                for call in llm_calls
            )

            # Check for code generation patterns
            generates_code = any(
                pattern in func_lower
                for pattern in self.CODE_GEN_PATTERNS
            )

            if has_llm_call or generates_code:
                # Check for safety measures
                has_sandbox = 'sandbox' in func_lower or 'safe' in func_lower
                has_validation = 'validate' in func_lower or 'check' in func_lower

                finding = Finding(
                    id=f"{self.detector_id}_{parsed_data.get('file_path', '')}_{func_start}_exec",
                    category=f"{self.detector_id}: {self.name}",
                    severity=Severity.CRITICAL,
                    confidence=0.0,  # Will be set by BaseDetector
                    title=f"Direct execution of LLM-generated code in '{func_name}'",
                    description=(
                        f"Function '{func_name}' on line {func_start} directly executes code generated "
                        f"or influenced by an LLM using exec()/eval() or subprocess. This creates a critical "
                        f"security risk where malicious or buggy LLM outputs can execute arbitrary code, "
                        f"potentially compromising the entire system."
                    ),
                    file_path=parsed_data.get('file_path', ''),
                    line_number=func_start,
                    code_snippet=self._get_code_snippet(source_lines, func_start, context=5),
                    recommendation=self._get_execution_recommendation(),
                    evidence={
                        'function_name': func_name,
                        'has_sandbox': has_sandbox,
                        'has_validation': has_validation,
                        'execution_type': self._identify_execution_type(func_body)
                    }
                )
                findings.append(finding)

        return findings

    def _analyze_llm_to_exec_flow(self, parsed_data: Dict[str, Any]) -> List[Finding]:
        """
        Use AST-based taint tracking to find LLM output flowing to exec/eval.

        This provides more accurate detection with:
        - Proper flow tracking through variables
        - Sink-specific validation checks
        - Confidence based on flow type
        """
        findings = []
        source_lines = parsed_data.get('source_lines', [])
        functions = parsed_data.get('functions', [])
        llm_calls = parsed_data.get('llm_api_calls', [])
        file_path = parsed_data.get('file_path', 'unknown')

        if not source_lines or not llm_calls:
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

        for func in functions:
            func_name = func['name']
            func_node = func_nodes.get(func_name)
            if not func_node:
                continue

            func_start = func['line']
            func_end = func.get('end_line', func_start + 100)

            # Find LLM calls in this function
            func_llm_calls = [
                call for call in llm_calls
                if func_start <= call['line'] <= func_end
            ]

            if not func_llm_calls:
                continue

            # Initialize taint tracker
            tracker = TaintTracker(func_node, source_lines)

            # Identify LLM output variables as taint sources
            sources = self._identify_llm_output_sources(
                func_llm_calls, func_node
            )

            if not sources:
                continue

            # Find execution sinks
            sinks = self._find_execution_sinks(func_node)

            for sink in sinks:
                flows = tracker.trace_flows(sources, sink)

                for flow in flows:
                    # Check for human-in-the-loop patterns
                    has_hitl = self._check_human_in_the_loop(
                        func_node, flow.source.line, flow.sink.line
                    )

                    # Calculate confidence
                    confidence = calculate_flow_confidence(flow, has_hitl)

                    if confidence < self.confidence_threshold:
                        continue

                    finding = Finding(
                        id=f"{self.detector_id}_{file_path}_{flow.sink.line}_exec_taint",
                        category=f"{self.detector_id}: {self.name}",
                        severity=Severity.CRITICAL,
                        confidence=confidence,
                        title=f"LLM output flows to code execution in '{func_name}'",
                        description=(
                            f"In function '{func_name}', LLM output variable "
                            f"'{flow.source.var_name}' flows to '{flow.sink.func_name}' "
                            f"on line {flow.sink.line} via {flow.flow_type.value} flow. "
                            f"This grants excessive agency to the LLM, allowing it to "
                            f"execute arbitrary code without human oversight."
                        ),
                        file_path=file_path,
                        line_number=flow.sink.line,
                        code_snippet=self._get_code_snippet(source_lines, flow.sink.line, context=3),
                        recommendation=self._get_execution_recommendation(),
                        evidence={
                            'function_name': func_name,
                            'source_var': flow.source.var_name,
                            'execution_type': flow.sink.func_name,
                            'flow_type': flow.flow_type.value,
                            'has_human_in_loop': has_hitl,
                        }
                    )
                    findings.append(finding)

        return findings

    def _identify_llm_output_sources(
        self,
        llm_calls: List[Dict[str, Any]],
        func_node: ast.FunctionDef
    ) -> List[TaintSource]:
        """Identify variables that hold LLM output"""
        sources = []

        for llm_call in llm_calls:
            llm_line = llm_call.get('line', 0)

            # Find assignment at LLM call line
            for stmt in func_node.body:
                if not isinstance(stmt, ast.Assign):
                    continue
                if not hasattr(stmt, 'lineno') or stmt.lineno != llm_line:
                    continue

                for target in stmt.targets:
                    if isinstance(target, ast.Name):
                        sources.append(TaintSource(
                            var_name=target.id,
                            line=llm_line,
                            source_type='llm_output',
                            node=stmt.value
                        ))

        # Track derived variables (response.text, result.content, etc.)
        for source in list(sources):
            for stmt in func_node.body:
                if not isinstance(stmt, ast.Assign):
                    continue
                if not hasattr(stmt, 'lineno'):
                    continue
                if stmt.lineno <= source.line:
                    continue

                for target in stmt.targets:
                    if isinstance(target, ast.Name):
                        from aisentry.utils.ast_utils import names_in_expr
                        if source.var_name in names_in_expr(stmt.value):
                            sources.append(TaintSource(
                                var_name=target.id,
                                line=stmt.lineno,
                                source_type='llm_output_derived',
                                node=stmt.value
                            ))

        return sources

    def _find_execution_sinks(self, func_node: ast.FunctionDef) -> List[TaintSink]:
        """Find exec/eval sinks in function"""
        sinks = []

        for node in ast.walk(func_node):
            if not isinstance(node, ast.Call):
                continue
            if not hasattr(node, 'lineno'):
                continue

            from aisentry.utils.ast_utils import get_full_call_name
            func_name = get_full_call_name(node)

            # Check for execution patterns
            exec_patterns = ['exec', 'eval', 'compile', 'subprocess', 'os.system']
            if any(p in func_name.lower() for p in exec_patterns):
                sinks.append(TaintSink(
                    func_name=func_name,
                    line=node.lineno,
                    sink_type=SinkType.CODE_EXEC,
                    node=node
                ))

        return sinks

    def _check_human_in_the_loop(
        self,
        func_node: ast.FunctionDef,
        source_line: int,
        sink_line: int
    ) -> bool:
        """
        Check if there's a human-in-the-loop confirmation between source and sink.

        Looks for patterns like:
        - user_approval = input(...)
        - if confirm(...)
        - await get_confirmation(...)
        """
        hitl_patterns = [
            'confirm', 'approval', 'approve', 'verify',
            'human_review', 'human_in_loop', 'manual_check',
            'input(', 'await_confirmation', 'ask_user'
        ]

        for stmt in func_node.body:
            if not hasattr(stmt, 'lineno'):
                continue

            # Only check between source and sink
            if not (source_line <= stmt.lineno < sink_line):
                continue

            stmt_str = ast.dump(stmt).lower()
            for pattern in hitl_patterns:
                if pattern in stmt_str:
                    return True

        return False

    def _check_high_risk_operations(self, parsed_data: Dict[str, Any]) -> List[Finding]:
        """Check for high-risk operations without confirmation.

        Only flags when:
        1. Function contains specific high-risk operation patterns (not generic keywords)
        2. Function has LLM call AND LLM output appears to flow to the operation
        3. Function is not a framework infrastructure pattern (excluded)
        """
        findings = []
        functions = parsed_data.get('functions', [])
        source_lines = parsed_data.get('source_lines', [])
        llm_calls = parsed_data.get('llm_api_calls', [])

        for func in functions:
            func_name = func.get('name', '')
            func_name_lower = func_name.lower()
            func_start = func.get('line', 0)
            func_end = func.get('end_line', func_start + 10)

            # Skip excluded framework infrastructure patterns
            if any(excl in func_name_lower for excl in self.EXCLUDED_PATTERNS):
                continue

            # Get function body
            func_body = '\n'.join(source_lines[func_start-1:func_end])

            # Check if function performs high-risk operations (exact pattern match)
            risk_types = []
            matched_patterns = []
            for risk_category, patterns in self.HIGH_RISK_OPERATIONS.items():
                for pattern in patterns:
                    if pattern in func_body:
                        risk_types.append(risk_category)
                        matched_patterns.append(pattern)
                        break

            if not risk_types:
                continue

            # Check if function has LLM call
            func_llm_calls = [
                call for call in llm_calls
                if func_start <= call.get('line', 0) <= func_end
            ]

            if not func_llm_calls:
                continue

            # Additional check: LLM output variable should be used near the high-risk operation
            # Look for response/result/output variable assignments from LLM calls
            llm_output_vars = set()
            for call in func_llm_calls:
                call_line = call.get('line', 0)
                if 0 < call_line <= len(source_lines):
                    line_content = source_lines[call_line - 1]
                    # Look for assignment: var = llm_call(...)
                    if '=' in line_content:
                        var_part = line_content.split('=')[0].strip()
                        if var_part and not var_part.startswith('#'):
                            llm_output_vars.add(var_part.split()[-1])

            # Check if any LLM output variable is used in the high-risk operation context
            has_llm_flow = False
            if llm_output_vars:
                for pattern in matched_patterns:
                    pattern_idx = func_body.find(pattern)
                    if pattern_idx >= 0:
                        # Get context around the pattern (50 chars before and after)
                        context_start = max(0, pattern_idx - 50)
                        context_end = min(len(func_body), pattern_idx + len(pattern) + 50)
                        context = func_body[context_start:context_end]
                        if any(var in context for var in llm_output_vars):
                            has_llm_flow = True
                            break

            if not has_llm_flow:
                continue

            # Check for confirmation mechanisms
            func_lower = func_body.lower()
            has_confirmation = any(
                keyword in func_lower
                for keyword in ['confirm', 'approval', 'verify', 'prompt', 'ask_user', 'human_review']
            )

            if not has_confirmation:
                severity = Severity.HIGH if 'delete' in risk_types or 'execute' in risk_types else Severity.MEDIUM

                finding = Finding(
                    id=f"{self.detector_id}_{parsed_data.get('file_path', '')}_{func_start}_risk",
                    category=f"{self.detector_id}: {self.name}",
                    severity=severity,
                    confidence=0.0,  # Will be set by BaseDetector
                    title=f"High-risk {'/'.join(risk_types)} operation without confirmation in '{func_name}'",
                    description=(
                        f"Function '{func_name}' on line {func_start} performs high-risk "
                        f"{'/'.join(risk_types)} operations based on LLM decisions without requiring "
                        f"user confirmation or approval. This allows the LLM to autonomously execute "
                        f"potentially destructive or sensitive actions."
                    ),
                    file_path=parsed_data.get('file_path', ''),
                    line_number=func_start,
                    code_snippet=self._get_code_snippet(source_lines, func_start, context=3),
                    recommendation=self._get_confirmation_recommendation(),
                    evidence={
                        'function_name': func_name,
                        'risk_types': risk_types,
                        'matched_patterns': matched_patterns,
                        'has_confirmation': False
                    }
                )
                findings.append(finding)

        return findings

    def _check_unrestricted_api_access(self, parsed_data: Dict[str, Any]) -> List[Finding]:
        """Check for unrestricted API access from LLM outputs.

        Only flags when:
        1. LLM output variable is used as URL parameter in HTTP request
        2. No URL validation/allowlist is present
        3. Function is not excluded infrastructure pattern
        """
        findings = []
        functions = parsed_data.get('functions', [])
        source_lines = parsed_data.get('source_lines', [])
        llm_calls = parsed_data.get('llm_api_calls', [])

        # Specific HTTP call patterns (not generic 'http.')
        HTTP_PATTERNS = ['requests.get(', 'requests.post(', 'requests.put(', 'requests.delete(',
                        'httpx.get(', 'httpx.post(', 'urllib.request.urlopen(',
                        'aiohttp.request(', 'fetch(']

        for func in functions:
            func_name = func.get('name', '')
            func_name_lower = func_name.lower()
            func_start = func.get('line', 0)
            func_end = func.get('end_line', func_start + 10)

            # Skip excluded framework infrastructure patterns
            if any(excl in func_name_lower for excl in self.EXCLUDED_PATTERNS):
                continue

            func_body = '\n'.join(source_lines[func_start-1:func_end])

            # Check if function makes specific API calls
            http_call_found = None
            for pattern in HTTP_PATTERNS:
                if pattern in func_body:
                    http_call_found = pattern
                    break

            if not http_call_found:
                continue

            # Check if function has LLM call
            func_llm_calls = [
                call for call in llm_calls
                if func_start <= call.get('line', 0) <= func_end
            ]

            if not func_llm_calls:
                continue

            # Extract LLM output variable names
            llm_output_vars = set()
            for call in func_llm_calls:
                call_line = call.get('line', 0)
                if 0 < call_line <= len(source_lines):
                    line_content = source_lines[call_line - 1]
                    if '=' in line_content:
                        var_part = line_content.split('=')[0].strip()
                        if var_part and not var_part.startswith('#'):
                            llm_output_vars.add(var_part.split()[-1])

            if not llm_output_vars:
                continue

            # Check if LLM output var is used in HTTP call (as URL parameter)
            http_call_idx = func_body.find(http_call_found)
            if http_call_idx < 0:
                continue

            # Get the HTTP call line and following content (to capture URL argument)
            http_context_end = func_body.find(')', http_call_idx)
            if http_context_end < 0:
                http_context_end = min(len(func_body), http_call_idx + 200)
            http_context = func_body[http_call_idx:http_context_end]

            # Check if any LLM output variable appears in the HTTP call arguments
            llm_var_in_url = any(var in http_context for var in llm_output_vars)

            if not llm_var_in_url:
                continue

            # Check for URL validation/allowlist
            func_lower = func_body.lower()
            has_url_validation = any(
                keyword in func_lower
                for keyword in ['allowlist', 'whitelist', 'validate_url', 'allowed_domains',
                               'allowed_hosts', 'url_validator', 'is_valid_url']
            )

            if not has_url_validation:
                finding = Finding(
                    id=f"{self.detector_id}_{parsed_data.get('file_path', '')}_{func_start}_api",
                    category=f"{self.detector_id}: {self.name}",
                    severity=Severity.HIGH,
                    confidence=0.0,  # Will be set by BaseDetector
                    title=f"LLM output used as URL in HTTP request in '{func_name}'",
                    description=(
                        f"Function '{func_name}' on line {func_start} uses LLM output as a URL "
                        f"in an HTTP request ({http_call_found.rstrip('(')}) without URL validation "
                        f"or allowlisting. This allows the LLM to make requests to arbitrary "
                        f"endpoints, potentially performing SSRF attacks or data exfiltration."
                    ),
                    file_path=parsed_data.get('file_path', ''),
                    line_number=func_start,
                    code_snippet=self._get_code_snippet(source_lines, func_start, context=3),
                    recommendation=self._get_api_access_recommendation(),
                    evidence={
                        'function_name': func_name,
                        'http_pattern': http_call_found,
                        'llm_vars_found': list(llm_output_vars),
                        'has_url_validation': False
                    }
                )
                findings.append(finding)

        return findings

    def _find_containing_function(self, functions: List[Dict], line_num: int) -> Dict[str, Any]:
        """Find function that contains given line number"""
        for func in functions:
            start = func.get('line', 0)
            end = func.get('end_line', start)
            if start <= line_num <= end:
                return func
        return {}

    def _assess_tool_risk(self, call_code: str) -> Severity:
        """Assess risk level based on tool capabilities"""
        call_lower = call_code.lower()

        # Check for high-risk keywords
        high_risk = ['delete', 'execute', 'admin', 'payment', 'sudo']
        if any(keyword in call_lower for keyword in high_risk):
            return Severity.HIGH

        return Severity.MEDIUM

    def _identify_tool_framework(self, call_code: str) -> str:
        """Identify which tool calling framework is being used"""
        call_lower = call_code.lower()

        for framework, patterns in self.TOOL_CALLING_PATTERNS.items():
            if any(pattern.lower() in call_lower for pattern in patterns):
                return framework

        return 'unknown'

    def _identify_execution_type(self, func_body: str) -> str:
        """Identify type of code execution"""
        func_lower = func_body.lower()

        if 'exec(' in func_lower:
            return 'exec'
        elif 'eval(' in func_lower:
            return 'eval'
        elif 'subprocess' in func_lower or 'os.system' in func_lower:
            return 'subprocess'
        elif 'compile(' in func_lower:
            return 'compile'

        return 'unknown'

    def _get_tool_calling_recommendation(self) -> str:
        """Get recommendation for tool calling security"""
        return """Tool Calling Security Best Practices:
1. Implement permission checks before tool execution (check_permission, authorize)
2. Use allowlists to restrict which tools can be called
3. Require human confirmation for sensitive operations
4. Log all tool executions with context for audit trails
5. Implement rate limiting on tool calls to prevent abuse
6. Use least-privilege principle - only grant necessary permissions
7. Add input validation for tool parameters
8. Consider implementing a "dry-run" mode for testing
9. Set up alerts for unusual tool usage patterns
10. Document tool permissions and restrictions clearly"""

    def _get_execution_recommendation(self) -> str:
        """Get recommendation for code execution security"""
        return """Code Execution Security:
1. NEVER execute LLM-generated code directly with exec()/eval()
2. If code execution is necessary, use sandboxed environments (Docker, VM)
3. Implement strict code validation and static analysis before execution
4. Use allowlists for permitted functions/modules
5. Set resource limits (CPU, memory, time) for execution
6. Parse and validate code structure before running
7. Consider using safer alternatives (JSON, declarative configs)
8. Log all code execution attempts with full context
9. Require human review for generated code
10. Use tools like RestrictedPython for safer Python execution"""

    def _get_confirmation_recommendation(self) -> str:
        """Get recommendation for operation confirmation"""
        return """High-Risk Operation Safety:
1. Require explicit user confirmation for destructive actions
2. Display clear preview of what will be changed/deleted
3. Implement "undo" functionality where possible
4. Use transaction rollback for database operations
5. Add time delays before executing irreversible actions
6. Send notifications for critical operations
7. Implement approval workflows for sensitive operations
8. Maintain detailed audit logs of all actions
9. Use "dry-run" mode to show what would happen
10. Consider implementing operation quotas/limits"""

    def _get_api_access_recommendation(self) -> str:
        """Get recommendation for API access control"""
        return """API Access Control:
1. Implement strict URL allowlists for permitted endpoints
2. Validate and sanitize all URLs before making requests
3. Use separate API keys with minimal permissions
4. Implement rate limiting on outbound requests
5. Log all API calls with full context
6. Block private/internal IP ranges (SSRF prevention)
7. Validate response content before processing
8. Set timeouts on API calls
9. Use circuit breakers for failing endpoints
10. Monitor for unusual access patterns"""

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
