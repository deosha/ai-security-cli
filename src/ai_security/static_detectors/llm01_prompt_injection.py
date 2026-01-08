"""
LLM01: Prompt Injection Detector

Detects unsafe embedding of user input into LLM prompts using:
- AST-based taint analysis (user input → prompt string → LLM call)
- Single-hop local variable resolution
- Negative evidence gates (sanitization, PromptTemplate)
- Confidence tiers based on evidence strength
"""

import ast
import logging
from typing import Dict, List, Any, Set, Optional, Tuple
from dataclasses import dataclass

from ai_security.static_detectors.base_detector import BaseDetector
from ai_security.models.finding import Finding, Severity
from ai_security.utils.ast_utils import (
    names_in_expr,
    names_in_fstring,
    is_sanitization_call,
    is_prompt_template_usage,
    resolve_single_hop,
    extract_dict_content_names,
    is_passthrough_call,
    get_full_call_name,
    LLM_SINK_KEYWORDS,
)

logger = logging.getLogger(__name__)


@dataclass
class TaintFlow:
    """Track flow of user input to LLM prompt"""
    source_var: str  # Variable name containing user input
    source_line: int
    sink_line: int  # Line where it reaches LLM call
    sink_function: str  # LLM API function called
    flow_type: str  # 'direct', 'single_hop', 'transitive'
    evidence: Dict[str, Any]


class PromptInjectionDetector(BaseDetector):
    """
    Detect LLM01: Prompt Injection vulnerabilities

    Detects:
    - Direct f-string injection: f"Prompt: {user_input}"
    - String concatenation: prompt + user_message
    - .format() calls: template.format(user_input)

    Confidence tiers:
    - 0.95: Direct injection, user param in LLM sink arg
    - 0.85: Single-hop flow (user_input → prompt_var → LLM call)
    - 0.70: Transitive flow (multiple hops or ambiguous)
    - Reduced by 0.15-0.30 if sanitization/PromptTemplate detected
    """

    detector_id = "LLM01"
    name = "Prompt Injection"
    default_confidence_threshold = 0.6

    # User input parameter name patterns
    USER_INPUT_PATTERNS = {
        'user_input', 'user_message', 'user_query', 'query', 'message',
        'input', 'prompt', 'text', 'content', 'request', 'user_text',
        'user_prompt', 'user_data', 'search_query', 'question',
        # Extended patterns for better recall
        'url', 'data', 'body', 'payload', 'document', 'doc',
        'context', 'external', 'source', 'file_content', 'raw_input'
    }

    # LLM API sink patterns (keyword args that receive prompts)
    LLM_SINK_PATTERNS = {
        'prompt', 'messages', 'input', 'text', 'query',
        'instruction', 'system', 'user', 'content'
    }

    # Functions that are NOT prompt injection sinks (embeddings, tokenization, etc.)
    SAFE_FUNCTION_PATTERNS = {
        # Embedding functions - convert text to vectors, not LLM prompts
        'embed', 'embed_documents', 'embed_query', 'encode',
        'get_embeddings', 'create_embedding', 'embed_text',
        # Tokenization - convert text to tokens, not LLM calls
        'tokenize', 'encode', 'get_token_ids', 'get_num_tokens',
        'count_tokens', 'num_tokens_from_messages',
        # Similarity/search - not prompt injection vectors
        'similarity', 'search', 'query_embed',
        # Text processing - not LLM calls
        'split_text', 'chunk', 'preprocess',
    }

    # LLM completion functions - these ARE prompt injection targets
    LLM_COMPLETION_PATTERNS = {
        'create', 'complete', 'completions', 'chat', 'generate',
        'invoke', 'call', 'run', 'predict', 'agenerate', 'ainvoke',
        'stream', 'astream',
    }

    def _gather_potential_findings(self, parsed_data: Dict[str, Any]) -> List[Finding]:
        """
        Find all potential prompt injection points using AST-based taint tracking

        Strategy:
        1. Parse source to AST for accurate analysis
        2. Identify user input parameters in functions
        3. Track taint flow using single-hop resolution
        4. Apply negative evidence gates (sanitization, PromptTemplate)
        """
        findings = []

        # Get parsed AST data
        functions = parsed_data.get('functions', [])
        llm_calls = parsed_data.get('llm_api_calls', [])
        source_lines = parsed_data.get('source_lines', [])
        file_path = parsed_data.get('file_path', 'unknown')

        if not llm_calls or not source_lines:
            return findings

        # Parse source code to AST for accurate analysis
        source_code = '\n'.join(source_lines)
        try:
            tree = ast.parse(source_code)
        except SyntaxError:
            # Fall back to string-based analysis if AST parse fails
            logger.debug(f"AST parse failed for {file_path}, using fallback")
            return self._fallback_analysis(parsed_data)

        # Build function node map for AST access
        func_nodes = self._extract_function_nodes(tree)

        # For each function with LLM calls
        for func in functions:
            func_name = func['name']
            func_start = func['line']
            func_end = func.get('end_line', func_start + 100)

            # Find LLM calls in this function
            func_llm_calls = [
                call for call in llm_calls
                if func_start <= call['line'] <= func_end
            ]

            if not func_llm_calls:
                continue

            # Check if function has user input parameters
            user_params = self._identify_user_input_params(func['args'])

            if not user_params:
                continue

            # Get the AST node for this function
            func_node = func_nodes.get(func_name)
            if not func_node:
                continue

            # Check for negative evidence (sanitization, PromptTemplate)
            has_sanitization = self._check_sanitization_in_function(func_node)
            has_prompt_template = is_prompt_template_usage(func_node)

            # Analyze each LLM call for taint flow
            for llm_call in func_llm_calls:
                taint_flows = self._trace_taint_ast(
                    func_node=func_node,
                    user_params=user_params,
                    llm_call=llm_call,
                    func_name=func_name
                )

                for flow in taint_flows:
                    # Apply negative evidence to confidence
                    flow.evidence['has_sanitization'] = has_sanitization
                    flow.evidence['has_prompt_template'] = has_prompt_template

                    finding = self._create_finding(
                        flow=flow,
                        parsed_data=parsed_data,
                        func=func
                    )
                    findings.append(finding)

        return findings

    def _extract_function_nodes(self, tree: ast.Module) -> Dict[str, ast.FunctionDef]:
        """Extract function AST nodes by name"""
        func_nodes = {}
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef):
                func_nodes[node.name] = node
        return func_nodes

    def _identify_user_input_params(self, param_names: List[str]) -> Set[str]:
        """Identify which parameters likely contain user input"""
        user_params = set()

        for param in param_names:
            param_lower = param.lower()
            if any(pattern in param_lower for pattern in self.USER_INPUT_PATTERNS):
                user_params.add(param)

        return user_params

    def _is_safe_function(self, func_name: str) -> bool:
        """Check if a function is a safe (non-LLM) function like embedding or tokenization."""
        func_lower = func_name.lower()

        # Check for safe patterns (embeddings, tokenization)
        for safe_pattern in self.SAFE_FUNCTION_PATTERNS:
            if safe_pattern in func_lower:
                return True

        # Additional check: must contain at least one LLM completion pattern
        # to be considered a real LLM sink
        has_completion_pattern = any(
            pattern in func_lower for pattern in self.LLM_COMPLETION_PATTERNS
        )

        return not has_completion_pattern

    def _trace_taint_ast(
        self,
        func_node: ast.FunctionDef,
        user_params: Set[str],
        llm_call: Dict[str, Any],
        func_name: str
    ) -> List[TaintFlow]:
        """
        Trace taint flow using AST-based analysis

        Uses single-hop resolution: tracks user_param → intermediate_var → llm_call

        Safe pattern filtering:
        - User param directly in 'user' role content is SAFE (expected pattern)
        - User param in 'system' role or via transformation is VULNERABLE
        - Embedding/tokenization functions are NOT prompt injection sinks
        """
        flows = []
        llm_line = llm_call['line']
        llm_func = llm_call.get('function', '')

        # Skip safe functions (embeddings, tokenization, etc.)
        if self._is_safe_function(llm_func):
            return flows

        # Reset safe vars tracking
        self._safe_user_role_vars = set()

        # Find the actual LLM call node in the AST
        llm_call_node = self._find_call_at_line(func_node, llm_line)
        if not llm_call_node:
            return flows

        # Extract variable names used in LLM call arguments
        arg_vars = self._extract_llm_call_vars(llm_call_node)

        # Get variables that are in safe user-role position (direct, no transformation)
        safe_user_role_vars = getattr(self, '_safe_user_role_vars', set())

        # Check for direct taint (user param directly in LLM call)
        direct_taints = arg_vars & user_params

        for tainted_var in direct_taints:
            # SAFE PATTERN: user param directly in user role message content
            # This is the expected pattern: {"role": "user", "content": user_input}
            if tainted_var in safe_user_role_vars:
                continue  # Skip - this is the correct way to pass user input

            flows.append(TaintFlow(
                source_var=tainted_var,
                source_line=llm_line,
                sink_line=llm_line,
                sink_function=llm_call['function'],
                flow_type='direct',
                evidence={
                    'operation_type': 'direct_param',
                    'llm_function': llm_call['function'],
                    'function_name': func_name,
                }
            ))

        # Check for single-hop and two-hop taint flows
        intermediate_vars = arg_vars - user_params
        for var in intermediate_vars:
            # Resolve what this variable was assigned from
            resolved = resolve_single_hop(func_node.body, var, llm_line)
            if resolved:
                # Check if the resolved value references user params (single-hop)
                resolved_names = names_in_expr(resolved)
                tainted_sources = resolved_names & user_params

                if tainted_sources:
                    # Found single-hop flow
                    source_var = list(tainted_sources)[0]
                    op_type = self._classify_operation(resolved)

                    flows.append(TaintFlow(
                        source_var=source_var,
                        source_line=self._get_assignment_line(func_node.body, var, llm_line),
                        sink_line=llm_line,
                        sink_function=llm_call['function'],
                        flow_type='single_hop',
                        evidence={
                            'operation_type': op_type,
                            'intermediate_var': var,
                            'llm_function': llm_call['function'],
                            'function_name': func_name,
                        }
                    ))
                else:
                    # Two-hop: check if any referenced var was assigned from user param
                    # e.g., external_content = requests.get(url).text; prompt = f"...{external_content}..."
                    for ref_var in resolved_names - user_params:
                        var_line = self._get_assignment_line(func_node.body, var, llm_line)
                        resolved2 = resolve_single_hop(func_node.body, ref_var, var_line)
                        if resolved2:
                            resolved2_names = names_in_expr(resolved2)
                            tainted_sources2 = resolved2_names & user_params

                            if tainted_sources2:
                                # Found two-hop flow
                                source_var = list(tainted_sources2)[0]
                                op_type = self._classify_operation(resolved)

                                flows.append(TaintFlow(
                                    source_var=source_var,
                                    source_line=self._get_assignment_line(func_node.body, ref_var, var_line),
                                    sink_line=llm_line,
                                    sink_function=llm_call['function'],
                                    flow_type='two_hop',
                                    evidence={
                                        'operation_type': op_type,
                                        'intermediate_var': var,
                                        'second_hop_var': ref_var,
                                        'llm_function': llm_call['function'],
                                        'function_name': func_name,
                                    }
                                ))
                                break  # Found a taint path, no need to check more

        return flows

    def _find_call_at_line(self, func_node: ast.FunctionDef, line: int) -> Optional[ast.Call]:
        """Find a Call node at a specific line within a function"""
        for node in ast.walk(func_node):
            if isinstance(node, ast.Call) and hasattr(node, 'lineno') and node.lineno == line:
                return node
        return None

    def _extract_llm_call_vars(self, call_node: ast.Call) -> Set[str]:
        """
        Extract variable names from LLM call arguments that represent VULNERABLE patterns.

        Safe pattern (excluded): user input in 'user' role message content
        Vulnerable pattern: user input in 'system' role, or in non-role-based prompts
        """
        vars_used = set()

        # Check positional arguments (direct prompt strings)
        for arg in call_node.args:
            vars_used.update(names_in_expr(arg))

        # Check keyword arguments
        for kw in call_node.keywords:
            if kw.arg and kw.arg.lower() in self.LLM_SINK_PATTERNS:
                # For 'messages' kwarg, check each message dict
                if kw.arg.lower() == 'messages' and isinstance(kw.value, ast.List):
                    vars_used.update(self._extract_vulnerable_message_vars(kw.value))
                else:
                    vars_used.update(names_in_expr(kw.value))

        return vars_used

    def _extract_vulnerable_message_vars(self, messages_list: ast.List) -> Set[str]:
        """
        Extract variables from messages list, with context about role.

        Returns all variables - the filtering for safe patterns happens in _trace_taint_ast
        when we check if a variable is directly a user param vs an intermediate.
        """
        vulnerable_vars = set()
        safe_user_role_vars = set()

        for elt in messages_list.elts:
            if isinstance(elt, ast.Dict):
                role = None
                content_node = None

                # Find role and content in this message dict
                for key, value in zip(elt.keys, elt.values):
                    if key is None:
                        continue

                    key_str = None
                    if isinstance(key, ast.Constant) and isinstance(key.value, str):
                        key_str = key.value
                    elif isinstance(key, ast.Str):  # Python 3.7 compat
                        key_str = key.s

                    if key_str == 'role':
                        if isinstance(value, ast.Constant) and isinstance(value.value, str):
                            role = value.value
                        elif isinstance(value, ast.Str):
                            role = value.s
                    elif key_str == 'content':
                        content_node = value

                # Extract variables from content
                if content_node:
                    content_vars = names_in_expr(content_node)

                    if role == 'user' and isinstance(content_node, ast.Name):
                        # Direct variable in user role - mark as potentially safe
                        # Will be filtered out only if it's a direct user param (no transformation)
                        safe_user_role_vars.update(content_vars)

                    # All content vars need to be checked for taint
                    vulnerable_vars.update(content_vars)

        # Return all vars, but also track which are in safe user role position
        # The caller can use this info to filter appropriately
        self._safe_user_role_vars = safe_user_role_vars
        return vulnerable_vars

    def _classify_operation(self, node: ast.AST) -> str:
        """Classify the type of string operation"""
        if isinstance(node, ast.JoinedStr):
            return 'f-string'
        elif isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            return 'concatenation'
        elif isinstance(node, ast.Call):
            func_name = get_full_call_name(node) if isinstance(node, ast.Call) else ''
            if 'format' in func_name:
                return 'format_call'
            if 'substitute' in func_name:
                return 'template_substitute'
            if 'safe_substitute' in func_name:
                return 'template_substitute'
            return 'call'
        return 'assignment'

    def _get_assignment_line(self, body: List[ast.stmt], var_name: str, max_line: int) -> int:
        """Get the line number of the most recent assignment to a variable"""
        last_line = max_line

        for stmt in body:
            if isinstance(stmt, ast.Assign) and hasattr(stmt, 'lineno'):
                if stmt.lineno < max_line:
                    for target in stmt.targets:
                        if isinstance(target, ast.Name) and target.id == var_name:
                            last_line = stmt.lineno

        return last_line

    def _check_sanitization_in_function(self, func_node: ast.FunctionDef) -> bool:
        """Check if function contains sanitization calls"""
        for node in ast.walk(func_node):
            if isinstance(node, ast.Call):
                if is_sanitization_call(node):
                    return True
        return False

    def _create_finding(
        self,
        flow: TaintFlow,
        parsed_data: Dict[str, Any],
        func: Dict[str, Any]
    ) -> Finding:
        """Create Finding from taint flow"""

        file_path = parsed_data.get('file_path', 'unknown')
        source_lines = parsed_data.get('source_lines', [])

        # Get code snippet
        snippet_start = max(0, flow.source_line - 2)
        snippet_end = min(len(source_lines), flow.sink_line + 1)
        code_snippet = '\n'.join(source_lines[snippet_start:snippet_end])

        # Add flow type and evidence
        evidence = flow.evidence.copy()
        evidence['flow_type'] = flow.flow_type

        # Construct description based on flow type
        if flow.flow_type == 'direct':
            description = (
                f"User input parameter '{flow.source_var}' is directly passed to "
                f"LLM API call '{flow.sink_function}'. This is a high-confidence "
                f"prompt injection vector."
            )
        else:
            intermediate = evidence.get('intermediate_var', 'variable')
            op_type = evidence.get('operation_type', 'operation')
            description = (
                f"User input '{flow.source_var}' flows to LLM call via {op_type} "
                f"in variable '{intermediate}'. Function '{func['name']}' may be "
                f"vulnerable to prompt injection attacks."
            )

        return Finding(
            id=f"{self.detector_id}_{file_path}_{flow.source_line}",
            category=f"{self.detector_id}: {self.name}",
            severity=Severity.CRITICAL,
            confidence=0.0,  # Will be calculated in calculate_confidence()
            title=f"User input '{flow.source_var}' embedded in LLM prompt",
            description=description,
            file_path=file_path,
            line_number=flow.source_line,
            code_snippet=code_snippet,
            recommendation=(
                "Mitigations:\n"
                "1. Use structured prompt templates (e.g., LangChain PromptTemplate)\n"
                "2. Implement input sanitization to remove prompt injection patterns\n"
                "3. Use separate 'user' and 'system' message roles (ChatML format)\n"
                "4. Apply input validation and length limits\n"
                "5. Use allowlists for expected input formats\n"
                "6. Consider prompt injection detection libraries"
            ),
            evidence=evidence
        )

    def calculate_confidence(self, evidence: Dict[str, Any]) -> float:
        """
        Calculate confidence based on evidence quality

        Confidence tiers:
        - 0.95: Direct flow (user param in LLM call)
        - 0.85: Single-hop flow with f-string/concatenation
        - 0.75: Single-hop with other operations
        - 0.60: Fallback/ambiguous cases

        Negative evidence reductions:
        - -0.15: Has basic validation (length checks)
        - -0.25: Has sanitization function calls
        - -0.30: Uses PromptTemplate (strongest mitigation)
        """
        flow_type = evidence.get('flow_type', 'unknown')
        op_type = evidence.get('operation_type', 'unknown')

        # Base confidence by flow type
        if flow_type == 'direct':
            confidence = 0.95
        elif flow_type == 'single_hop':
            # Adjust by operation type
            if op_type == 'f-string':
                confidence = 0.90
            elif op_type == 'concatenation':
                confidence = 0.85
            elif op_type in ('format_call', 'template_substitute'):
                confidence = 0.80
            else:
                confidence = 0.75
        elif flow_type == 'two_hop':
            # Two-hop flows have slightly lower confidence (more distance = more uncertainty)
            if op_type == 'f-string':
                confidence = 0.85
            elif op_type == 'concatenation':
                confidence = 0.80
            elif op_type in ('format_call', 'template_substitute'):
                confidence = 0.75
            else:
                confidence = 0.70
        else:
            confidence = 0.60

        # Apply negative evidence gates
        if evidence.get('has_prompt_template', False):
            confidence -= 0.30  # PromptTemplate is strong mitigation
        elif evidence.get('has_sanitization', False):
            confidence -= 0.25  # Sanitization is moderate mitigation
        elif evidence.get('has_validation', False):
            confidence -= 0.15  # Validation is weak mitigation

        # Ensure confidence stays in valid range
        return max(0.0, min(1.0, confidence))

    def _fallback_analysis(self, parsed_data: Dict[str, Any]) -> List[Finding]:
        """
        Fallback string-based analysis when AST parse fails

        Uses parser's string data instead of AST nodes
        """
        findings = []

        functions = parsed_data.get('functions', [])
        string_ops = parsed_data.get('string_operations', [])
        llm_calls = parsed_data.get('llm_api_calls', [])
        assignments = parsed_data.get('assignments', [])
        file_path = parsed_data.get('file_path', 'unknown')
        source_lines = parsed_data.get('source_lines', [])

        if not llm_calls:
            return findings

        for func in functions:
            func_name = func['name']
            func_start = func['line']
            func_end = func.get('end_line', func_start + 100)

            func_llm_calls = [
                call for call in llm_calls
                if func_start <= call['line'] <= func_end
            ]

            if not func_llm_calls:
                continue

            user_params = self._identify_user_input_params(func['args'])
            if not user_params:
                continue

            # Simple string-based taint check
            func_string_ops = [
                op for op in string_ops
                if func_start <= op['line'] <= func_end
            ]

            for llm_call in func_llm_calls:
                # Check if any user param appears in LLM call args
                llm_args_str = str(llm_call.get('args', [])) + str(llm_call.get('keywords', {}))

                for user_param in user_params:
                    if user_param in llm_args_str:
                        snippet_start = max(0, llm_call['line'] - 3)
                        snippet_end = min(len(source_lines), llm_call['line'] + 1)

                        findings.append(Finding(
                            id=f"{self.detector_id}_{file_path}_{llm_call['line']}",
                            category=f"{self.detector_id}: {self.name}",
                            severity=Severity.CRITICAL,
                            confidence=0.65,  # Lower confidence for fallback
                            title=f"User input '{user_param}' may reach LLM prompt",
                            description=(
                                f"String-based analysis suggests user input '{user_param}' "
                                f"may flow to LLM call '{llm_call['function']}' in function "
                                f"'{func_name}'. Manual verification recommended."
                            ),
                            file_path=file_path,
                            line_number=llm_call['line'],
                            code_snippet='\n'.join(source_lines[snippet_start:snippet_end]),
                            recommendation=(
                                "Review this code path for prompt injection vulnerabilities.\n"
                                "Consider using PromptTemplate or input sanitization."
                            ),
                            evidence={
                                'flow_type': 'fallback',
                                'operation_type': 'unknown',
                                'llm_function': llm_call['function'],
                                'function_name': func_name,
                            }
                        ))
                        break  # One finding per user param per LLM call

        return findings
