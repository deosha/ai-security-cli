"""
Shared AST-Based Taint Tracking Module

Provides unified taint analysis for detecting data flows from sources to sinks.
Used by LLM01, LLM02, LLM07, and LLM08 detectors.

Features:
- Single-hop and multi-hop variable resolution
- Sink-specific validation checks (parameterized SQL, shell=False, URL allowlists)
- Structural validation detection (sanitization wrapping)
- Confidence tiers based on flow type and evidence
"""

import ast
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple

from aisentry.utils.ast_utils import (
    get_full_call_name,
    get_call_name,
    names_in_expr,
    resolve_single_hop,
)


class FlowType(Enum):
    """Type of taint flow between source and sink"""
    DIRECT = "direct"           # Source directly in sink call
    SINGLE_HOP = "single_hop"   # One variable assignment between source and sink
    TWO_HOP = "two_hop"         # Two variable assignments
    TRANSITIVE = "transitive"   # Multiple hops or ambiguous


class SinkType(Enum):
    """Categories of dangerous sinks"""
    LLM_PROMPT = "llm_prompt"       # LLM01: User input in LLM prompts
    XSS = "xss"                     # LLM02: HTML rendering
    COMMAND = "command_injection"   # LLM02: Shell commands
    SQL = "sql_injection"           # LLM02: SQL queries
    CODE_EXEC = "code_execution"    # LLM02: eval/exec
    PLUGIN = "plugin"               # LLM07: Plugin execution
    FILE = "file_access"            # LLM07: File operations
    HTTP = "http_request"           # LLM07/LLM08: HTTP requests


@dataclass
class TaintSource:
    """Represents a source of tainted data"""
    var_name: str
    line: int
    source_type: str  # 'user_param', 'llm_output', 'external_input', etc.
    node: Optional[ast.AST] = None


@dataclass
class TaintSink:
    """Represents a dangerous sink"""
    func_name: str
    line: int
    sink_type: SinkType
    node: Optional[ast.AST] = None
    keyword_arg: Optional[str] = None  # e.g., 'shell', 'messages'


@dataclass
class TaintFlow:
    """Represents a flow from source to sink"""
    source: TaintSource
    sink: TaintSink
    flow_type: FlowType
    intermediate_vars: List[str] = field(default_factory=list)
    evidence: Dict[str, Any] = field(default_factory=dict)

    @property
    def base_confidence(self) -> float:
        """Get base confidence based on flow type"""
        confidence_map = {
            FlowType.DIRECT: 0.95,
            FlowType.SINGLE_HOP: 0.85,
            FlowType.TWO_HOP: 0.75,
            FlowType.TRANSITIVE: 0.65,
        }
        return confidence_map.get(self.flow_type, 0.60)


@dataclass
class SinkValidation:
    """Result of sink-specific validation checks"""
    is_safe: bool
    reason: Optional[str] = None
    confidence_adjustment: float = 0.0  # Negative reduces confidence


class TaintTracker:
    """
    AST-based taint tracking for security analysis.

    Tracks data flow from sources (user input, LLM output) to sinks
    (shell commands, SQL queries, HTML rendering, etc.)
    """

    # Sink patterns by type
    SINK_PATTERNS: Dict[SinkType, Set[str]] = {
        SinkType.COMMAND: {
            'subprocess.run', 'subprocess.call', 'subprocess.Popen',
            'subprocess.check_output', 'subprocess.check_call',
            'os.system', 'os.popen', 'os.exec', 'os.spawn',
            'commands.getoutput', 'commands.getstatusoutput',
        },
        SinkType.SQL: {
            'execute', 'executemany', 'cursor.execute',
            'raw', 'extra', 'RawSQL',
        },
        SinkType.XSS: {
            'render_template', 'render', 'render_to_string',
            'innerHTML', 'outerHTML', 'document.write',
            'dangerouslySetInnerHTML', 'Markup', 'mark_safe',
        },
        SinkType.CODE_EXEC: {
            'eval', 'exec', 'compile', '__import__',
            'importlib.import_module',
        },
        SinkType.FILE: {
            'open', 'read', 'write', 'unlink', 'remove',
            'shutil.rmtree', 'os.remove', 'os.unlink',
            'pathlib.Path.write_text', 'pathlib.Path.read_text',
        },
        SinkType.HTTP: {
            'requests.get', 'requests.post', 'requests.put',
            'requests.delete', 'requests.patch', 'requests.request',
            'httpx.get', 'httpx.post', 'httpx.Client',
            'urllib.request.urlopen', 'aiohttp.ClientSession',
        },
        SinkType.PLUGIN: {
            'importlib.import_module', '__import__',
            'exec', 'eval', 'load_module', 'runpy.run_module',
        },
    }

    # Sanitization patterns by sink type
    SANITIZATION_BY_SINK: Dict[SinkType, Set[str]] = {
        SinkType.COMMAND: {
            'shlex.quote', 'shlex.split', 'pipes.quote',
            'shell=False',  # Special: keyword arg check
        },
        SinkType.SQL: {
            'parameterized', '%s', '?',  # Placeholders
            'prepared', 'bind', 'params=',
        },
        SinkType.XSS: {
            'html.escape', 'cgi.escape', 'markupsafe.escape',
            'bleach.clean', 'nh3.clean', 'escape(',
            'autoescape', 'Markup.escape',
        },
        SinkType.CODE_EXEC: {
            'ast.literal_eval', 'json.loads',  # Safe alternatives
            'sandbox', 'restricted',
        },
        SinkType.FILE: {
            'os.path.basename', 'pathlib.Path.name',
            'secure_filename', 'validate_path',
        },
        SinkType.HTTP: {
            'allowlist', 'whitelist', 'allowed_domains',
            'validate_url', 'urlparse',
        },
    }

    # Validation patterns by sink type
    VALIDATION_PATTERNS: Dict[SinkType, Set[str]] = {
        SinkType.COMMAND: {'allowlist', 'whitelist', 'permitted_commands'},
        SinkType.SQL: {'validate', 'schema', 'pydantic'},
        SinkType.XSS: {'validate', 'strip_tags', 'clean'},
        SinkType.FILE: {'allowed_paths', 'base_dir', 'secure_filename'},
        SinkType.HTTP: {'allowed_hosts', 'allowed_domains', 'url_validator'},
    }

    def __init__(self, func_node: ast.FunctionDef, source_lines: List[str]):
        """
        Initialize taint tracker for a function.

        Args:
            func_node: AST node of the function to analyze
            source_lines: Source code lines for context
        """
        self.func_node = func_node
        self.source_lines = source_lines
        self.func_body = func_node.body

        # Cache assignments for faster lookup
        self._assignment_cache: Dict[str, List[Tuple[int, ast.AST]]] = {}
        self._build_assignment_cache()

    def _build_assignment_cache(self) -> None:
        """Build cache of variable assignments in function"""
        for stmt in ast.walk(self.func_node):
            if isinstance(stmt, ast.Assign):
                for target in stmt.targets:
                    if isinstance(target, ast.Name):
                        var_name = target.id
                        if var_name not in self._assignment_cache:
                            self._assignment_cache[var_name] = []
                        self._assignment_cache[var_name].append(
                            (stmt.lineno, stmt.value)
                        )

    def trace_flows(
        self,
        sources: List[TaintSource],
        sink: TaintSink,
        max_hops: int = 2
    ) -> List[TaintFlow]:
        """
        Trace taint flows from sources to a sink.

        Args:
            sources: List of taint sources to track
            sink: The sink to check for tainted data
            max_hops: Maximum number of variable hops to track

        Returns:
            List of TaintFlow objects for detected flows
        """
        flows = []
        source_names = {s.var_name for s in sources}

        # Find the sink node
        sink_node = self._find_call_at_line(sink.line)
        if not sink_node:
            return flows

        # Extract variables used in sink
        sink_vars = self._extract_sink_vars(sink_node, sink.sink_type)

        # Check for direct flows (source directly in sink)
        direct_taints = sink_vars & source_names
        for var in direct_taints:
            source = next(s for s in sources if s.var_name == var)

            # Check sink-specific validation
            validation = self._check_sink_validation(sink_node, sink.sink_type)
            if validation.is_safe:
                continue

            flows.append(TaintFlow(
                source=source,
                sink=sink,
                flow_type=FlowType.DIRECT,
                intermediate_vars=[],
                evidence={
                    'operation': 'direct_usage',
                    'sink_validation': validation.reason,
                }
            ))

        # Check for single-hop flows
        intermediate_vars = sink_vars - source_names
        for var in intermediate_vars:
            resolved = resolve_single_hop(self.func_body, var, sink.line)
            if not resolved:
                continue

            resolved_names = names_in_expr(resolved)
            tainted_sources = resolved_names & source_names

            if tainted_sources:
                source_var = list(tainted_sources)[0]
                source = next(s for s in sources if s.var_name == source_var)

                # Check for sanitization wrapping
                if self._has_sanitization_wrapper(resolved, sink.sink_type):
                    continue

                # Check sink-specific validation
                validation = self._check_sink_validation(sink_node, sink.sink_type)
                if validation.is_safe:
                    continue

                flows.append(TaintFlow(
                    source=source,
                    sink=sink,
                    flow_type=FlowType.SINGLE_HOP,
                    intermediate_vars=[var],
                    evidence={
                        'operation': self._classify_operation(resolved),
                        'intermediate_var': var,
                        'sink_validation': validation.reason,
                    }
                ))
            elif max_hops >= 2:
                # Check two-hop flows
                for ref_var in resolved_names - source_names:
                    var_line = self._get_assignment_line(var, sink.line)
                    resolved2 = resolve_single_hop(self.func_body, ref_var, var_line)
                    if not resolved2:
                        continue

                    resolved2_names = names_in_expr(resolved2)
                    tainted_sources2 = resolved2_names & source_names

                    if tainted_sources2:
                        source_var = list(tainted_sources2)[0]
                        source = next(s for s in sources if s.var_name == source_var)

                        # Check for sanitization wrapping
                        if self._has_sanitization_wrapper(resolved, sink.sink_type):
                            continue
                        if self._has_sanitization_wrapper(resolved2, sink.sink_type):
                            continue

                        validation = self._check_sink_validation(sink_node, sink.sink_type)
                        if validation.is_safe:
                            continue

                        flows.append(TaintFlow(
                            source=source,
                            sink=sink,
                            flow_type=FlowType.TWO_HOP,
                            intermediate_vars=[ref_var, var],
                            evidence={
                                'operation': self._classify_operation(resolved),
                                'intermediate_vars': [ref_var, var],
                                'sink_validation': validation.reason,
                            }
                        ))
                        break

        return flows

    def _find_call_at_line(self, line: int) -> Optional[ast.Call]:
        """Find a Call node at a specific line"""
        for node in ast.walk(self.func_node):
            if isinstance(node, ast.Call) and hasattr(node, 'lineno'):
                if node.lineno == line:
                    return node
        return None

    def _extract_sink_vars(
        self,
        call_node: ast.Call,
        sink_type: SinkType
    ) -> Set[str]:
        """Extract variable names used in sink call arguments"""
        vars_used = set()

        # Get all variables from arguments
        for arg in call_node.args:
            vars_used.update(names_in_expr(arg))

        for kw in call_node.keywords:
            vars_used.update(names_in_expr(kw.value))

        return vars_used

    def _check_sink_validation(
        self,
        sink_node: ast.Call,
        sink_type: SinkType
    ) -> SinkValidation:
        """
        Check sink-specific validation patterns.

        Returns SinkValidation indicating if the sink is properly protected.
        """
        func_name = get_full_call_name(sink_node)

        # Command injection: check for shell=False or list arguments
        if sink_type == SinkType.COMMAND:
            return self._validate_command_sink(sink_node)

        # SQL injection: check for parameterized queries
        elif sink_type == SinkType.SQL:
            return self._validate_sql_sink(sink_node)

        # XSS: check for HTML escaping
        elif sink_type == SinkType.XSS:
            return self._validate_xss_sink(sink_node)

        # HTTP: check for URL allowlists
        elif sink_type == SinkType.HTTP:
            return self._validate_http_sink(sink_node)

        return SinkValidation(is_safe=False, reason="no_validation_detected")

    def _validate_command_sink(self, sink_node: ast.Call) -> SinkValidation:
        """
        Validate command injection sink.

        Safe patterns:
        - subprocess.run([cmd, arg1, arg2]) with list args
        - subprocess.run(..., shell=False)
        - shlex.quote() wrapping

        Unsafe patterns:
        - subprocess.run(cmd_string, shell=True)
        - os.system(cmd_string)
        """
        func_name = get_full_call_name(sink_node)

        # os.system always takes string - never safe with tainted data
        if 'os.system' in func_name or 'os.popen' in func_name:
            return SinkValidation(
                is_safe=False,
                reason="os.system/popen_always_unsafe"
            )

        # Check subprocess calls
        if 'subprocess' in func_name:
            # Check shell= keyword
            for kw in sink_node.keywords:
                if kw.arg == 'shell':
                    if isinstance(kw.value, ast.Constant):
                        if kw.value.value is True:
                            return SinkValidation(
                                is_safe=False,
                                reason="shell=True"
                            )
                        elif kw.value.value is False:
                            # shell=False is safe IF using list args
                            if sink_node.args and isinstance(sink_node.args[0], ast.List):
                                return SinkValidation(
                                    is_safe=True,
                                    reason="shell=False_with_list_args"
                                )

            # No shell= kwarg - check if first arg is a list
            if sink_node.args:
                first_arg = sink_node.args[0]
                if isinstance(first_arg, ast.List):
                    return SinkValidation(
                        is_safe=True,
                        reason="list_args_default_shell_false"
                    )

        return SinkValidation(is_safe=False, reason="no_shell_protection")

    def _validate_sql_sink(self, sink_node: ast.Call) -> SinkValidation:
        """
        Validate SQL injection sink.

        Safe patterns:
        - cursor.execute(query, (params,))  # Parameterized
        - cursor.execute(query, params=[...])

        Unsafe patterns:
        - cursor.execute(f"SELECT * FROM {table}")  # String interpolation
        - cursor.execute("SELECT * FROM " + table)  # Concatenation
        """
        # Check if there's a second argument (parameters)
        if len(sink_node.args) >= 2:
            return SinkValidation(
                is_safe=True,
                reason="parameterized_query"
            )

        # Check for params= keyword
        for kw in sink_node.keywords:
            if kw.arg in ('params', 'parameters', 'args'):
                return SinkValidation(
                    is_safe=True,
                    reason="parameterized_query_kwarg"
                )

        # Check if first arg is a simple string constant (no interpolation)
        if sink_node.args:
            first_arg = sink_node.args[0]
            if isinstance(first_arg, ast.Constant) and isinstance(first_arg.value, str):
                # Plain string - safe if no external vars
                return SinkValidation(
                    is_safe=True,
                    reason="constant_query"
                )

        return SinkValidation(is_safe=False, reason="no_parameterization")

    def _validate_xss_sink(self, sink_node: ast.Call) -> SinkValidation:
        """
        Validate XSS sink.

        Safe patterns:
        - html.escape(data)
        - bleach.clean(data)
        - Template with autoescape=True

        Note: Context matters - JSON API responses are safe even without escaping
        """
        # XSS validation is primarily done via wrapper detection
        # This function checks for template autoescape settings

        for kw in sink_node.keywords:
            if kw.arg == 'autoescape':
                if isinstance(kw.value, ast.Constant) and kw.value.value is True:
                    return SinkValidation(
                        is_safe=True,
                        reason="autoescape_enabled"
                    )

        return SinkValidation(is_safe=False, reason="no_html_escaping")

    def _validate_http_sink(self, sink_node: ast.Call) -> SinkValidation:
        """
        Validate HTTP request sink.

        Safe patterns:
        - URL from allowlist
        - URL validation before use
        - Hardcoded URL

        Unsafe patterns:
        - User-controlled URL without validation
        """
        # Check if URL is a constant
        if sink_node.args:
            first_arg = sink_node.args[0]
            if isinstance(first_arg, ast.Constant) and isinstance(first_arg.value, str):
                return SinkValidation(
                    is_safe=True,
                    reason="constant_url"
                )

        # Check for url= keyword with constant
        for kw in sink_node.keywords:
            if kw.arg == 'url':
                if isinstance(kw.value, ast.Constant):
                    return SinkValidation(
                        is_safe=True,
                        reason="constant_url_kwarg"
                    )

        return SinkValidation(is_safe=False, reason="dynamic_url")

    def _has_sanitization_wrapper(
        self,
        node: ast.AST,
        sink_type: SinkType
    ) -> bool:
        """
        Check if an expression is wrapped by a sanitization function.

        Examples:
        - shlex.quote(user_input) for command injection
        - html.escape(llm_output) for XSS
        - validate_url(url) for HTTP
        """
        if not isinstance(node, ast.Call):
            return False

        func_name = get_full_call_name(node)
        sanitizers = self.SANITIZATION_BY_SINK.get(sink_type, set())

        for sanitizer in sanitizers:
            if sanitizer in func_name.lower():
                return True

        return False

    def _classify_operation(self, node: ast.AST) -> str:
        """Classify the type of string operation"""
        if isinstance(node, ast.JoinedStr):
            return 'f-string'
        elif isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            return 'concatenation'
        elif isinstance(node, ast.Call):
            func_name = get_call_name(node) or ''
            if 'format' in func_name.lower():
                return 'format_call'
            return 'call'
        return 'assignment'

    def _get_assignment_line(self, var_name: str, max_line: int) -> int:
        """Get the line number of the most recent assignment to a variable"""
        if var_name in self._assignment_cache:
            valid = [
                (line, _) for line, _ in self._assignment_cache[var_name]
                if line < max_line
            ]
            if valid:
                return max(valid, key=lambda x: x[0])[0]
        return max_line

    def check_structural_validation(
        self,
        source: TaintSource,
        sink: TaintSink
    ) -> bool:
        """
        Check if there's structural validation between source and sink.

        Looks for validation patterns like:
        - if not validate(source): return
        - assert is_valid(source)
        - try: validate(source) except: ...
        """
        validation_patterns = self.VALIDATION_PATTERNS.get(sink.sink_type, set())

        # Check statements between source and sink lines
        for stmt in self.func_body:
            if not hasattr(stmt, 'lineno'):
                continue

            # Only check between source and sink
            if not (source.line <= stmt.lineno < sink.line):
                continue

            # Check for validation in if statements
            if isinstance(stmt, ast.If):
                test_str = ast.dump(stmt.test).lower()
                for pattern in validation_patterns:
                    if pattern in test_str:
                        return True

            # Check for assert statements
            elif isinstance(stmt, ast.Assert):
                test_str = ast.dump(stmt.test).lower()
                for pattern in validation_patterns:
                    if pattern in test_str:
                        return True

            # Check for try/except with validation
            elif isinstance(stmt, ast.Try):
                for try_stmt in stmt.body:
                    if isinstance(try_stmt, ast.Expr) and isinstance(try_stmt.value, ast.Call):
                        func_name = get_full_call_name(try_stmt.value)
                        for pattern in validation_patterns:
                            if pattern in func_name.lower():
                                return True

        return False


def calculate_flow_confidence(
    flow: TaintFlow,
    has_structural_validation: bool = False
) -> float:
    """
    Calculate final confidence for a taint flow.

    Base confidence by flow type:
    - Direct: 0.95
    - Single-hop: 0.85
    - Two-hop: 0.75
    - Transitive: 0.65

    Adjustments:
    - Has sanitization wrapper: -0.30 (should not reach here)
    - Has structural validation: -0.20
    - f-string operation: +0.05 (clearer intent)
    - Assignment only: -0.10 (more ambiguous)
    """
    confidence = flow.base_confidence

    # Adjust for structural validation
    if has_structural_validation:
        confidence -= 0.20

    # Adjust based on operation type
    operation = flow.evidence.get('operation', '')
    if operation == 'f-string':
        confidence += 0.05
    elif operation == 'assignment':
        confidence -= 0.10

    return max(0.0, min(1.0, confidence))


def identify_sink_type(func_name: str) -> Optional[SinkType]:
    """
    Identify the sink type from a function name.

    Args:
        func_name: Full or partial function name

    Returns:
        SinkType if recognized, None otherwise
    """
    func_lower = func_name.lower()

    for sink_type, patterns in TaintTracker.SINK_PATTERNS.items():
        for pattern in patterns:
            if pattern.lower() in func_lower:
                return sink_type

    return None
