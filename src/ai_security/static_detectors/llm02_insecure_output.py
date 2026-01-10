"""
LLM02: Insecure Output Handling Detector

Detects unsafe usage of LLM outputs in dangerous contexts:
- XSS: Rendering in HTML/JavaScript without escaping
- Command Injection: Using in shell commands
- SQL Injection: Building SQL queries
- Code Execution: eval(), exec(), compile()
"""

import logging
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Set

from ai_security.models.finding import Finding, Severity
from ai_security.static_detectors.base_detector import BaseDetector

logger = logging.getLogger(__name__)


@dataclass
class OutputFlow:
    """Track flow of LLM output to dangerous sink"""
    llm_call_line: int
    llm_function: str
    sink_line: int
    sink_type: str  # 'xss', 'command', 'sql', 'eval'
    sink_function: str
    intermediate_vars: List[str]


class InsecureOutputDetector(BaseDetector):
    """
    Detect LLM02: Insecure Output Handling

    Detects:
    - XSS: response rendered in HTML/JS
    - Command injection: response used in subprocess/os.system
    - SQL injection: response used in SQL queries
    - Code execution: response passed to eval/exec
    """

    detector_id = "LLM02"
    name = "Insecure Output Handling"
    default_confidence_threshold = 0.6

    # Dangerous sinks for LLM output
    XSS_SINKS = {
        'render_template', 'render', 'Response', 'HttpResponse',
        'innerHTML', 'outerHTML', 'document.write', 'html()',
        'dangerouslySetInnerHTML', 'v-html'
    }

    COMMAND_SINKS = {
        'subprocess.', 'os.system', 'os.popen', 'commands.', 'shell=True',
        'Popen', 'call(', 'check_output', 'run('
    }

    SQL_SINKS = {
        'execute(', 'executemany(', 'cursor.execute', 'raw(', 'extra(',
        'SELECT', 'INSERT', 'UPDATE', 'DELETE', 'WHERE'
    }

    EVAL_SINKS = {
        'eval(', 'exec(', 'compile(', '__import__'
    }

    # Sanitization functions that reduce risk
    SANITIZATION_PATTERNS = {
        'escape', 'sanitize', 'quote', 'bleach', 'clean',
        'html.escape', 'markupsafe', 'shlex.quote', 'urllib.parse.quote'
    }

    def _gather_potential_findings(self, parsed_data: Dict[str, Any]) -> List[Finding]:
        """Find all insecure output handling"""
        findings = []

        llm_calls = parsed_data.get('llm_api_calls', [])
        assignments = parsed_data.get('assignments', [])
        functions = parsed_data.get('functions', [])
        source_lines = parsed_data.get('source_lines', [])

        if not llm_calls:
            return findings

        # For each LLM call, track where output goes
        for llm_call in llm_calls:
            llm_line = llm_call.get('line', 0)
            llm_func = llm_call.get('function', '')

            # Find the function containing this LLM call
            containing_func = self._find_containing_function(llm_line, functions)
            if not containing_func:
                continue

            func_start = containing_func['line']
            func_end = containing_func.get('end_line', func_start + 100)

            # FIRST: Check if LLM call is used inline within a dangerous sink
            # e.g., subprocess.run(openai.ChatCompletion.create(...).choices[0].message.content)
            inline_flow = self._check_inline_sink_usage(
                llm_call, llm_line, func_end, source_lines
            )
            if inline_flow:
                finding = self._create_finding(
                    flow=inline_flow,
                    llm_call=llm_call,
                    parsed_data=parsed_data,
                    func=containing_func
                )
                findings.append(finding)
                # Continue to also check variable-based flows

            # SECOND: Track variables that hold LLM output
            output_vars = self._track_output_variables(
                llm_line, func_start, func_end, assignments, source_lines
            )

            # Check if output vars reach dangerous sinks
            flows = self._find_dangerous_flows(
                output_vars, func_start, func_end, source_lines
            )

            for flow in flows:
                finding = self._create_finding(
                    flow=flow,
                    llm_call=llm_call,
                    parsed_data=parsed_data,
                    func=containing_func
                )
                findings.append(finding)

        return findings

    def _find_containing_function(
        self, line: int, functions: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """Find which function contains the given line"""
        for func in functions:
            func_start = func['line']
            func_end = func.get('end_line', func_start + 100)
            if func_start <= line <= func_end:
                return func
        return {}

    def _check_inline_sink_usage(
        self,
        llm_call: Dict[str, Any],
        llm_line: int,
        func_end: int,
        source_lines: List[str]
    ) -> Optional[OutputFlow]:
        """
        Check if LLM call output is used inline within a dangerous sink.
        E.g., subprocess.run(openai.ChatCompletion.create(...).choices[0].message.content)
        """
        # Gather lines that contain this LLM call (may span multiple lines)
        llm_func_name = llm_call.get('function', '')

        # Look for sink patterns in a window around the LLM call
        # The LLM call might span multiple lines if it has multi-line arguments
        # Look backward too, since sink might start before LLM call (e.g., eval(\n  llm_call(...)))
        search_start = max(0, llm_line - 5)  # Look back 5 lines
        search_end = min(len(source_lines), llm_line + 10)  # Look ahead up to 10 lines

        # Collect the code block containing the LLM call
        code_block = ''.join(source_lines[search_start:search_end]).lower()

        # Check if the LLM function appears within the code block
        if llm_func_name.lower() not in code_block:
            return None

        # Extract just the portion containing the LLM call
        # Look for patterns like: sink(llm_call(...).property)
        for i in range(search_start, search_end):
            line = source_lines[i].lower()

            # Check if this line contains both the LLM call and a sink
            if llm_func_name.lower() in line:
                # Check for sanitization that wraps the LLM output in the SAME expression
                # E.g., subprocess.run(shlex.quote(llm.create(...).content), shell=True)
                #       ^sink           ^sanitize   ^llm_call
                # The pattern should be: sink_func(sanitize_func(llm_call))

                # To properly check this, we need to look at the actual sink line and verify
                # that sanitization appears in the same expression between the sink and LLM call

                # First, find which line actually contains the sink
                sink_line_num = None
                for sink in list(self.COMMAND_SINKS) + list(self.XSS_SINKS) + list(self.SQL_SINKS) + list(self.EVAL_SINKS):
                    if sink.lower() in code_block:
                        # Find the line containing this sink
                        for j in range(search_start, search_end):
                            if sink.lower() in source_lines[j].lower():
                                sink_line_num = j
                                break
                        if sink_line_num:
                            break

                # Build the expression: from sink line to a few lines after (for multi-line calls)
                if sink_line_num is not None:
                    expr_start = sink_line_num
                    expr_end = min(len(source_lines), sink_line_num + 8)
                    expression = ''.join(source_lines[expr_start:expr_end]).lower()
                else:
                    expression = code_block

                has_wrapping_sanitization = False

                for pattern in self.SANITIZATION_PATTERNS:
                    pattern_lower = pattern.lower()
                    func_pattern = f"{pattern_lower}("

                    # Check if sanitization function appears in the SAME expression as sink and LLM
                    if func_pattern in expression and llm_func_name.lower() in expression:
                        # Verify that sanitization WRAPS the LLM call, not just appears before it
                        # E.g., shlex.quote(llm_call()) is valid
                        # But: shlex.quote(other), llm_call() is NOT valid (different arguments)

                        pattern_idx = expression.find(func_pattern)
                        llm_idx = expression.find(llm_func_name.lower())

                        # Sanitization must appear before LLM call
                        if not (0 <= pattern_idx < llm_idx):
                            continue

                        # Extract the substring between sanitization and LLM call
                        between = expression[pattern_idx + len(func_pattern):llm_idx]

                        # The sanitization wraps the LLM if there's ONLY whitespace/parens between them
                        # This ensures: sanitize(llm_call) not sanitize(x), llm_call
                        # Allow: whitespace, opening parens, but NOT commas or closing parens
                        if ',' in between or ')' in between:
                            # Comma or closing paren means they're separate arguments/calls
                            continue

                        # Additional check: count opening parens vs closing parens in between
                        # If balanced or more opens than closes, sanitize wraps LLM
                        opens = between.count('(')
                        closes = between.count(')')

                        # If more closes than opens, sanitize( already closed before LLM
                        if closes > opens:
                            continue

                        # Passes all checks: sanitization wraps the LLM output
                        has_wrapping_sanitization = True
                        break

                # Skip this sink if wrapping sanitization is present in the same expression
                if has_wrapping_sanitization:
                    continue

                # Check for dangerous sinks on same/subsequent lines
                # Use sink_type names that match _create_finding expectations
                for sink in self.COMMAND_SINKS:
                    if sink.lower() in code_block:
                        return OutputFlow(
                            llm_call_line=llm_line,
                            llm_function=llm_func_name,
                            sink_line=i + 1,
                            sink_type='command_injection',  # Fixed: was 'command'
                            sink_function=sink,
                            intermediate_vars=[]  # No intermediate vars for inline usage
                        )

                for sink in self.XSS_SINKS:
                    if sink.lower() in code_block:
                        return OutputFlow(
                            llm_call_line=llm_line,
                            llm_function=llm_func_name,
                            sink_line=i + 1,
                            sink_type='xss',  # Correct
                            sink_function=sink,
                            intermediate_vars=[]
                        )

                for sink in self.SQL_SINKS:
                    if sink.lower() in code_block:
                        return OutputFlow(
                            llm_call_line=llm_line,
                            llm_function=llm_func_name,
                            sink_line=i + 1,
                            sink_type='sql_injection',  # Fixed: was 'sql'
                            sink_function=sink,
                            intermediate_vars=[]
                        )

                for sink in self.EVAL_SINKS:
                    if sink.lower() in code_block:
                        return OutputFlow(
                            llm_call_line=llm_line,
                            llm_function=llm_func_name,
                            sink_line=i + 1,
                            sink_type='code_execution',  # Fixed: was 'eval'
                            sink_function=sink,
                            intermediate_vars=[]
                        )

        return None

    def _track_output_variables(
        self,
        llm_line: int,
        func_start: int,
        func_end: int,
        assignments: List[Dict[str, Any]],
        source_lines: List[str]
    ) -> Set[str]:
        """Track which variables hold LLM output"""
        output_vars = set()

        # Check if LLM call is assigned to a variable
        # Look at the line: response = llm.create(...)
        if llm_line > 0 and llm_line <= len(source_lines):
            line_content = source_lines[llm_line - 1]
            if '=' in line_content:
                # Extract variable name before =
                parts = line_content.split('=')
                if len(parts) >= 2:
                    var_name = parts[0].strip().split()[-1]
                    output_vars.add(var_name)

        # Track assignments that reference output variables
        func_assignments = [
            a for a in assignments
            if func_start <= a.get('line', 0) <= func_end
        ]

        # Iterate to find derived variables
        for _ in range(3):  # Max 3 levels of indirection
            new_vars = set()
            for assign in func_assignments:
                assign_value = assign.get('value', '')
                for output_var in output_vars:
                    if output_var in assign_value:
                        new_vars.add(assign.get('name', ''))
            output_vars.update(new_vars)

        return output_vars

    def _find_dangerous_flows(
        self,
        output_vars: Set[str],
        func_start: int,
        func_end: int,
        source_lines: List[str]
    ) -> List[OutputFlow]:
        """Find dangerous usage of output variables"""
        flows = []

        for line_num in range(func_start, min(func_end + 1, len(source_lines) + 1)):
            if line_num < 1 or line_num > len(source_lines):
                continue

            line = source_lines[line_num - 1]

            # Check if any output var appears in this line
            vars_in_line = [v for v in output_vars if v in line]
            if not vars_in_line:
                continue

            # Check for dangerous sinks
            sink_type = None
            sink_func = None

            if any(pattern in line for pattern in self.XSS_SINKS):
                sink_type = 'xss'
                sink_func = next((p for p in self.XSS_SINKS if p in line), 'render')

            elif any(pattern in line for pattern in self.COMMAND_SINKS):
                sink_type = 'command_injection'
                sink_func = next((p for p in self.COMMAND_SINKS if p in line), 'subprocess')

            elif any(pattern in line for pattern in self.SQL_SINKS):
                sink_type = 'sql_injection'
                sink_func = next((p for p in self.SQL_SINKS if p in line), 'execute')

            elif any(pattern in line for pattern in self.EVAL_SINKS):
                sink_type = 'code_execution'
                sink_func = next((p for p in self.EVAL_SINKS if p in line), 'eval')

            if sink_type:
                # Check if sanitization is present
                has_sanitization = any(
                    pattern in line for pattern in self.SANITIZATION_PATTERNS
                )

                if not has_sanitization:
                    flow = OutputFlow(
                        llm_call_line=func_start,  # Approximate
                        llm_function='llm_api',
                        sink_line=line_num,
                        sink_type=sink_type,
                        sink_function=sink_func,
                        intermediate_vars=vars_in_line
                    )
                    flows.append(flow)

        return flows

    def _create_finding(
        self,
        flow: OutputFlow,
        llm_call: Dict[str, Any],
        parsed_data: Dict[str, Any],
        func: Dict[str, Any]
    ) -> Finding:
        """Create Finding from output flow"""
        file_path = parsed_data.get('file_path', 'unknown')
        source_lines = parsed_data.get('source_lines', [])

        # Get code snippet
        snippet_start = max(0, flow.sink_line - 2)
        snippet_end = min(len(source_lines), flow.sink_line + 2)
        code_snippet = '\n'.join(source_lines[snippet_start:snippet_end])

        # Determine severity based on sink type
        severity_map = {
            'xss': Severity.HIGH,
            'command_injection': Severity.CRITICAL,
            'sql_injection': Severity.CRITICAL,
            'code_execution': Severity.CRITICAL
        }
        severity = severity_map.get(flow.sink_type, Severity.HIGH)

        # Build evidence
        evidence = {
            'sink_type': flow.sink_type,
            'sink_function': flow.sink_function,
            'output_variables': flow.intermediate_vars,
            'llm_function': llm_call.get('function', ''),
            'function_name': func['name']
        }

        # Recommendation based on sink type
        recommendations = {
            'xss': (
                "Mitigations for XSS:\n"
                "1. Use auto-escaping templates (Jinja2, Django templates)\n"
                "2. Apply HTML escaping: html.escape(response)\n"
                "3. Use Content Security Policy (CSP) headers\n"
                "4. Sanitize with bleach.clean() for rich text\n"
                "5. Never use innerHTML or dangerouslySetInnerHTML with LLM output"
            ),
            'command_injection': (
                "Mitigations for Command Injection:\n"
                "1. Never pass LLM output to shell commands\n"
                "2. Use subprocess with shell=False and list arguments\n"
                "3. Apply allowlist validation for expected values\n"
                "4. Use shlex.quote() if shell execution is unavoidable\n"
                "5. Consider alternative APIs that don't use shell"
            ),
            'sql_injection': (
                "Mitigations for SQL Injection:\n"
                "1. Use parameterized queries: cursor.execute(query, (param,))\n"
                "2. Never concatenate LLM output into SQL\n"
                "3. Use ORM query builders (SQLAlchemy, Django ORM)\n"
                "4. Apply strict input validation\n"
                "5. Use read-only database connections where possible"
            ),
            'code_execution': (
                "Mitigations for Code Execution:\n"
                "1. Never pass LLM output to eval() or exec()\n"
                "2. Use safe alternatives (ast.literal_eval for data)\n"
                "3. Implement sandboxing if code execution is required\n"
                "4. Use allowlists for permitted operations\n"
                "5. Consider structured output formats (JSON) instead"
            )
        }

        return Finding(
            id=f"{self.detector_id}_{file_path}_{flow.sink_line}",
            category=f"{self.detector_id}: {self.name}",
            severity=severity,
            confidence=0.0,  # Will be calculated
            title=f"LLM output used in dangerous {flow.sink_type} sink",
            description=(
                f"LLM output from '{llm_call.get('function', 'unknown')}' is used in "
                f"'{flow.sink_function}' on line {flow.sink_line} without sanitization. "
                f"This creates a {flow.sink_type} vulnerability where malicious LLM output "
                f"can compromise application security."
            ),
            file_path=file_path,
            line_number=flow.sink_line,
            code_snippet=code_snippet,
            recommendation=recommendations.get(flow.sink_type, "Sanitize LLM output before use."),
            evidence=evidence
        )

    def calculate_confidence(self, evidence: Dict[str, Any]) -> float:
        """Calculate confidence score for finding"""
        confidence = 0.7  # Base confidence

        # Higher confidence for critical sinks
        if evidence.get('sink_type') in ['command_injection', 'code_execution']:
            confidence += 0.2

        # Adjust based on clarity of flow
        output_vars = evidence.get('output_variables', [])
        if len(output_vars) == 1:
            confidence += 0.1  # Direct flow is clearer

        return min(1.0, confidence)
