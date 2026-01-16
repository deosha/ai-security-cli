"""
Semantic Taint Detector - Detects LLM output flowing to dangerous sinks.

This detector identifies vulnerabilities where user-controlled data passes
through LLM API calls and then reaches dangerous sinks (exec, subprocess, SQL, etc.).

Key innovation: We recognize that LLM output carries "semantic influence" from
its inputs - an attacker controlling the input can influence the output content,
even though there's no direct data flow.

Example vulnerability detected:
    user_input = request.get("query")
    summary = llm.summarize(user_input)  # Taint preserved through LLM
    execute_command(summary)              # VULNERABLE!
"""

from typing import Any, Dict, List

from aisentry.models.finding import Finding, Severity
from aisentry.static_detectors.base_detector import BaseDetector
from aisentry.utils.taint_tracker import (
    SemanticTaintPropagator,
    SemanticTaintType,
    DangerousSinkInfo,
)


class SemanticTaintDetector(BaseDetector):
    """
    Detector for semantic taint vulnerabilities through LLM calls.

    This detector builds a semantic taint graph that tracks data flow
    through LLM API calls, recognizing that LLM output carries semantic
    influence from its inputs.
    """

    detector_id = "TAINT01"
    detector_name = "Semantic Taint Analysis"

    # Lower threshold since semantic influence is subtle but real
    default_confidence_threshold = 0.5

    # Severity mapping by sink category
    SEVERITY_MAP = {
        'code_execution': Severity.CRITICAL,
        'command_injection': Severity.CRITICAL,
        'sql_injection': Severity.HIGH,
        'xss': Severity.HIGH,
        'ssrf': Severity.HIGH,
        'path_traversal': Severity.MEDIUM,
    }

    # CWE mappings for OWASP compliance
    CWE_MAP = {
        'code_execution': 'CWE-94',
        'command_injection': 'CWE-78',
        'sql_injection': 'CWE-89',
        'xss': 'CWE-79',
        'ssrf': 'CWE-918',
        'path_traversal': 'CWE-22',
    }

    def __init__(self, confidence_threshold: float = None, verbose: bool = False):
        super().__init__(confidence_threshold, verbose)

    def _gather_potential_findings(self, parsed_data: Dict[str, Any]) -> List[Finding]:
        """
        Gather all potential semantic taint findings.

        Steps:
        1. Build semantic taint graph with LLM propagation
        2. Identify dangerous sinks in the code
        3. Check if tainted data (with LLM hops) reaches sinks
        4. Generate findings for vulnerable paths
        """
        findings = []
        file_path = parsed_data.get('file_path', '')
        source_lines = parsed_data.get('source_lines', [])

        # Build taint graph with semantic propagation
        propagator = SemanticTaintPropagator(parsed_data)
        taint_graph = propagator.build_taint_graph()

        # Get dangerous sinks
        sinks = propagator.get_dangerous_sinks()

        # Check each sink for semantic taint flows
        for sink in sinks:
            # Get flows that reach this sink through LLM calls
            flows = propagator.analyze_sink_reachability(sink)

            for flow in flows:
                # Only report flows with semantic influence (LLM hop)
                if flow.get('llm_hops', 0) == 0:
                    continue

                finding = self._create_finding(
                    sink=sink,
                    flow=flow,
                    file_path=file_path,
                    source_lines=source_lines
                )
                findings.append(finding)

        return findings

    def _create_finding(
        self,
        sink: DangerousSinkInfo,
        flow: Dict[str, Any],
        file_path: str,
        source_lines: List[str]
    ) -> Finding:
        """Create a Finding from a semantic taint flow."""

        # Build taint path description
        path = flow.get('path', [])
        path_desc = self._describe_taint_path(path)

        # Get code snippet
        snippet = self._get_snippet(source_lines, sink.line)

        # Determine severity
        severity = self.SEVERITY_MAP.get(sink.category, Severity.MEDIUM)
        cwe_id = self.CWE_MAP.get(sink.category, 'CWE-74')

        # Build title
        title = f"LLM output flows to {sink.category.replace('_', ' ')} sink"

        # Build description
        description = self._build_description(sink, flow, path_desc)

        # Build recommendation
        recommendation = self._get_recommendation(sink.category)

        return Finding(
            id=f"TAINT01_{file_path}_{sink.line}_{sink.function_name}",
            category="Semantic Taint: LLM Output to Dangerous Sink",
            severity=severity,
            confidence=0.0,  # Will be calculated by calculate_confidence
            title=title,
            description=description,
            file_path=file_path,
            line_number=sink.line,
            code_snippet=snippet,
            recommendation=recommendation,
            cwe_id=cwe_id,
            owasp_category="LLM02",  # Insecure Output Handling
            evidence={
                'sink_category': sink.category,
                'sink_function': sink.function_name,
                'llm_hops': flow.get('llm_hops', 1),
                'influence_strength': flow.get('influence_strength', 0.5),
                'source_var': flow.get('source_var'),
                'source_line': flow.get('source_line'),
                'source_type': flow.get('source_type'),
                'has_user_input': flow.get('has_user_input', False),
                'taint_path': path_desc,
                'detection_method': 'semantic_taint',
            }
        )

    def _describe_taint_path(self, path: List[Any]) -> str:
        """Create human-readable description of taint path."""
        if not path:
            return "Unknown path"

        descriptions = []
        for node in path:
            var_name = node.variable_name
            line = node.line_number
            llm_hops = node.llm_hops

            if SemanticTaintType.USER_INPUT in node.taint_types:
                descriptions.append(f"{var_name} (user input, line {line})")
            elif SemanticTaintType.SEMANTIC_INFLUENCE in node.taint_types:
                descriptions.append(f"{var_name} (LLM output hop {llm_hops}, line {line})")
            else:
                descriptions.append(f"{var_name} (line {line})")

        return " → ".join(descriptions)

    def _build_description(
        self,
        sink: DangerousSinkInfo,
        flow: Dict[str, Any],
        path_desc: str
    ) -> str:
        """Build detailed finding description."""
        llm_hops = flow.get('llm_hops', 1)
        influence = flow.get('influence_strength', 0.5)
        source_type = flow.get('source_type', 'unknown')

        desc = [
            f"User-controlled data flows through {llm_hops} LLM call(s) and reaches "
            f"a {sink.category.replace('_', ' ')} sink at `{sink.function_name}()`.",
            "",
            "**Why this is dangerous:** Even though the data is transformed by the LLM, "
            "an attacker can craft inputs that influence the LLM output to contain "
            "malicious payloads. This is known as 'indirect prompt injection'.",
            "",
            f"**Taint path:** {path_desc}",
            "",
            f"**Influence strength:** {influence:.0%} (based on input position and LLM hops)",
        ]

        if source_type == 'user_input':
            desc.append("\n**Source:** Direct user input (highest risk)")

        return "\n".join(desc)

    def _get_recommendation(self, sink_category: str) -> str:
        """Get remediation recommendation for the sink category."""
        recommendations = {
            'code_execution': (
                "1. NEVER execute LLM output as code. Use structured outputs (JSON schema) instead.\n"
                "2. If code execution is required, use a sandboxed environment (e.g., Docker, gVisor).\n"
                "3. Implement strict output validation before any execution.\n"
                "4. Consider using ast.literal_eval() for simple data parsing instead of eval()."
            ),
            'command_injection': (
                "1. Avoid passing LLM output to shell commands entirely.\n"
                "2. If shell commands are necessary, use subprocess with shell=False and list arguments.\n"
                "3. Implement strict allowlisting of permitted commands.\n"
                "4. Use shlex.quote() if shell=True is unavoidable (not recommended)."
            ),
            'sql_injection': (
                "1. Always use parameterized queries, never string interpolation with LLM output.\n"
                "2. Use ORM methods that handle escaping automatically.\n"
                "3. Validate LLM output against expected schema before database operations.\n"
                "4. Implement least-privilege database accounts."
            ),
            'xss': (
                "1. Always escape LLM output before rendering in HTML.\n"
                "2. Use template engines with auto-escaping enabled.\n"
                "3. Implement Content Security Policy (CSP) headers.\n"
                "4. Use bleach.clean() or similar sanitization libraries."
            ),
            'ssrf': (
                "1. Never use LLM output directly as URLs.\n"
                "2. Implement URL allowlisting with strict domain validation.\n"
                "3. Use urlparse to validate and restrict URL components.\n"
                "4. Consider using a proxy service for external requests."
            ),
            'path_traversal': (
                "1. Never use LLM output directly in file paths.\n"
                "2. Use os.path.basename() to strip directory components.\n"
                "3. Validate paths are within expected directories using realpath.\n"
                "4. Implement file operation allowlisting."
            ),
        }

        return recommendations.get(
            sink_category,
            "Validate and sanitize all LLM output before use in sensitive operations."
        )

    def _get_snippet(self, source_lines: List[str], line_num: int, context: int = 3) -> str:
        """Get code snippet around the vulnerable line."""
        if not source_lines:
            return ""

        start = max(0, line_num - context - 1)
        end = min(len(source_lines), line_num + context)

        lines = []
        for i in range(start, end):
            prefix = ">>> " if i == line_num - 1 else "    "
            lines.append(f"{prefix}{i + 1}: {source_lines[i]}")

        return "\n".join(lines)

    def calculate_confidence(self, evidence: Dict[str, Any]) -> float:
        """
        Calculate confidence score based on evidence.

        Factors:
        - Influence strength (accounts for decay through LLM hops)
        - Number of LLM hops (more hops = less certainty)
        - Sink severity (critical sinks boost confidence)
        - Source type (user input = higher confidence)
        """
        # Base confidence from influence strength
        influence_strength = evidence.get('influence_strength', 0.5)
        confidence = influence_strength

        # Adjust for LLM hops (each hop adds uncertainty)
        llm_hops = evidence.get('llm_hops', 1)
        hop_modifier = 0.95 ** (llm_hops - 1)  # 5% decay per additional hop
        confidence *= hop_modifier

        # Boost for critical sinks
        sink_category = evidence.get('sink_category', '')
        if sink_category in ('code_execution', 'command_injection'):
            confidence = min(1.0, confidence + 0.15)
        elif sink_category in ('sql_injection', 'ssrf'):
            confidence = min(1.0, confidence + 0.10)

        # Boost for confirmed user input
        if evidence.get('has_user_input'):
            confidence = min(1.0, confidence + 0.10)

        return max(0.0, min(1.0, confidence))

    def apply_mitigations(self, confidence: float, evidence: Dict[str, Any]) -> float:
        """
        Apply mitigation-based confidence demotions.

        Checks for common mitigations in the evidence.
        """
        # Note: Most mitigations are already handled by the base class
        # via the negative evidence patterns

        # Additional semantic-specific mitigations could be added here
        # For example, structured output validation before sink

        return confidence
