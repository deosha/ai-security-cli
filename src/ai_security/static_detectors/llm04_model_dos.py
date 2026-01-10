"""
LLM04: Model Denial of Service Detector

Detects vulnerabilities that enable resource exhaustion attacks:
- Missing rate limiting on LLM endpoints
- No input length validation
- Recursive/looping LLM calls
- Missing timeout configuration
- Unbounded context window usage
"""

import logging
from typing import Any, Dict, List

from ai_security.models.finding import Finding, Severity
from ai_security.static_detectors.base_detector import BaseDetector

logger = logging.getLogger(__name__)


class ModelDOSDetector(BaseDetector):
    """
    Detect LLM04: Model Denial of Service

    Detects:
    - LLM calls without rate limiting
    - Missing input length validation
    - Recursive/looping LLM calls
    - No timeout configuration
    - Unbounded token/context usage
    """

    detector_id = "LLM04"
    name = "Model Denial of Service"
    default_confidence_threshold = 0.5

    # Rate limiting indicators (positive)
    RATE_LIMIT_PATTERNS = {
        'rate_limit', 'ratelimit', 'throttle', 'Limiter',
        '@limiter', 'RateLimiter', 'TokenBucket', 'CircuitBreaker'
    }

    # Timeout patterns (positive)
    TIMEOUT_PATTERNS = {
        'timeout', 'max_time', 'deadline', 'time_limit'
    }

    # Length validation patterns (positive)
    LENGTH_VALIDATION_PATTERNS = {
        'len(', 'max_length', 'max_tokens', 'limit', 'truncate'
    }

    # Loop indicators (negative - risk)
    LOOP_PATTERNS = {
        'while', 'for ', 'loop', 'recursive'
    }

    # Resource limit patterns (positive)
    RESOURCE_LIMIT_PATTERNS = {
        'max_tokens', 'max_length', 'token_limit', 'context_limit'
    }

    def _gather_potential_findings(self, parsed_data: Dict[str, Any]) -> List[Finding]:
        """Find Model DoS vulnerabilities"""
        findings = []

        functions = parsed_data.get('functions', [])
        llm_calls = parsed_data.get('llm_api_calls', [])
        source_lines = parsed_data.get('source_lines', [])

        if not llm_calls:
            return findings

        # Check each function with LLM calls
        for func in functions:
            func_name = func['name']
            func_start = func['line']
            func_end = func.get('end_line', func_start + 100)

            # Find LLM calls in this function
            func_llm_calls = [
                call for call in llm_calls
                if func_start <= call.get('line', 0) <= func_end
            ]

            if not func_llm_calls:
                continue

            # Check for various DoS risks
            risks = []

            # Risk 1: No rate limiting
            if not self._has_rate_limiting(func_start, func_end, source_lines):
                risks.append('no_rate_limiting')

            # Risk 2: No input length validation
            if not self._has_length_validation(func, func_start, func_end, source_lines):
                risks.append('no_length_validation')

            # Risk 3: LLM calls in loops
            if self._has_llm_in_loop(func_llm_calls, func_start, func_end, source_lines):
                risks.append('llm_in_loop')

            # Risk 4: No timeout configuration
            if not self._has_timeout(func_llm_calls, source_lines):
                risks.append('no_timeout')

            # Risk 5: No token limits
            if not self._has_token_limits(func_llm_calls, source_lines):
                risks.append('no_token_limits')

            # Create findings for identified risks
            if risks:
                finding = self._create_dos_finding(
                    func=func,
                    risks=risks,
                    llm_calls=func_llm_calls,
                    source_lines=source_lines,
                    parsed_data=parsed_data
                )
                findings.append(finding)

        return findings

    def _has_rate_limiting(
        self, func_start: int, func_end: int, source_lines: List[str]
    ) -> bool:
        """Check if function has rate limiting"""
        # Check function decorator lines (before function definition)
        for line_num in range(max(0, func_start - 5), func_start):
            if line_num < len(source_lines):
                line = source_lines[line_num].lower()
                if any(pattern in line for pattern in self.RATE_LIMIT_PATTERNS):
                    return True

        # Check within function
        for line_num in range(func_start, min(func_end + 1, len(source_lines) + 1)):
            if line_num > 0 and line_num <= len(source_lines):
                line = source_lines[line_num - 1].lower()
                if any(pattern in line for pattern in self.RATE_LIMIT_PATTERNS):
                    return True

        return False

    def _has_length_validation(
        self, func: Dict[str, Any], func_start: int, func_end: int, source_lines: List[str]
    ) -> bool:
        """Check if function validates input length"""
        # Check function parameters for user input
        args = func.get('args', [])
        has_input_param = any(
            any(pattern in arg.lower() for pattern in ['user', 'input', 'query', 'message'])
            for arg in args
        )

        if not has_input_param:
            return True  # No user input, no validation needed

        # Check for length validation
        for line_num in range(func_start, min(func_end + 1, len(source_lines) + 1)):
            if line_num > 0 and line_num <= len(source_lines):
                line = source_lines[line_num - 1].lower()
                if any(pattern in line for pattern in self.LENGTH_VALIDATION_PATTERNS):
                    return True

        return False

    def _has_llm_in_loop(
        self,
        llm_calls: List[Dict[str, Any]],
        func_start: int,
        func_end: int,
        source_lines: List[str]
    ) -> bool:
        """Check if LLM calls are inside loops"""
        for llm_call in llm_calls:
            llm_line = llm_call.get('line', 0)

            # Look backwards from LLM call to find loop keywords
            for line_num in range(max(func_start, llm_line - 10), llm_line):
                if line_num > 0 and line_num <= len(source_lines):
                    line = source_lines[line_num - 1].lower()
                    # Check indentation and loop keywords
                    if any(pattern in line for pattern in self.LOOP_PATTERNS):
                        # Simple heuristic: if 'while' or 'for' appears before LLM call, likely in loop
                        return True

        return False

    def _has_timeout(
        self, llm_calls: List[Dict[str, Any]], source_lines: List[str]
    ) -> bool:
        """Check if LLM calls have timeout configuration"""
        for llm_call in llm_calls:
            line_num = llm_call.get('line', 0)
            if line_num > 0 and line_num <= len(source_lines):
                # Check the LLM call line and next few lines for timeout
                for offset in range(0, 5):
                    check_line = line_num + offset
                    if check_line <= len(source_lines):
                        line = source_lines[check_line - 1].lower()
                        if any(pattern in line for pattern in self.TIMEOUT_PATTERNS):
                            return True

        return False

    def _has_token_limits(
        self, llm_calls: List[Dict[str, Any]], source_lines: List[str]
    ) -> bool:
        """Check if LLM calls have token/length limits"""
        for llm_call in llm_calls:
            line_num = llm_call.get('line', 0)
            if line_num > 0 and line_num <= len(source_lines):
                # Check the LLM call line and next few lines for token limits
                for offset in range(0, 5):
                    check_line = line_num + offset
                    if check_line <= len(source_lines):
                        line = source_lines[check_line - 1].lower()
                        if any(pattern in line for pattern in self.RESOURCE_LIMIT_PATTERNS):
                            return True

        return False

    def _create_dos_finding(
        self,
        func: Dict[str, Any],
        risks: List[str],
        llm_calls: List[Dict[str, Any]],
        source_lines: List[str],
        parsed_data: Dict[str, Any]
    ) -> Finding:
        """Create DoS finding based on identified risks"""
        file_path = parsed_data.get('file_path', 'unknown')
        line_num = func['line']

        snippet_start = max(0, line_num - 1)
        snippet_end = min(len(source_lines), line_num + 10)
        code_snippet = '\n'.join(source_lines[snippet_start:snippet_end])

        # Determine severity based on risk count
        risk_count = len(risks)
        if risk_count >= 4:
            severity = Severity.CRITICAL
            confidence = 0.8
        elif risk_count >= 3:
            severity = Severity.HIGH
            confidence = 0.7
        elif risk_count >= 2:
            severity = Severity.MEDIUM
            confidence = 0.6
        else:
            severity = Severity.LOW
            confidence = 0.5

        # Build risk description
        risk_descriptions = {
            'no_rate_limiting': 'No rate limiting',
            'no_length_validation': 'No input length validation',
            'llm_in_loop': 'LLM calls in loops',
            'no_timeout': 'No timeout configuration',
            'no_token_limits': 'No token/context limits'
        }

        risk_list = [risk_descriptions.get(r, r) for r in risks]
        risk_text = ', '.join(risk_list)

        evidence = {
            'function_name': func['name'],
            'risks': risks,
            'llm_call_count': len(llm_calls),
            'risk_count': risk_count
        }

        return Finding(
            id=f"{self.detector_id}_{file_path}_{line_num}",
            category=f"{self.detector_id}: {self.name}",
            severity=severity,
            confidence=confidence,
            title=f"Model DoS vulnerability: {risk_text}",
            description=(
                f"Function '{func['name']}' on line {line_num} has {risk_count} DoS risk(s): "
                f"{risk_text}. These missing protections enable attackers to exhaust model "
                f"resources through excessive requests, large inputs, or recursive calls, "
                f"leading to service degradation or unavailability."
            ),
            file_path=file_path,
            line_number=line_num,
            code_snippet=code_snippet,
            recommendation=(
                "Model DoS Mitigations:\n"
                "1. Implement rate limiting per user/IP (@limiter.limit('10/minute'))\n"
                "2. Validate and limit input length (max 1000 chars)\n"
                "3. Set token limits (max_tokens=500)\n"
                "4. Configure timeouts (timeout=30 seconds)\n"
                "5. Avoid LLM calls in unbounded loops\n"
                "6. Implement circuit breakers for cascading failures\n"
                "7. Monitor and alert on resource usage\n"
                "8. Use queuing for batch processing\n"
                "9. Implement cost controls and budgets"
            ),
            evidence=evidence
        )

    def calculate_confidence(self, evidence: Dict[str, Any]) -> float:
        """Calculate confidence based on evidence"""
        # Confidence scales with risk count
        risk_count = evidence.get('risk_count', 0)

        if risk_count >= 4:
            return 0.8
        elif risk_count >= 3:
            return 0.7
        elif risk_count >= 2:
            return 0.6
        else:
            return 0.5
