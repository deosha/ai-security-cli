"""
LLM09: Overreliance Detector

Detects excessive trust in LLM outputs without proper verification or oversight.

Precision Strategy (v1.1):
Most LLM09 findings are demoted to INFO (advisory) by default.
Only escalate to HIGH/CRITICAL when there's a clear ACTION EDGE:
  - LLM output drives HTTP requests (requests.post, httpx, etc.)
  - LLM output drives file writes
  - LLM output drives database modifications
  - LLM output drives subprocess/command execution
  - AND no human approval/validation is present

This reduces false positives from word-pattern matching (e.g., functions
with "payment" in name but no actual payment execution).
"""

import re
from typing import Any, Dict, List

from aisentry.models.finding import Severity
from aisentry.static_detectors.base_detector import BaseDetector, Finding


class OverrelianceDetector(BaseDetector):
    """
    Detects overreliance on LLM outputs

    Key vulnerabilities:
    1. Critical decisions based on unverified LLM output
    2. No human oversight for high-stakes operations
    3. Missing output verification/validation
    4. Automated execution without confidence thresholds

    Severity Strategy:
    - INFO (advisory): Word-pattern matches without action edges
    - MEDIUM: Action edge present but with some safeguards
    - HIGH: Action edge without safeguards
    - CRITICAL: Direct code execution (eval/exec) from LLM output
    """

    detector_id = "LLM09"
    name = "Overreliance"

    # Critical decision patterns that require oversight
    CRITICAL_DECISIONS = {
        'financial': [
            'payment', 'refund', 'transaction', 'transfer',
            'charge', 'bill', 'invoice', 'price', 'cost'
        ],
        'medical': [
            'diagnosis', 'treatment', 'prescription', 'medication',
            'dosage', 'medical', 'patient', 'health'
        ],
        'legal': [
            'contract', 'legal', 'compliance', 'regulation',
            'lawsuit', 'liability', 'terms', 'agreement'
        ],
        'security': [
            'access', 'permission', 'authorize', 'grant',
            'deny', 'role', 'privilege', 'security'
        ],
        'data_modification': [
            'delete', 'drop', 'truncate', 'remove',
            'update', 'modify', 'alter', 'change'
        ]
    }

    # Human oversight patterns
    OVERSIGHT_PATTERNS = [
        'human_review', 'manual_review', 'human_approval',
        'requires_approval', 'review_queue', 'human_in_loop',
        'escalate', 'flag_for_review'
    ]

    # Verification patterns
    VERIFICATION_PATTERNS = [
        'verify', 'validate', 'check', 'confirm',
        'cross_check', 'double_check', 'review'
    ]

    # Confidence threshold patterns
    CONFIDENCE_PATTERNS = [
        'confidence', 'confidence_threshold', 'certainty',
        'if confidence', 'confidence >', 'confidence <',
        'min_confidence', 'threshold'
    ]

    # Output validation patterns
    VALIDATION_PATTERNS = [
        'validate', 'validation', 'validator', 'schema',
        'pydantic', 'parse_obj', 'check_format'
    ]

    # Disclaimer patterns
    DISCLAIMER_PATTERNS = [
        'disclaimer', 'warning', 'may be incorrect',
        'not guaranteed', 'verify independently',
        'consult professional', 'informational only'
    ]

    # Direct execution patterns (problematic)
    DIRECT_EXECUTION = [
        'exec(', 'eval(', 'subprocess.run', 'os.system',
        'sql.execute', 'db.execute', 'cursor.execute'
    ]

    # ==========================================================================
    # ACTION EDGE PATTERNS - Required for HIGH/CRITICAL severity
    # ==========================================================================

    # HTTP/Network action edges
    HTTP_ACTION_PATTERNS = [
        r'requests\.(post|put|patch|delete)',
        r'httpx\.(post|put|patch|delete)',
        r'aiohttp.*\.(post|put|patch|delete)',
        r'urllib\.request\.urlopen',
        r'http\.client',
    ]

    # File action edges
    FILE_ACTION_PATTERNS = [
        r'\.write\s*\(',
        r'open\s*\([^)]*["\']w',  # open(..., 'w')
        r'shutil\.(copy|move|rmtree)',
        r'os\.(remove|unlink|rmdir)',
        r'pathlib.*\.write',
    ]

    # Database action edges
    DB_ACTION_PATTERNS = [
        r'\.execute\s*\(',
        r'\.executemany\s*\(',
        r'\.commit\s*\(',
        r'session\.(add|delete|merge)',
        r'bulk_(insert|update)',
    ]

    # Subprocess/command action edges
    SUBPROCESS_ACTION_PATTERNS = [
        r'subprocess\.(run|call|Popen|check_output)',
        r'os\.(system|popen|exec)',
        r'commands\.getoutput',
    ]

    # Code execution action edges (always CRITICAL)
    CODE_EXEC_PATTERNS = [
        r'\beval\s*\(',
        r'\bexec\s*\(',
        r'\bcompile\s*\(',
    ]

    def _gather_potential_findings(self, parsed_data: Dict[str, Any]) -> List[Finding]:
        """Gather all potential overreliance findings with action-edge-based severity."""
        findings = []

        # Check for direct code execution (always CRITICAL if combined with LLM)
        findings.extend(self._check_direct_execution(parsed_data))

        # Check critical decisions - demote to INFO unless action edge present
        findings.extend(self._check_critical_decisions(parsed_data))

        # Check automated actions - demote to INFO unless action edge present
        findings.extend(self._check_automated_actions(parsed_data))

        # Skip _check_missing_verification entirely - too many FPs, low value
        # findings.extend(self._check_missing_verification(parsed_data))

        return findings

    def _detect_action_edges(self, source_lines: List[str]) -> Dict[str, bool]:
        """
        Detect action edge patterns in source code.

        Returns dict indicating which types of action edges are present:
        - http: HTTP POST/PUT/DELETE/PATCH
        - file: File writes/deletes
        - db: Database modifications
        - subprocess: Command execution
        - code_exec: eval/exec/compile
        """
        source_code = '\n'.join(source_lines)

        edges = {
            'http': False,
            'file': False,
            'db': False,
            'subprocess': False,
            'code_exec': False,
            'any': False,
        }

        # Check HTTP patterns
        for pattern in self.HTTP_ACTION_PATTERNS:
            if re.search(pattern, source_code, re.IGNORECASE):
                edges['http'] = True
                break

        # Check file patterns
        for pattern in self.FILE_ACTION_PATTERNS:
            if re.search(pattern, source_code):
                edges['file'] = True
                break

        # Check DB patterns
        for pattern in self.DB_ACTION_PATTERNS:
            if re.search(pattern, source_code, re.IGNORECASE):
                edges['db'] = True
                break

        # Check subprocess patterns
        for pattern in self.SUBPROCESS_ACTION_PATTERNS:
            if re.search(pattern, source_code, re.IGNORECASE):
                edges['subprocess'] = True
                break

        # Check code execution patterns
        for pattern in self.CODE_EXEC_PATTERNS:
            if re.search(pattern, source_code):
                edges['code_exec'] = True
                break

        edges['any'] = any([
            edges['http'], edges['file'], edges['db'],
            edges['subprocess'], edges['code_exec']
        ])

        return edges

    def calculate_confidence(self, evidence: Dict[str, Any]) -> float:
        """Calculate confidence based on evidence"""
        confidence_scores = [0.7]  # Base confidence

        # High confidence for critical decisions without oversight
        if evidence.get('is_critical_decision') and not evidence.get('has_oversight'):
            confidence_scores.append(0.9)

        # High confidence for direct execution
        if evidence.get('has_direct_execution'):
            confidence_scores.append(0.85)

        # Medium-high for missing verification
        if evidence.get('is_critical_decision') and not evidence.get('has_verification'):
            confidence_scores.append(0.75)

        # Medium for missing confidence checks
        if not evidence.get('has_confidence_check'):
            confidence_scores.append(0.65)

        return min(max(confidence_scores), 1.0)

    def _check_critical_decisions(self, parsed_data: Dict[str, Any]) -> List[Finding]:
        """Check for critical decisions without proper oversight.

        Severity Strategy:
        - INFO: Word pattern match but no action edge (advisory only)
        - MEDIUM: Action edge present but with some safeguards
        - HIGH: Action edge + no safeguards
        - CRITICAL: Medical/financial + action edge + no safeguards
        """
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

            # Check if function makes LLM calls
            has_llm_call = any(func_start <= line <= func_end for line in llm_call_lines)
            if not has_llm_call:
                continue

            # Check if this is a critical decision function
            decision_types = []
            for category, patterns in self.CRITICAL_DECISIONS.items():
                if any(pattern in func_lower for pattern in patterns):
                    decision_types.append(category)

            if not decision_types:
                continue

            # Check for oversight mechanisms
            has_oversight = any(
                pattern in func_lower for pattern in self.OVERSIGHT_PATTERNS
            )

            # Check for verification
            has_verification = any(
                pattern in func_lower for pattern in self.VERIFICATION_PATTERNS
            )

            # Check for confidence thresholds
            has_confidence_check = any(
                pattern in func_lower for pattern in self.CONFIDENCE_PATTERNS
            )

            # Check for validation
            has_validation = any(
                pattern in func_lower for pattern in self.VALIDATION_PATTERNS
            )

            # Check for disclaimers
            has_disclaimer = any(
                pattern in func_lower for pattern in self.DISCLAIMER_PATTERNS
            )

            # Create finding if critical decision lacks proper safeguards
            if not has_oversight and not has_verification:
                # Detect action edges within this specific function
                func_lines = source_lines[func_start-1:func_end]
                action_edges = self._detect_action_edges(func_lines)

                # Severity depends on action edges - advisory by default
                is_high_stakes = 'medical' in decision_types or 'financial' in decision_types
                has_any_safeguard = has_confidence_check or has_validation or has_disclaimer

                if action_edges.get('any'):
                    # Action edge present - this is actionable
                    if is_high_stakes and not has_any_safeguard:
                        severity = Severity.CRITICAL
                    elif not has_any_safeguard:
                        severity = Severity.HIGH
                    else:
                        severity = Severity.MEDIUM
                else:
                    # No action edge - demote to INFO (advisory only)
                    severity = Severity.INFO

                finding = Finding(
                    id=f"{self.detector_id}_{parsed_data.get('file_path', '')}_{func_start}_critical_decision",
                    category=f"{self.detector_id}: {self.name}",
                    severity=severity,
                    confidence=0.0,  # Will be set by BaseDetector
                    title=f"Critical decision without oversight in '{func.get('name')}'",
                    description=(
                        f"Function '{func.get('name')}' on line {func_start} makes critical {', '.join(decision_types)} "
                        f"decisions based on LLM output without human oversight or verification. "
                        + ("Action edges detected (HTTP/file/DB/subprocess) - risk of automated execution."
                           if action_edges.get('any') else
                           "No action edges detected - advisory only.")
                    ),
                    file_path=parsed_data.get('file_path', ''),
                    line_number=func_start,
                    code_snippet=self._get_code_snippet(source_lines, func_start, context=3),
                    recommendation=self._get_oversight_recommendation(decision_types),
                    evidence={
                        'function_name': func.get('name'),
                        'decision_types': decision_types,
                        'is_critical_decision': True,
                        'has_oversight': has_oversight,
                        'has_verification': has_verification,
                        'has_confidence_check': has_confidence_check,
                        'has_validation': has_validation,
                        'has_disclaimer': has_disclaimer,
                        'action_edges': action_edges
                    }
                )
                findings.append(finding)

        return findings

    def _check_automated_actions(self, parsed_data: Dict[str, Any]) -> List[Finding]:
        """Check for automated actions without confidence thresholds.

        Severity Strategy:
        - INFO: Word pattern match but no action edge (advisory only)
        - MEDIUM: Action edge + some safeguards
        - HIGH: Action edge + no safeguards
        """
        findings = []
        functions = parsed_data.get('functions', [])
        source_lines = parsed_data.get('source_lines', [])
        llm_calls = parsed_data.get('llm_api_calls', [])

        # Map LLM calls to their locations
        llm_call_lines = {call.get('line', 0) for call in llm_calls}

        # Look for automated action patterns
        action_patterns = [
            'execute', 'run', 'perform', 'apply',
            'send', 'post', 'create', 'update'
        ]

        for func in functions:
            func_name = func.get('name', '').lower()
            func_start = func.get('line', 0)
            func_end = func.get('end_line', func_start + 10)

            # Get function body
            func_body = '\n'.join(source_lines[func_start-1:func_end])
            func_lower = func_body.lower()

            # Check if function makes LLM calls
            has_llm_call = any(func_start <= line <= func_end for line in llm_call_lines)
            if not has_llm_call:
                continue

            # Check if this is an automated action function
            is_action_function = any(pattern in func_name for pattern in action_patterns)
            if not is_action_function:
                continue

            # Check for confidence thresholds
            has_confidence_check = any(
                pattern in func_lower for pattern in self.CONFIDENCE_PATTERNS
            )

            # Check for validation
            has_validation = any(
                pattern in func_lower for pattern in self.VALIDATION_PATTERNS
            )

            # Create finding if automated action lacks confidence checks
            if not has_confidence_check and not has_validation:
                # Detect action edges within this specific function
                func_lines = source_lines[func_start-1:func_end]
                action_edges = self._detect_action_edges(func_lines)

                # Severity depends on action edges - advisory by default
                if action_edges.get('any'):
                    severity = Severity.HIGH
                else:
                    severity = Severity.INFO

                finding = Finding(
                    id=f"{self.detector_id}_{parsed_data.get('file_path', '')}_{func_start}_automated_action",
                    category=f"{self.detector_id}: {self.name}",
                    severity=severity,
                    confidence=0.0,  # Will be set by BaseDetector
                    title=f"Automated action without confidence threshold in '{func.get('name')}'",
                    description=(
                        f"Function '{func.get('name')}' on line {func_start} automatically executes actions "
                        f"based on LLM output without checking confidence thresholds or validating output. "
                        + ("Action edges detected - risk of automated execution."
                           if action_edges.get('any') else
                           "No action edges detected - advisory only.")
                    ),
                    file_path=parsed_data.get('file_path', ''),
                    line_number=func_start,
                    code_snippet=self._get_code_snippet(source_lines, func_start, context=3),
                    recommendation=self._get_confidence_recommendation(),
                    evidence={
                        'function_name': func.get('name'),
                        'is_automated_action': True,
                        'has_confidence_check': False,
                        'has_validation': False,
                        'action_edges': action_edges
                    }
                )
                findings.append(finding)

        return findings

    def _check_missing_verification(self, parsed_data: Dict[str, Any]) -> List[Finding]:
        """Check for LLM outputs used without verification"""
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

            # Check if function makes LLM calls
            has_llm_call = any(func_start <= line <= func_end for line in llm_call_lines)
            if not has_llm_call:
                continue

            # Skip functions that already have verification
            has_verification = any(
                pattern in func_lower for pattern in self.VERIFICATION_PATTERNS
            )
            has_validation = any(
                pattern in func_lower for pattern in self.VALIDATION_PATTERNS
            )
            has_oversight = any(
                pattern in func_lower for pattern in self.OVERSIGHT_PATTERNS
            )

            # Check if output is returned or used directly
            returns_output = 'return' in func_lower

            if returns_output and not (has_verification or has_validation or has_oversight):
                # This is a lower severity issue - output is returned without verification
                finding = Finding(
                    id=f"{self.detector_id}_{parsed_data.get('file_path', '')}_{func_start}_missing_verification",
                    category=f"{self.detector_id}: {self.name}",
                    severity=Severity.LOW,
                    confidence=0.0,  # Will be set by BaseDetector
                    title=f"LLM output returned without verification in '{func.get('name')}'",
                    description=(
                        f"Function '{func.get('name')}' on line {func_start} returns LLM output "
                        f"without verification, validation, or oversight mechanisms. "
                        f"Consider adding output validation or including disclaimers."
                    ),
                    file_path=parsed_data.get('file_path', ''),
                    line_number=func_start,
                    code_snippet=self._get_code_snippet(source_lines, func_start, context=3),
                    recommendation=self._get_verification_recommendation(),
                    evidence={
                        'function_name': func.get('name'),
                        'has_verification': False,
                        'has_validation': False,
                        'returns_output': True
                    }
                )
                findings.append(finding)

        return findings

    def _check_direct_execution(self, parsed_data: Dict[str, Any]) -> List[Finding]:
        """Check for direct execution of LLM-generated code.

        NOTE: Direct code execution (eval/exec) is ALWAYS CRITICAL -
        no advisory demotion here since eval/exec IS the action edge.
        """
        findings = []
        functions = parsed_data.get('functions', [])
        source_lines = parsed_data.get('source_lines', [])
        llm_calls = parsed_data.get('llm_api_calls', [])

        # Map LLM calls to their locations
        llm_call_lines = {call.get('line', 0) for call in llm_calls}

        for func in functions:
            func_start = func.get('line', 0)
            func_end = func.get('end_line', func_start + 10)

            # Get function body
            func_body = '\n'.join(source_lines[func_start-1:func_end])
            func_lower = func_body.lower()

            # Check if function makes LLM calls
            has_llm_call = any(func_start <= line <= func_end for line in llm_call_lines)
            if not has_llm_call:
                continue

            # Check for direct execution patterns
            execution_patterns_found = [
                pattern for pattern in self.DIRECT_EXECUTION
                if pattern in func_lower
            ]

            if execution_patterns_found:
                # Direct execution is ALWAYS CRITICAL - no advisory demotion
                finding = Finding(
                    id=f"{self.detector_id}_{parsed_data.get('file_path', '')}_{func_start}_direct_execution",
                    category=f"{self.detector_id}: {self.name}",
                    severity=Severity.CRITICAL,
                    confidence=0.0,  # Will be set by BaseDetector
                    title=f"Direct execution of LLM output in '{func.get('name')}'",
                    description=(
                        f"Function '{func.get('name')}' on line {func_start} directly executes "
                        f"LLM-generated code using {', '.join(execution_patterns_found)}. "
                        f"This is extremely dangerous and allows arbitrary code execution."
                    ),
                    file_path=parsed_data.get('file_path', ''),
                    line_number=func_start,
                    code_snippet=self._get_code_snippet(source_lines, func_start, context=3),
                    recommendation=self._get_execution_recommendation(),
                    evidence={
                        'function_name': func.get('name'),
                        'has_direct_execution': True,
                        'execution_patterns': execution_patterns_found
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

    def _get_oversight_recommendation(self, decision_types: List[str]) -> str:
        """Get recommendation for adding oversight"""
        return f"""Critical {', '.join(decision_types)} decision requires human oversight:

1. Implement human-in-the-loop review:
   - Add review queue for high-stakes decisions
   - Require explicit human approval before execution
   - Log all decisions for audit trail

2. Add verification mechanisms:
   - Cross-reference with trusted sources
   - Implement multi-step verification
   - Use confidence thresholds

3. Include safety checks:
   - Set limits on transaction amounts
   - Require secondary confirmation
   - Implement rollback mechanisms

4. Add disclaimers:
   - Inform users output may be incorrect
   - Recommend professional consultation
   - Document limitations clearly

5. Monitor and review:
   - Track decision outcomes
   - Review failures and near-misses
   - Continuously improve safeguards"""

    def _get_confidence_recommendation(self) -> str:
        """Get recommendation for confidence thresholds"""
        return """Implement confidence thresholds for automated actions:

1. Add confidence scoring:
   - Request confidence scores from LLM
   - Calculate custom confidence metrics
   - Track historical accuracy

2. Set thresholds:
   - High confidence (>0.9): Auto-execute
   - Medium confidence (0.7-0.9): Human review
   - Low confidence (<0.7): Reject or escalate

3. Validate output:
   - Use schema validation (Pydantic)
   - Check output format and constraints
   - Verify against expected patterns

4. Implement fallbacks:
   - Have backup strategies for low confidence
   - Use simpler/safer alternatives
   - Escalate to human operators"""

    def _get_verification_recommendation(self) -> str:
        """Get recommendation for output verification"""
        return """Add verification mechanisms for LLM output:

1. Implement validation:
   - Schema validation (Pydantic)
   - Format checking (regex, parsing)
   - Constraint verification

2. Add fact-checking:
   - Cross-reference with trusted sources
   - Use RAG for grounding
   - Verify claims against knowledge base

3. Include disclaimers:
   - "AI-generated content, verify independently"
   - "For informational purposes only"
   - "Consult professional for critical decisions"

4. Track accuracy:
   - Monitor user corrections
   - Collect feedback
   - Improve over time"""

    def _get_execution_recommendation(self) -> str:
        """Get recommendation for preventing direct execution"""
        return """NEVER directly execute LLM-generated code:

1. Remove direct execution:
   - Do not use eval(), exec(), or os.system()
   - Avoid dynamic code execution
   - Use safer alternatives (allow-lists)

2. If code generation is required:
   - Generate code for review only
   - Require human approval before execution
   - Use sandboxing (containers, VMs)
   - Implement strict security policies

3. Use structured outputs:
   - Return data, not code
   - Use JSON schemas
   - Define clear interfaces

4. Add safeguards:
   - Static code analysis before execution
   - Whitelist allowed operations
   - Rate limiting and monitoring"""
