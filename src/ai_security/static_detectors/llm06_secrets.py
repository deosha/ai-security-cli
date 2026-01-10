"""
LLM06: Sensitive Information Disclosure - Hardcoded Secrets Detector

Detects hardcoded secrets in code:
- API keys (OpenAI, Anthropic, AWS, etc.)
- Tokens and passwords
- Private keys and certificates
- Database credentials

Uses entropy analysis + pattern matching for high accuracy.
"""

import logging
import math
import re
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

from ai_security.models.finding import Finding, Severity
from ai_security.static_detectors.base_detector import BaseDetector

logger = logging.getLogger(__name__)


@dataclass
class SecretPattern:
    """Pattern for detecting specific secret types"""
    name: str
    pattern: re.Pattern
    min_entropy: float = 3.0  # Minimum Shannon entropy
    severity: Severity = Severity.CRITICAL


class SecretsDetector(BaseDetector):
    """
    Detect LLM06: Hardcoded Secrets

    Detection methods:
    1. Pattern matching for known secret formats
    2. Entropy analysis to avoid false positives
    3. Context analysis (variable names, comments)

    Confidence factors:
    - HIGH (0.9+): Known secret format + high entropy + secret variable name
    - MEDIUM (0.6-0.8): Pattern match + medium entropy
    - LOW (<0.6): Generic string pattern
    """

    detector_id = "LLM06"
    name = "Sensitive Information Disclosure"
    default_confidence_threshold = 0.7

    # Secret patterns with regex
    SECRET_PATTERNS = [
        SecretPattern(
            name="OpenAI API Key",
            pattern=re.compile(r'sk-[a-zA-Z0-9]{48,}'),
            min_entropy=4.0,
            severity=Severity.CRITICAL
        ),
        SecretPattern(
            name="OpenAI API Key (new format)",
            pattern=re.compile(r'sk-proj-[a-zA-Z0-9]{48,}'),
            min_entropy=4.0,
            severity=Severity.CRITICAL
        ),
        SecretPattern(
            name="Anthropic API Key",
            pattern=re.compile(r'sk-ant-[a-zA-Z0-9\-]{95,}'),
            min_entropy=4.0,
            severity=Severity.CRITICAL
        ),
        SecretPattern(
            name="AWS Access Key",
            pattern=re.compile(r'AKIA[0-9A-Z]{16}'),
            min_entropy=3.5,
            severity=Severity.CRITICAL
        ),
        SecretPattern(
            name="GitHub Token",
            pattern=re.compile(r'ghp_[a-zA-Z0-9]{36,}'),
            min_entropy=4.0,
            severity=Severity.CRITICAL
        ),
        SecretPattern(
            name="Generic API Key",
            pattern=re.compile(r'["\']?[a-zA-Z0-9_-]{32,}["\']?'),
            min_entropy=4.5,  # Higher entropy required for generic pattern
            severity=Severity.HIGH
        ),
        SecretPattern(
            name="Private Key",
            pattern=re.compile(r'-----BEGIN (RSA |EC )?PRIVATE KEY-----'),
            min_entropy=0.0,  # Clear indicator, no entropy check needed
            severity=Severity.CRITICAL
        ),
        SecretPattern(
            name="JWT Token",
            pattern=re.compile(r'eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+'),
            min_entropy=4.0,
            severity=Severity.HIGH
        ),
        SecretPattern(
            name="Database Connection String",
            pattern=re.compile(
                r'(postgresql|mysql|mongodb|redis)://[^:]+:[^@]+@[^/]+',
                re.IGNORECASE
            ),
            min_entropy=3.0,
            severity=Severity.CRITICAL
        ),
    ]

    # Variable names that indicate secrets
    SECRET_VARIABLE_NAMES = {
        'api_key', 'apikey', 'api_secret', 'apisecret',
        'secret_key', 'secretkey', 'secret', 'password', 'passwd', 'pwd',
        'token', 'auth_token', 'access_token', 'private_key', 'privatekey',
        'client_secret', 'aws_secret', 'credential', 'credentials',
        'openai_key', 'anthropic_key', 'openai_api_key', 'anthropic_api_key'
    }

    # Safe patterns to exclude (environment variables, config references)
    SAFE_PATTERNS = {
        'os.getenv', 'os.environ', 'env.get', 'config.get',
        'settings.', 'ENV[', 'process.env', 'System.getenv',
        'dotenv', 'load_dotenv', '.env'
    }

    def _gather_potential_findings(self, parsed_data: Dict[str, Any]) -> List[Finding]:
        """Find all potential hardcoded secrets"""
        findings = []

        file_path = parsed_data.get('file_path', 'unknown')
        source_lines = parsed_data.get('source_lines', [])
        assignments = parsed_data.get('assignments', [])
        llm_calls = parsed_data.get('llm_api_calls', [])
        string_ops = parsed_data.get('string_operations', [])
        classes = parsed_data.get('classes', [])

        # Get line numbers of LLM calls to avoid duplicate detection
        llm_call_lines = {call['line'] for call in llm_calls}

        # 1. Check assignments for secrets (skip LLM call lines - handled separately)
        findings.extend(self._check_assignments(assignments, source_lines, file_path, llm_call_lines))

        # 2. Check LLM API call arguments for secrets (more specific context)
        findings.extend(self._check_llm_call_args(llm_calls, source_lines, file_path))

        # 3. Check f-strings for embedded secrets
        findings.extend(self._check_string_operations(string_ops, source_lines, file_path))

        # 4. Check class attributes (common place for API keys)
        findings.extend(self._check_class_attributes(classes, source_lines, file_path))

        return findings

    def _check_assignments(
        self,
        assignments: List[Dict[str, Any]],
        source_lines: List[str],
        file_path: str,
        llm_call_lines: set = None
    ) -> List[Finding]:
        """Check variable assignments for hardcoded secrets"""
        findings = []
        llm_call_lines = llm_call_lines or set()

        for assignment in assignments:
            var_name = assignment.get('name', '')
            value = assignment.get('value', '')
            line_num = assignment.get('line', 0)

            # Skip if this assignment is an LLM call (handled by _check_llm_call_args)
            if line_num in llm_call_lines:
                continue

            # Skip if value references environment/config
            if self._is_safe_reference(value):
                continue

            # Check each secret pattern
            for pattern in self.SECRET_PATTERNS:
                matches = pattern.pattern.findall(value)

                for match in matches:
                    finding = self._create_secret_finding(
                        pattern=pattern,
                        match=match,
                        var_name=var_name,
                        line_num=line_num,
                        source_lines=source_lines,
                        file_path=file_path,
                        context='assignment'
                    )
                    if finding:
                        findings.append(finding)

        return findings

    def _check_llm_call_args(
        self,
        llm_calls: List[Dict[str, Any]],
        source_lines: List[str],
        file_path: str
    ) -> List[Finding]:
        """Check LLM API call arguments for inline secrets"""
        findings = []

        for llm_call in llm_calls:
            args = llm_call.get('args', [])
            keywords = llm_call.get('keywords', {})  # Fixed: parser uses 'keywords' not 'kwargs'
            line_num = llm_call.get('line', 0)

            # Check positional arguments
            for arg in args:
                arg_str = str(arg)
                if self._is_safe_reference(arg_str):
                    continue

                for pattern in self.SECRET_PATTERNS:
                    matches = pattern.pattern.findall(arg_str)
                    for match in matches:
                        finding = self._create_secret_finding(
                            pattern=pattern,
                            match=match,
                            var_name='inline_arg',
                            line_num=line_num,
                            source_lines=source_lines,
                            file_path=file_path,
                            context='llm_call_argument'
                        )
                        if finding:
                            findings.append(finding)

            # Check keyword arguments (e.g., api_key="sk-...")
            for key, value in keywords.items():
                value_str = str(value)
                if self._is_safe_reference(value_str):
                    continue

                for pattern in self.SECRET_PATTERNS:
                    matches = pattern.pattern.findall(value_str)
                    for match in matches:
                        finding = self._create_secret_finding(
                            pattern=pattern,
                            match=match,
                            var_name=key,
                            line_num=line_num,
                            source_lines=source_lines,
                            file_path=file_path,
                            context='llm_call_kwarg'
                        )
                        if finding:
                            findings.append(finding)

        return findings

    def _check_string_operations(
        self,
        string_ops: List[Dict[str, Any]],
        source_lines: List[str],
        file_path: str
    ) -> List[Finding]:
        """Check f-strings and format strings for embedded secrets"""
        findings = []

        for string_op in string_ops:
            if string_op['type'] == 'f-string':
                values = string_op.get('values', [])
                line_num = string_op.get('line', 0)

                for value in values:
                    value_str = str(value)
                    if self._is_safe_reference(value_str):
                        continue

                    for pattern in self.SECRET_PATTERNS:
                        matches = pattern.pattern.findall(value_str)
                        for match in matches:
                            finding = self._create_secret_finding(
                                pattern=pattern,
                                match=match,
                                var_name='f-string_value',
                                line_num=line_num,
                                source_lines=source_lines,
                                file_path=file_path,
                                context='f-string'
                            )
                            if finding:
                                findings.append(finding)

        return findings

    def _check_class_attributes(
        self,
        classes: List[Dict[str, Any]],
        source_lines: List[str],
        file_path: str
    ) -> List[Finding]:
        """Check class attributes for hardcoded secrets"""
        findings = []

        # Parse source lines within class definitions for attribute assignments
        for cls in classes:
            class_name = cls.get('name', '')
            class_line = cls.get('line', 0)

            # Look at lines after class definition for attributes
            # Simple heuristic: check next 50 lines for attribute assignments
            for i in range(class_line, min(class_line + 50, len(source_lines))):
                line = source_lines[i]

                # Look for class attribute patterns: self.api_key = "..."
                if '=' in line and ('self.' in line or class_name in line):
                    for pattern in self.SECRET_PATTERNS:
                        matches = pattern.pattern.findall(line)
                        for match in matches:
                            if not self._is_safe_reference(line):
                                finding = self._create_secret_finding(
                                    pattern=pattern,
                                    match=match,
                                    var_name=f'{class_name}_attribute',
                                    line_num=i + 1,
                                    source_lines=source_lines,
                                    file_path=file_path,
                                    context='class_attribute'
                                )
                                if finding:
                                    findings.append(finding)

        return findings

    def _create_secret_finding(
        self,
        pattern: SecretPattern,
        match: str,
        var_name: str,
        line_num: int,
        source_lines: List[str],
        file_path: str,
        context: str
    ) -> Optional[Finding]:
        """Create a Finding for a detected secret"""
        # Calculate entropy
        entropy = self._calculate_entropy(match)

        # Skip if entropy too low (likely false positive)
        if entropy < pattern.min_entropy:
            return None

        # Get code snippet
        snippet = self._get_code_snippet(source_lines, line_num)

        # Build evidence
        evidence = {
            'secret_type': pattern.name,
            'variable_name': var_name,
            'entropy': entropy,
            'has_secret_var_name': self._is_secret_variable_name(var_name),
            'value_length': len(match),
            'pattern_matched': True,
            'detection_context': context
        }

        return Finding(
            id=f"{self.detector_id}_{file_path}_{line_num}_{context}",
            category=f"{self.detector_id}: {self.name}",
            severity=pattern.severity,
            confidence=0.0,  # Will be calculated
            title=f"Hardcoded {pattern.name} detected in {context}",
            description=(
                f"Hardcoded {pattern.name} found in {context} "
                f"on line {line_num}. Hardcoded secrets in source code pose a critical "
                f"security risk as they can be extracted by anyone with access to the "
                f"codebase, version control history, or compiled binaries."
            ),
            file_path=file_path,
            line_number=line_num,
            code_snippet=snippet,
            recommendation=(
                "Remove hardcoded secrets immediately:\n"
                "1. Use environment variables: os.getenv('API_KEY')\n"
                "2. Use secret management: AWS Secrets Manager, Azure Key Vault, HashiCorp Vault\n"
                "3. Use configuration files (never commit to git): config.ini, .env\n"
                "4. Rotate the exposed secret immediately\n"
                "5. Scan git history for leaked secrets: git-secrets, truffleHog\n"
                "6. Add secret scanning to CI/CD pipeline"
            ),
            evidence=evidence
        )

    def _is_safe_reference(self, value: str) -> bool:
        """Check if value is a safe reference (env var, config)"""
        value_lower = value.lower()
        return any(pattern in value_lower for pattern in self.SAFE_PATTERNS)

    def _is_secret_variable_name(self, var_name: str) -> bool:
        """Check if variable name indicates a secret"""
        var_lower = var_name.lower()
        return any(secret_name in var_lower for secret_name in self.SECRET_VARIABLE_NAMES)

    def _calculate_entropy(self, string: str) -> float:
        """
        Calculate Shannon entropy of a string
        Higher entropy = more random = likely a real secret

        Returns: Entropy value (0-8 for base-256, typically 3-5 for secrets)
        """
        if not string:
            return 0.0

        # Count character frequencies
        frequencies = {}
        for char in string:
            frequencies[char] = frequencies.get(char, 0) + 1

        # Calculate entropy
        entropy = 0.0
        length = len(string)

        for count in frequencies.values():
            probability = count / length
            entropy -= probability * math.log2(probability)

        return entropy

    def _get_code_snippet(self, source_lines: List[str], line_num: int, context: int = 2) -> str:
        """Get code snippet with context lines"""
        start = max(0, line_num - context - 1)
        end = min(len(source_lines), line_num + context)
        return '\n'.join(source_lines[start:end])

    def calculate_confidence(self, evidence: Dict[str, Any]) -> float:
        """
        Calculate confidence based on evidence

        Scoring:
        - Base: 0.5 (pattern matched)
        - +0.2 if high entropy (>4.5)
        - +0.2 if variable name indicates secret
        - +0.1 if known secret format (not generic)
        """
        confidence = 0.5  # Base confidence for pattern match

        # Entropy boost
        entropy = evidence.get('entropy', 0.0)
        if entropy >= 4.5:
            confidence += 0.2
        elif entropy >= 4.0:
            confidence += 0.1

        # Variable name boost
        if evidence.get('has_secret_var_name', False):
            confidence += 0.2

        # Known format boost (not generic)
        secret_type = evidence.get('secret_type', '')
        if secret_type != 'Generic API Key':
            confidence += 0.1

        return min(1.0, confidence)
