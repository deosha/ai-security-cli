"""
LLM06: Sensitive Information Disclosure - Hardcoded Secrets Detector

Detects hardcoded secrets in code:
- API keys (OpenAI, Anthropic, AWS, etc.)
- Tokens and passwords
- Private keys and certificates
- Database credentials

Uses detect-secrets library + custom patterns for comprehensive detection.
"""

import logging
import math
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional

from detect_secrets.core.scan import scan_file
from detect_secrets.settings import transient_settings

from aisentry.models.finding import Finding, Severity
from aisentry.static_detectors.base_detector import BaseDetector

logger = logging.getLogger(__name__)

# detect-secrets plugins to use
DETECT_SECRETS_PLUGINS = [
    {'name': 'AWSKeyDetector'},
    {'name': 'AzureStorageKeyDetector'},
    {'name': 'BasicAuthDetector'},
    {'name': 'GitHubTokenDetector'},
    {'name': 'GitLabTokenDetector'},
    {'name': 'Base64HighEntropyString'},
    {'name': 'HexHighEntropyString'},
    {'name': 'JwtTokenDetector'},
    {'name': 'KeywordDetector'},
    {'name': 'OpenAIDetector'},
    {'name': 'PrivateKeyDetector'},
    {'name': 'SlackDetector'},
    {'name': 'StripeDetector'},
    {'name': 'TwilioKeyDetector'},
]


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

    # PII patterns for sensitive data detection
    PII_PATTERNS = {
        'ssn': re.compile(r'\d{3}[-\s]?\d{2}[-\s]?\d{4}'),  # SSN
        'credit_card': re.compile(r'\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}'),  # Credit card
        'email': re.compile(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'),  # Email
    }

    # Keywords indicating sensitive data in prompts/system messages
    SENSITIVE_PROMPT_KEYWORDS = {
        'password', 'secret', 'confidential', 'internal', 'private',
        'ssn', 'credit_card', 'creditcard', 'social security',
    }

    # Variables that likely contain sensitive user data
    SENSITIVE_DATA_VAR_NAMES = {
        'user_data', 'userdata', 'user_info', 'pii', 'personal_data',
        'profile', 'secret', 'password', 'credentials', 'ssn',
        'credit_card', 'cc_number', 'social_security'
    }

    # Safe patterns to exclude (reading from environment/config is safe)
    # NOTE: os.environ.get() and os.getenv() are safe (reading from env)
    # but os.environ["X"] = "value" is NOT safe (setting hardcoded value)
    SAFE_PATTERNS = {
        'os.getenv', 'os.environ.get', 'env.get', 'config.get',
        'settings.', 'process.env', 'System.getenv',
        'dotenv', 'load_dotenv'
    }

    # Pattern for hardcoded env var assignment (VULNERABLE)
    HARDCODED_ENV_PATTERN = re.compile(
        r'os\.environ\s*\[\s*["\']([^"\']+)["\']\s*\]\s*=\s*["\']([^"\']+)["\']',
        re.IGNORECASE
    )

    # Pattern to find keyword arguments with secret-like names (catches what detect-secrets misses)
    # Matches: password="value", secret="value", api_key="value", db_pass="value", etc.
    KEYWORD_ARG_SECRET_PATTERN = re.compile(
        r'\b(password|passwd|pwd|secret|api_key|apikey|token|auth_token|'
        r'access_token|private_key|client_secret|secret_key|'
        r'db_pass|db_password|db_pwd|database_password|database_pass|'
        r'mysql_password|postgres_password|redis_password|mongo_password)\s*=\s*["\']([^"\']+)["\']',
        re.IGNORECASE
    )

    # Placeholder values that are safe (defaults/examples) - exact matches
    SAFE_PLACEHOLDER_VALUES = {
        'password', 'secret', 'changeme',
        'your_password', 'your_secret', 'your-password', 'your-secret',
        'none', 'null', '', 'test', 'example', 'placeholder', 'default',
        'secret-key', 'secretkey', 'my-secret', 'mysecret', 'super-secret',
        'admin', 'root', 'user', 'guest', 'demo', 'sample',
    }

    # Placeholder patterns (regex) - matches xxx, xxxx, *****, etc.
    SAFE_PLACEHOLDER_PATTERNS = [
        re.compile(r'^x+$', re.IGNORECASE),        # xxx, xxxx, XXXX
        re.compile(r'^\*+$'),                       # ***, ****
        re.compile(r'^\.+$'),                       # ..., ....
        re.compile(r'^<[^>]+>$'),                   # <your-secret>, <API_KEY>
        re.compile(r'^\$\{[^}]+\}$'),               # ${SECRET}, ${PASSWORD}
        re.compile(r'^%\([^)]+\)s$'),               # %(password)s
    ]

    def _gather_potential_findings(self, parsed_data: Dict[str, Any]) -> List[Finding]:
        """Find all potential hardcoded secrets and sensitive data exposure"""
        findings = []

        file_path = parsed_data.get('file_path', 'unknown')
        source_lines = parsed_data.get('source_lines', [])
        assignments = parsed_data.get('assignments', [])
        llm_calls = parsed_data.get('llm_api_calls', [])
        string_ops = parsed_data.get('string_operations', [])
        classes = parsed_data.get('classes', [])
        functions = parsed_data.get('functions', [])

        # Get line numbers of LLM calls to avoid duplicate detection
        llm_call_lines = {call['line'] for call in llm_calls}

        # 0. Use detect-secrets for comprehensive secret detection
        findings.extend(self._scan_with_detect_secrets(file_path, source_lines))

        # Track lines already found by detect-secrets to avoid duplicates
        found_lines = {f.line_number for f in findings}

        # 1. Check assignments for secrets (skip LLM call lines - handled separately)
        for f in self._check_assignments(assignments, source_lines, file_path, llm_call_lines):
            if f.line_number not in found_lines:
                findings.append(f)
                found_lines.add(f.line_number)

        # 2. Check LLM API call arguments for secrets (more specific context)
        for f in self._check_llm_call_args(llm_calls, source_lines, file_path):
            if f.line_number not in found_lines:
                findings.append(f)
                found_lines.add(f.line_number)

        # 3. Check f-strings for embedded secrets
        for f in self._check_string_operations(string_ops, source_lines, file_path):
            if f.line_number not in found_lines:
                findings.append(f)
                found_lines.add(f.line_number)

        # 4. Check class attributes (common place for API keys)
        for f in self._check_class_attributes(classes, source_lines, file_path):
            if f.line_number not in found_lines:
                findings.append(f)
                found_lines.add(f.line_number)

        # 5. Check for secrets/PII flowing into prompts
        findings.extend(self._check_secrets_in_prompts(functions, llm_calls, assignments, source_lines, file_path))

        # 6. Check for sensitive data in system prompts
        findings.extend(self._check_sensitive_system_prompts(llm_calls, source_lines, file_path))

        # 7. Check for sensitive data logging
        findings.extend(self._check_sensitive_logging(functions, assignments, source_lines, file_path))

        # 8. Check for hardcoded env var assignments (os.environ["X"] = "secret")
        for f in self._check_hardcoded_env_assignments(source_lines, file_path):
            if f.line_number not in found_lines:
                findings.append(f)
                found_lines.add(f.line_number)

        # 9. Check for keyword-style credential assignments (db_pass = "secret")
        for f in self._check_keyword_credentials(source_lines, file_path):
            if f.line_number not in found_lines:
                findings.append(f)
                found_lines.add(f.line_number)

        return findings

    def _scan_with_detect_secrets(
        self,
        file_path: str,
        source_lines: List[str]
    ) -> List[Finding]:
        """Use detect-secrets library for comprehensive secret detection."""
        findings = []

        # Skip if file doesn't exist (e.g., in-memory parsing)
        if not file_path or file_path == 'unknown' or not Path(file_path).exists():
            return findings

        try:
            with transient_settings({'plugins_used': DETECT_SECRETS_PLUGINS}):
                secrets = list(scan_file(file_path))

                for secret in secrets:
                    # Skip test files for certain detectors (but not 'testbed' directories)
                    basename = Path(file_path).name.lower()
                    if ('test_' in basename or '_test.' in basename or basename.endswith('_test.py')) \
                            and secret.type == 'Secret Keyword':
                        continue

                    # Get code snippet
                    line_num = secret.line_number
                    snippet = self._get_code_snippet(source_lines, line_num)

                    # Map severity based on secret type
                    severity = Severity.CRITICAL
                    if secret.type in ('Base64 High Entropy String', 'Hex High Entropy String'):
                        severity = Severity.HIGH

                    findings.append(Finding(
                        id=f"LLM06_DS_{file_path}_{line_num}",
                        category="LLM06: Sensitive Information Disclosure",
                        severity=severity,
                        confidence=0.85,
                        title=f"Hardcoded secret detected: {secret.type}",
                        description=(
                            f"detect-secrets found a potential {secret.type} on line {line_num}. "
                            f"Hardcoded secrets in source code can be extracted from version control, "
                            f"compiled binaries, or by anyone with code access."
                        ),
                        file_path=file_path,
                        line_number=line_num,
                        code_snippet=snippet,
                        recommendation=(
                            "Remove hardcoded secrets:\n"
                            "1. Use environment variables: os.getenv('SECRET_KEY')\n"
                            "2. Use secret management (AWS Secrets Manager, HashiCorp Vault)\n"
                            "3. Use .env files (not committed to git)\n"
                            "4. Rotate the exposed credential immediately"
                        ),
                        evidence={
                            'secret_type': secret.type,
                            'detector': 'detect-secrets',
                        }
                    ))

        except Exception as e:
            logger.debug(f"detect-secrets scan failed for {file_path}: {e}")

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

    def _check_hardcoded_env_assignments(
        self,
        source_lines: List[str],
        file_path: str
    ) -> List[Finding]:
        """
        Detect hardcoded values assigned to environment variables.

        This catches patterns like:
            os.environ["AWS_ACCESS_KEY_ID"] = "AKIA..."
            os.environ["SECRET_KEY"] = "hardcoded_value"

        These are dangerous because they embed secrets in source code
        while appearing to use environment variables.
        """
        findings = []

        # Known credential env var names
        SENSITIVE_ENV_VARS = {
            'aws_access_key_id', 'aws_secret_access_key', 'aws_session_token',
            'azure_storage_key', 'azure_subscription_id', 'azure_tenant_id',
            'google_api_key', 'google_application_credentials',
            'openai_api_key', 'anthropic_api_key', 'cohere_api_key',
            'database_url', 'db_password', 'db_pass', 'mysql_password',
            'postgres_password', 'redis_password', 'mongo_password',
            'secret_key', 'private_key', 'api_key', 'auth_token',
            'access_token', 'refresh_token', 'jwt_secret',
        }

        for idx, line in enumerate(source_lines):
            match = self.HARDCODED_ENV_PATTERN.search(line)
            if match:
                env_var_name = match.group(1)
                env_var_value = match.group(2)

                # Skip placeholder values
                if self._is_placeholder_value(env_var_value):
                    continue

                # Higher severity for known credential env vars
                env_var_lower = env_var_name.lower()
                is_known_secret = any(
                    known in env_var_lower for known in SENSITIVE_ENV_VARS
                )

                line_num = idx + 1
                snippet = self._get_code_snippet(source_lines, line_num)

                findings.append(Finding(
                    id=f"LLM06_{file_path}_{line_num}_env_hardcode",
                    category="LLM06: Sensitive Information Disclosure",
                    severity=Severity.CRITICAL if is_known_secret else Severity.HIGH,
                    confidence=0.9 if is_known_secret else 0.75,
                    title="Hardcoded credential in environment variable assignment",
                    description=(
                        f"Environment variable '{env_var_name}' is being set to a hardcoded "
                        f"value on line {line_num}. This defeats the purpose of using environment "
                        f"variables for secrets and exposes credentials in source code."
                    ),
                    file_path=file_path,
                    line_number=line_num,
                    code_snippet=snippet,
                    recommendation=(
                        "Remove hardcoded environment variable assignments:\n"
                        "1. Set environment variables externally (shell, .env file, CI/CD)\n"
                        "2. Use os.getenv() to READ from environment, never SET hardcoded values\n"
                        "3. Use secret management (AWS Secrets Manager, HashiCorp Vault)\n"
                        "4. For local dev, use .env files (not committed to git)\n"
                        "5. Rotate the exposed credential immediately"
                    )
                ))

        return findings

    def _check_keyword_credentials(
        self,
        source_lines: List[str],
        file_path: str
    ) -> List[Finding]:
        """
        Detect hardcoded credentials in keyword-style assignments.

        This catches patterns like:
            db_pass = "P@ssw0rd123!"
            mysql_password = "secret123"

        Filters out placeholder values like "secret", "password", "changeme".
        """
        findings = []

        for idx, line in enumerate(source_lines):
            match = self.KEYWORD_ARG_SECRET_PATTERN.search(line)
            if match:
                var_name = match.group(1)
                value = match.group(2)

                # Skip placeholder values
                if self._is_placeholder_value(value):
                    continue

                # Skip safe references (env vars, config)
                if self._is_safe_reference(line):
                    continue

                line_num = idx + 1
                snippet = self._get_code_snippet(source_lines, line_num)

                findings.append(Finding(
                    id=f"LLM06_{file_path}_{line_num}_keyword_cred",
                    category="LLM06: Sensitive Information Disclosure",
                    severity=Severity.HIGH,
                    confidence=0.85,
                    title=f"Hardcoded {var_name} credential detected",
                    description=(
                        f"Variable '{var_name}' on line {line_num} contains a hardcoded "
                        f"credential value. This exposes sensitive data in source code."
                    ),
                    file_path=file_path,
                    line_number=line_num,
                    code_snippet=snippet,
                    recommendation=(
                        "Remove hardcoded credentials:\n"
                        "1. Use environment variables: os.getenv('DB_PASSWORD')\n"
                        "2. Use secret management (AWS Secrets Manager, HashiCorp Vault)\n"
                        "3. Use configuration files (not committed to git)\n"
                        "4. Rotate the exposed credential immediately"
                    )
                ))

        return findings

    def _is_placeholder_value(self, value: str) -> bool:
        """Check if value is a placeholder/example value that shouldn't trigger alerts."""
        if not value:
            return True

        value_lower = value.lower()

        # Check exact matches
        if value_lower in self.SAFE_PLACEHOLDER_VALUES:
            return True

        # Check regex patterns
        for pattern in self.SAFE_PLACEHOLDER_PATTERNS:
            if pattern.match(value):
                return True

        return False

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

    def _check_secrets_in_prompts(
        self,
        functions: List[Dict[str, Any]],
        llm_calls: List[Dict[str, Any]],
        assignments: List[Dict[str, Any]],
        source_lines: List[str],
        file_path: str
    ) -> List[Finding]:
        """Check for secrets/PII being passed into prompts sent to LLMs"""
        findings = []

        # Build map of variable names that contain secrets/sensitive data
        sensitive_vars = set()
        for assign in assignments:
            var_name = assign.get('name', '').lower()
            value = assign.get('value', '')

            # Check if variable name indicates sensitive data
            if any(s in var_name for s in self.SENSITIVE_DATA_VAR_NAMES):
                sensitive_vars.add(assign.get('name', ''))

            # Check if variable name indicates secret
            if any(s in var_name for s in self.SECRET_VARIABLE_NAMES):
                sensitive_vars.add(assign.get('name', ''))

            # Check if value contains PII patterns
            for pii_type, pattern in self.PII_PATTERNS.items():
                if pattern.search(value):
                    sensitive_vars.add(assign.get('name', ''))

        # For each function containing LLM call, check if sensitive vars flow into prompt
        for func in functions:
            func_name = func.get('name', '').lower()
            func_start = func.get('line', 0)
            func_end = func.get('end_line', func_start + 100)

            # Find LLM calls in this function
            func_llm_calls = [
                c for c in llm_calls
                if func_start <= c.get('line', 0) <= func_end
            ]

            if not func_llm_calls:
                continue

            # Check source lines in function for f-strings with sensitive vars
            for line_num in range(func_start, min(func_end + 1, len(source_lines) + 1)):
                if line_num <= 0 or line_num > len(source_lines):
                    continue
                line = source_lines[line_num - 1]

                # Look for f-string or .format() containing sensitive variable
                if 'f"' in line or "f'" in line or '.format(' in line:
                    # Check if any sensitive variable is referenced
                    for var in sensitive_vars:
                        if '{' + var + '}' in line or var + '}' in line:
                            snippet = self._get_code_snippet(source_lines, line_num)
                            findings.append(Finding(
                                id=f"{self.detector_id}_{file_path}_{line_num}_secret_in_prompt",
                                category=f"{self.detector_id}: {self.name}",
                                severity=Severity.HIGH,
                                confidence=0.0,
                                title="Sensitive data passed into LLM prompt",
                                description=(
                                    f"Variable '{var}' containing sensitive data is included "
                                    f"in a prompt string on line {line_num}. This can lead to "
                                    f"data leakage through model outputs, logs, or training data."
                                ),
                                file_path=file_path,
                                line_number=line_num,
                                code_snippet=snippet,
                                recommendation=(
                                    "Sensitive Data in Prompts:\n"
                                    "1. Never include PII (SSN, credit cards, emails) in prompts\n"
                                    "2. Redact or anonymize sensitive data before sending to LLM\n"
                                    "3. Use data masking: 'SSN: ***-**-1234'\n"
                                    "4. Consider using PII detection libraries before LLM calls\n"
                                    "5. Implement data classification to identify sensitive fields"
                                ),
                                evidence={
                                    'sensitive_variable': var,
                                    'detection_type': 'secret_in_prompt'
                                }
                            ))

        return findings

    def _check_sensitive_system_prompts(
        self,
        llm_calls: List[Dict[str, Any]],
        source_lines: List[str],
        file_path: str
    ) -> List[Finding]:
        """Check for confidential information in system prompts"""
        findings = []

        for llm_call in llm_calls:
            line_num = llm_call.get('line', 0)

            # Get context around LLM call to find system prompt
            start = max(0, line_num - 10)
            end = min(len(source_lines), line_num + 5)
            context = '\n'.join(source_lines[start:end])
            context_lower = context.lower()

            # Check for system prompt with sensitive keywords
            if 'system' in context_lower and ('role' in context_lower or 'message' in context_lower):
                for keyword in self.SENSITIVE_PROMPT_KEYWORDS:
                    if keyword in context_lower:
                        # Find the actual line with the keyword
                        for i in range(start, end):
                            if i < len(source_lines) and keyword in source_lines[i].lower():
                                snippet = self._get_code_snippet(source_lines, i + 1)
                                findings.append(Finding(
                                    id=f"{self.detector_id}_{file_path}_{i+1}_sensitive_system_prompt",
                                    category=f"{self.detector_id}: {self.name}",
                                    severity=Severity.HIGH,
                                    confidence=0.0,
                                    title="Sensitive information in system prompt",
                                    description=(
                                        f"System prompt contains sensitive keyword '{keyword}' "
                                        f"on line {i+1}. Confidential business logic, pricing, or "
                                        f"internal policies in system prompts can be extracted "
                                        f"through prompt injection attacks."
                                    ),
                                    file_path=file_path,
                                    line_number=i + 1,
                                    code_snippet=snippet,
                                    recommendation=(
                                        "System Prompt Security:\n"
                                        "1. Never embed secrets or confidential data in prompts\n"
                                        "2. Move business logic to backend, not LLM instructions\n"
                                        "3. Use output filtering to prevent system prompt leakage\n"
                                        "4. Implement prompt injection defenses\n"
                                        "5. Consider prompt obfuscation for sensitive instructions"
                                    ),
                                    evidence={
                                        'sensitive_keyword': keyword,
                                        'detection_type': 'sensitive_system_prompt'
                                    }
                                ))
                                break

        return findings

    def _check_sensitive_logging(
        self,
        functions: List[Dict[str, Any]],
        assignments: List[Dict[str, Any]],
        source_lines: List[str],
        file_path: str
    ) -> List[Finding]:
        """Check for logging of sensitive data"""
        findings = []

        # Build set of sensitive variable names
        sensitive_vars = set()
        for assign in assignments:
            var_name = assign.get('name', '').lower()
            if any(s in var_name for s in self.SENSITIVE_DATA_VAR_NAMES):
                sensitive_vars.add(assign.get('name', ''))
            if any(s in var_name for s in self.SECRET_VARIABLE_NAMES):
                sensitive_vars.add(assign.get('name', ''))

        # Check each line for logging patterns with sensitive vars
        for line_num, line in enumerate(source_lines, 1):
            line_lower = line.lower()

            # Check for logging calls
            if any(log in line_lower for log in ['logger.', 'logging.', 'log.', 'print(']):
                # Check if any sensitive variable is being logged
                for var in sensitive_vars:
                    if var in line:
                        snippet = self._get_code_snippet(source_lines, line_num)
                        findings.append(Finding(
                            id=f"{self.detector_id}_{file_path}_{line_num}_sensitive_logging",
                            category=f"{self.detector_id}: {self.name}",
                            severity=Severity.MEDIUM,
                            confidence=0.0,
                            title="Sensitive data in log statement",
                            description=(
                                f"Variable '{var}' containing sensitive data is being logged "
                                f"on line {line_num}. Log files often lack proper access controls "
                                f"and can expose PII, secrets, or prompt content."
                            ),
                            file_path=file_path,
                            line_number=line_num,
                            code_snippet=snippet,
                            recommendation=(
                                "Secure Logging:\n"
                                "1. Never log PII, credentials, or sensitive user data\n"
                                "2. Implement log redaction for sensitive fields\n"
                                "3. Use structured logging with data classification\n"
                                "4. Set appropriate log levels (avoid DEBUG in prod)\n"
                                "5. Ensure log storage has proper access controls"
                            ),
                            evidence={
                                'logged_variable': var,
                                'detection_type': 'sensitive_logging'
                            }
                        ))

        return findings

    def calculate_confidence(self, evidence: Dict[str, Any]) -> float:
        """
        Calculate confidence based on evidence

        Scoring varies by detection type:
        - detect-secrets findings: 0.85 (trusted library)
        - Hardcoded secrets: entropy + variable name + format pattern
        - Secret in prompt: 0.8 base (high confidence when taint flows to LLM)
        - Sensitive system prompt: 0.75 base
        - Sensitive logging: 0.7 base
        """
        detection_type = evidence.get('detection_type', '')

        # detect-secrets library findings are trusted
        if evidence.get('detector') == 'detect-secrets':
            secret_type = evidence.get('secret_type', '')
            # Higher confidence for specific secret types, lower for generic
            if secret_type in ('AWS Access Key', 'OpenAI API Key', 'GitHub Token'):
                return 0.9
            elif secret_type in ('Secret Keyword', 'Basic Auth Credentials'):
                return 0.75  # Slightly above threshold
            else:
                return 0.8

        # Handle new detection types
        if detection_type == 'secret_in_prompt':
            # High confidence - sensitive variable flows to LLM
            return 0.8
        elif detection_type == 'sensitive_system_prompt':
            # Good confidence - keyword in system prompt context
            return 0.75
        elif detection_type == 'sensitive_logging':
            # Moderate confidence - logging sensitive var name
            return 0.7

        # Original logic for hardcoded secrets
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
