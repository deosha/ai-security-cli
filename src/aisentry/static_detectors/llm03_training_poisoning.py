"""
LLM03: Training Data Poisoning Detector

Detects risks related to model fine-tuning and data collection:
- Untrusted data sources for fine-tuning
- Missing data validation in training pipelines
- User-generated content used for training
- Lack of data provenance tracking
"""

import logging
from typing import Any, Dict, List

from aisentry.models.finding import Finding, Severity
from aisentry.static_detectors.base_detector import BaseDetector

logger = logging.getLogger(__name__)


class TrainingPoisoningDetector(BaseDetector):
    """
    Detect LLM03: Training Data Poisoning

    Detects:
    - Fine-tuning APIs with unvalidated data
    - User input collected for training
    - Missing data validation in training pipelines
    - Untrusted data sources
    """

    detector_id = "LLM03"
    name = "Training Data Poisoning"
    default_confidence_threshold = 0.5

    # Fine-tuning API patterns
    FINETUNING_APIS = {
        'openai.FineTune', 'openai.fine_tuning', 'fine_tuning', 'FineTuningJob',
        'anthropic.finetune', 'cohere.finetune',
        'fit(', 'train(', 'fine_tune('
    }

    # Data collection patterns
    DATA_COLLECTION_PATTERNS = {
        'feedback', 'training_data', 'dataset', 'examples',
        'user_corrections', 'annotations', 'labels'
    }

    # User input indicators
    USER_INPUT_INDICATORS = {
        'user_input', 'request.', 'form.', 'input_data',
        'user_feedback', 'user_annotation'
    }

    # Validation patterns (positive indicators)
    VALIDATION_PATTERNS = {
        'validate', 'sanitize', 'check_', 'verify_',
        'allowlist', 'whitelist', 'filter', 'clean'
    }

    # Unsafe data loading patterns (can execute arbitrary code)
    UNSAFE_LOAD_PATTERNS = {
        'pickle.load', 'pickle.loads',
        'torch.load',
        'joblib.load',
        'dill.load',
        'cloudpickle.load',
    }

    # Training/dataset context indicators in function names
    TRAINING_CONTEXT_PATTERNS = {
        'train', 'dataset', 'data', 'load', 'model',
        'finetune', 'fine_tune', 'checkpoint', 'weight'
    }

    def _gather_potential_findings(self, parsed_data: Dict[str, Any]) -> List[Finding]:
        """Find training data poisoning risks"""
        findings = []

        llm_calls = parsed_data.get('llm_api_calls', [])
        functions = parsed_data.get('functions', [])
        assignments = parsed_data.get('assignments', [])
        source_lines = parsed_data.get('source_lines', [])

        # Check 1: Fine-tuning APIs
        findings.extend(
            self._check_finetuning_apis(llm_calls, functions, source_lines, parsed_data)
        )

        # Check 2: Data collection from users
        findings.extend(
            self._check_data_collection(functions, assignments, source_lines, parsed_data)
        )

        # Check 3: Unsafe data loading in training contexts
        findings.extend(
            self._check_unsafe_data_loading(functions, source_lines, parsed_data)
        )

        return findings

    def _check_finetuning_apis(
        self,
        llm_calls: List[Dict[str, Any]],
        functions: List[Dict[str, Any]],
        source_lines: List[str],
        parsed_data: Dict[str, Any]
    ) -> List[Finding]:
        """Check for fine-tuning API usage without validation"""
        findings = []

        # Look for fine-tuning API calls
        for llm_call in llm_calls:
            func_name = llm_call.get('function', '')
            line_num = llm_call.get('line', 0)

            if any(pattern in func_name for pattern in self.FINETUNING_APIS):
                # Check if there's data validation nearby
                has_validation = self._check_validation_nearby(
                    line_num, source_lines, window=10
                )

                if not has_validation:
                    finding = self._create_finetuning_finding(
                        llm_call, source_lines, parsed_data
                    )
                    findings.append(finding)

        return findings

    def _check_data_collection(
        self,
        functions: List[Dict[str, Any]],
        assignments: List[Dict[str, Any]],
        source_lines: List[str],
        parsed_data: Dict[str, Any]
    ) -> List[Finding]:
        """Check for user data collection without validation"""
        findings = []

        for func in functions:
            func_name = func.get('name', '').lower()
            func_start = func['line']
            func_end = func.get('end_line', func_start + 50)

            # Check if function collects training data
            is_data_collection = any(
                pattern in func_name for pattern in self.DATA_COLLECTION_PATTERNS
            )

            if is_data_collection:
                # Check if it uses user input
                func_assigns = [
                    a for a in assignments
                    if func_start <= a.get('line', 0) <= func_end
                ]

                uses_user_input = False
                for assign in func_assigns:
                    value = assign.get('value', '')
                    if any(pattern in value for pattern in self.USER_INPUT_INDICATORS):
                        uses_user_input = True
                        break

                if uses_user_input:
                    # Check if validation is present
                    has_validation = self._check_validation_in_function(
                        func_start, func_end, source_lines
                    )

                    if not has_validation:
                        finding = self._create_data_collection_finding(
                            func, source_lines, parsed_data
                        )
                        findings.append(finding)

        return findings

    def _check_unsafe_data_loading(
        self,
        functions: List[Dict[str, Any]],
        source_lines: List[str],
        parsed_data: Dict[str, Any]
    ) -> List[Finding]:
        """Check for unsafe data loading (pickle, torch.load) in training contexts"""
        findings = []
        file_path = parsed_data.get('file_path', 'unknown')

        for func in functions:
            func_name = func.get('name', '').lower()
            func_start = func['line']
            func_end = func.get('end_line', func_start + 50)

            # Check if function is in a training/data context
            is_training_context = any(
                pattern in func_name for pattern in self.TRAINING_CONTEXT_PATTERNS
            )

            if not is_training_context:
                continue

            # Check for unsafe load patterns in this function
            for line_num in range(func_start, min(func_end + 1, len(source_lines) + 1)):
                if line_num > 0 and line_num <= len(source_lines):
                    line_content = source_lines[line_num - 1]

                    for pattern in self.UNSAFE_LOAD_PATTERNS:
                        if pattern in line_content:
                            # Check for safe alternatives
                            has_safe_load = (
                                'weights_only=True' in line_content or
                                'safetensors' in line_content.lower()
                            )

                            if not has_safe_load:
                                findings.append(self._create_unsafe_load_finding(
                                    func, pattern, line_num, source_lines, parsed_data
                                ))

        return findings

    def _create_unsafe_load_finding(
        self,
        func: Dict[str, Any],
        pattern: str,
        line_num: int,
        source_lines: List[str],
        parsed_data: Dict[str, Any]
    ) -> Finding:
        """Create finding for unsafe data loading"""
        file_path = parsed_data.get('file_path', 'unknown')

        snippet_start = max(0, line_num - 2)
        snippet_end = min(len(source_lines), line_num + 2)
        code_snippet = '\n'.join(source_lines[snippet_start:snippet_end])

        severity = Severity.CRITICAL if 'pickle' in pattern else Severity.HIGH

        return Finding(
            id=f"{self.detector_id}_{file_path}_{line_num}_unsafe_load",
            category=f"{self.detector_id}: {self.name}",
            severity=severity,
            confidence=0.85,
            title=f"Unsafe data loading with {pattern} in training context",
            description=(
                f"Function '{func['name']}' uses {pattern} on line {line_num}. "
                f"Pickle-based deserialization can execute arbitrary code, allowing "
                f"attackers to inject malicious code through poisoned training data or models."
            ),
            file_path=file_path,
            line_number=line_num,
            code_snippet=code_snippet,
            recommendation=(
                "Secure Data Loading:\n"
                "1. Use safetensors instead of pickle for model weights\n"
                "2. For torch.load, use weights_only=True\n"
                "3. Verify checksums/signatures before loading\n"
                "4. Only load data from trusted, verified sources\n"
                "5. Implement content scanning before deserialization\n"
                "6. Consider using JSON/YAML for configuration data"
            ),
            evidence={
                'function_name': func['name'],
                'unsafe_pattern': pattern,
                'risk_type': 'unsafe_data_loading'
            }
        )

    def _check_validation_nearby(
        self, line: int, source_lines: List[str], window: int = 5
    ) -> bool:
        """Check if validation exists within window of lines"""
        start = max(0, line - window)
        end = min(len(source_lines), line + window)

        for i in range(start, end):
            if i < len(source_lines):
                line_content = source_lines[i].lower()
                if any(pattern in line_content for pattern in self.VALIDATION_PATTERNS):
                    return True

        return False

    def _check_validation_in_function(
        self, func_start: int, func_end: int, source_lines: List[str]
    ) -> bool:
        """Check if validation exists in function"""
        for line_num in range(func_start, min(func_end + 1, len(source_lines) + 1)):
            if line_num > 0 and line_num <= len(source_lines):
                line_content = source_lines[line_num - 1].lower()
                if any(pattern in line_content for pattern in self.VALIDATION_PATTERNS):
                    return True
        return False

    def _create_finetuning_finding(
        self,
        llm_call: Dict[str, Any],
        source_lines: List[str],
        parsed_data: Dict[str, Any]
    ) -> Finding:
        """Create finding for unvalidated fine-tuning"""
        file_path = parsed_data.get('file_path', 'unknown')
        line_num = llm_call.get('line', 0)

        snippet_start = max(0, line_num - 2)
        snippet_end = min(len(source_lines), line_num + 3)
        code_snippet = '\n'.join(source_lines[snippet_start:snippet_end])

        evidence = {
            'api_function': llm_call.get('function', ''),
            'has_validation': False,
            'risk_type': 'unvalidated_finetuning'
        }

        return Finding(
            id=f"{self.detector_id}_{file_path}_{line_num}",
            category=f"{self.detector_id}: {self.name}",
            severity=Severity.HIGH,
            confidence=0.7,
            title="Fine-tuning with potentially unvalidated training data",
            description=(
                f"Fine-tuning API '{llm_call.get('function')}' is called on line {line_num} "
                f"without visible data validation. Poisoned training data can manipulate model "
                f"behavior, inject backdoors, or leak sensitive information through model outputs."
            ),
            file_path=file_path,
            line_number=line_num,
            code_snippet=code_snippet,
            recommendation=(
                "Training Data Security:\n"
                "1. Validate all training data sources\n"
                "2. Implement data provenance tracking\n"
                "3. Apply content filtering and anomaly detection\n"
                "4. Use trusted, curated datasets when possible\n"
                "5. Monitor model outputs for signs of poisoning\n"
                "6. Implement data versioning and rollback capability\n"
                "7. Regularly audit training data for malicious content"
            ),
            evidence=evidence
        )

    def _create_data_collection_finding(
        self,
        func: Dict[str, Any],
        source_lines: List[str],
        parsed_data: Dict[str, Any]
    ) -> Finding:
        """Create finding for unvalidated data collection"""
        file_path = parsed_data.get('file_path', 'unknown')
        line_num = func['line']

        snippet_start = max(0, line_num - 1)
        snippet_end = min(len(source_lines), line_num + 5)
        code_snippet = '\n'.join(source_lines[snippet_start:snippet_end])

        evidence = {
            'function_name': func['name'],
            'has_validation': False,
            'risk_type': 'unvalidated_data_collection'
        }

        return Finding(
            id=f"{self.detector_id}_{file_path}_{line_num}_collection",
            category=f"{self.detector_id}: {self.name}",
            severity=Severity.MEDIUM,
            confidence=0.6,
            title="Training data collected from users without validation",
            description=(
                f"Function '{func['name']}' collects data from users for training/fine-tuning "
                f"on line {line_num} without visible validation. Attackers can submit poisoned "
                f"data to manipulate model behavior or inject backdoors."
            ),
            file_path=file_path,
            line_number=line_num,
            code_snippet=code_snippet,
            recommendation=(
                "Data Collection Security:\n"
                "1. Validate all user-submitted training data\n"
                "2. Implement content moderation and filtering\n"
                "3. Use rate limiting to prevent bulk poisoning\n"
                "4. Apply anomaly detection to identify suspicious patterns\n"
                "5. Require authentication for data submission\n"
                "6. Log data provenance for audit trails\n"
                "7. Implement human review for high-risk submissions"
            ),
            evidence=evidence
        )

    def calculate_confidence(self, evidence: Dict[str, Any]) -> float:
        """Calculate confidence based on evidence"""
        confidence = 0.6  # Base confidence

        risk_type = evidence.get('risk_type', '')
        if risk_type == 'unsafe_data_loading':
            # High confidence - pickle/torch.load in training context
            # is a well-known attack vector (CVE-rich pattern)
            confidence = 0.85
        elif risk_type == 'unvalidated_finetuning':
            confidence = 0.7
        elif risk_type == 'unvalidated_data_collection':
            confidence = 0.6

        return confidence
