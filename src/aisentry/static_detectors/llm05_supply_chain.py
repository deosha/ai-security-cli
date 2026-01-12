"""
LLM05: Supply Chain Vulnerabilities Detector

Detects risks in the AI/ML supply chain:
- Unpinned model dependencies
- Untrusted model sources
- Missing model verification
- Vulnerable ML libraries
- Unsigned model downloads

Confirmer Strategy (v1.1 - Precision Improvement):
To reduce false positives, this detector requires a CONJUNCTION of signals
before emitting HIGH/CRITICAL findings:
  - Supply chain risk indicator (unpinned, untrusted source, etc.) AND
  - Dynamic execution/loading pattern (importlib, exec, subprocess, etc.)

Findings without dynamic execution confirmers are demoted to LOW/INFO (advisory).
"""

import logging
import re
from typing import Any, Dict, List

from aisentry.models.finding import Finding, Severity
from aisentry.static_detectors.base_detector import BaseDetector

logger = logging.getLogger(__name__)


class SupplyChainDetector(BaseDetector):
    """
    Detect LLM05: Supply Chain Vulnerabilities

    Detects:
    - Unpinned model versions (model="gpt-4" without version)
    - Untrusted model sources (arbitrary URLs, local paths)
    - Missing model verification (no checksums, signatures)
    - Vulnerable ML library versions
    - Direct model downloads without validation
    """

    detector_id = "LLM05"
    name = "Supply Chain Vulnerabilities"
    default_confidence_threshold = 0.6

    # Model loading patterns - functions that actually load/download models
    MODEL_LOADING_FUNCTIONS = {
        # HuggingFace - the most common ML model loading
        'from_pretrained',
        'AutoModel', 'AutoTokenizer', 'AutoModelForCausalLM',
        'AutoModelForSequenceClassification', 'AutoModelForTokenClassification',
        'pipeline',
        # PyTorch
        'torch.load', 'torch.hub.load', 'load_state_dict',
        # TensorFlow/Keras
        'load_model', 'tf.saved_model.load', 'keras.models.load_model',
        # Generic model loading
        'load_weights', 'restore', 'load_checkpoint',
        # Sentence transformers
        'SentenceTransformer',
    }

    # Trusted model repositories - URLs containing these are OK
    TRUSTED_SOURCES = {
        'huggingface.co', 'hf.co', 'huggingface-models',
        'openai.com', 'anthropic.com',
        'tensorflow.org', 'pytorch.org',
        'registry.hub.docker.com',
        'storage.googleapis.com/tensorflow',
        'download.pytorch.org',
    }

    # Verification patterns (positive indicators)
    VERIFICATION_PATTERNS = {
        'checksum': ['sha256', 'md5sum', 'hashlib', 'verify_checksum', 'check_hash'],
        'signature': ['gpg', 'signature', 'verify_signature', 'signed'],
        'pinning': ['revision=', 'model_version', 'version=', '@'],
        'sbom': ['sbom', 'bill_of_materials', 'dependencies.json']
    }

    # Model file extensions - only flag URLs/paths with these extensions
    MODEL_FILE_EXTENSIONS = {
        '.pt', '.pth', '.bin', '.h5', '.hdf5', '.ckpt',
        '.safetensors', '.onnx', '.pb', '.tflite', '.model'
    }

    # ==========================================================================
    # CONFIRMER PATTERNS - Dynamic execution/loading (required for HIGH/CRITICAL)
    # ==========================================================================

    # Dynamic module loading patterns
    DYNAMIC_LOADING_PATTERNS = {
        'importlib.import_module',
        'importlib.util.spec_from_file_location',
        'importlib.util.module_from_spec',
        '__import__',
        'pkg_resources.iter_entry_points',
        'pkg_resources.load_entry_point',
        'importlib.metadata.entry_points',
        'pluggy',  # Plugin framework
        'stevedore',  # Plugin framework
    }

    # Code execution patterns (when combined with external input)
    CODE_EXEC_PATTERNS = {
        'exec', 'eval', 'compile',
        'ast.literal_eval',  # Safer but still deserializes
    }

    # Subprocess patterns that could execute downloaded code
    SUBPROCESS_EXEC_PATTERNS = {
        'subprocess.run', 'subprocess.call', 'subprocess.Popen',
        'subprocess.check_output', 'subprocess.check_call',
        'os.system', 'os.popen', 'os.exec', 'os.spawn',
    }

    # Network fetch patterns (for fetch + exec detection)
    NETWORK_FETCH_PATTERNS = {
        'requests.get', 'requests.post', 'requests.request',
        'urllib.request.urlopen', 'urllib.request.urlretrieve',
        'httpx.get', 'httpx.post', 'httpx.Client',
        'aiohttp.ClientSession',
    }

    # Pip/package installation patterns
    PIP_INSTALL_PATTERNS = [
        r'pip\s+install',
        r'subprocess.*pip.*install',
        r'os\.system.*pip.*install',
        r'pkg_resources\.working_set\.add',
    ]

    # Integrity verification patterns (positive signal - reduces severity)
    INTEGRITY_CHECK_PATTERNS = {
        'hashlib.sha256', 'hashlib.md5', 'hashlib.sha512',
        'verify_checksum', 'check_hash', 'verify_hash',
        'gpg.verify', 'signature', 'verify_signature',
        'sigstore', 'cosign',  # Modern signing tools
    }

    # ==========================================================================
    # ADDITIONAL SUPPLY CHAIN RISK PATTERNS
    # ==========================================================================

    # Unsafe model loading patterns (direct vulnerability indicators)
    UNSAFE_LOADING_PATTERNS = [
        # HuggingFace trust_remote_code
        (r'trust_remote_code\s*=\s*True', 'trust_remote_code=True enables arbitrary code execution'),
        # PyTorch unsafe load - negative lookahead INSIDE to check args don't contain weights_only
        (r'torch\.load\s*\((?![^)]*weights_only)[^)]*\)', 'torch.load without weights_only=True can execute arbitrary code'),
        # Joblib load
        (r'joblib\.load\s*\(', 'joblib.load can execute arbitrary code from untrusted files'),
    ]

    # Dynamic tool/plugin loading patterns
    DYNAMIC_TOOL_PATTERNS = [
        (r'load_tools\s*\(\s*\[', 'Loading dynamic LangChain tools without verification'),
        (r'create_tool_calling_agent', 'Dynamic tool calling without validation'),
    ]

    # Eval/exec on external content patterns
    EXTERNAL_CODE_EXEC_PATTERNS = [
        (r'eval\s*\(\s*(?![\"\'])', 'eval() on non-literal content'),
        (r'exec\s*\(\s*(?![\"\'])', 'exec() on non-literal content'),
        (r'compile\s*\([^,]+,\s*[^,]+,\s*[\"\']exec', 'compile() for execution'),
    ]

    def _gather_potential_findings(self, parsed_data: Dict[str, Any]) -> List[Finding]:
        """Find supply chain vulnerabilities with confirmer-based precision."""
        findings = []

        imports = parsed_data.get('imports', [])
        llm_calls = parsed_data.get('llm_api_calls', [])
        assignments = parsed_data.get('assignments', [])
        source_lines = parsed_data.get('source_lines', [])
        file_path = parsed_data.get('file_path', 'unknown')

        # Step 1: Detect confirmer signals (dynamic execution patterns)
        confirmers = self._detect_confirmers(source_lines, imports)

        # Step 2: Detect integrity checks (positive signal)
        has_integrity_checks = self._detect_integrity_checks(source_lines)

        # Check 1: Unpinned model versions (demote without confirmers)
        findings.extend(
            self._check_unpinned_models(
                llm_calls, assignments, source_lines, file_path,
                confirmers, has_integrity_checks
            )
        )

        # Check 2: Untrusted model sources (keep HIGH if URL + dynamic exec)
        findings.extend(
            self._check_untrusted_sources(
                source_lines, file_path, confirmers, has_integrity_checks
            )
        )

        # Check 3: Missing verification (demote without confirmers)
        findings.extend(
            self._check_missing_verification(
                llm_calls, source_lines, file_path,
                confirmers, has_integrity_checks
            )
        )

        # Check 4: Vulnerable libraries (demote without external model loading)
        findings.extend(
            self._check_vulnerable_libraries(
                imports, file_path, confirmers, has_integrity_checks
            )
        )

        # Check 5: NEW - Direct dynamic execution risks (network fetch + exec)
        findings.extend(
            self._check_fetch_and_execute(source_lines, file_path, confirmers)
        )

        # Check 6: NEW - Unsafe loading patterns (trust_remote_code, torch.load, etc.)
        findings.extend(
            self._check_unsafe_loading_patterns(source_lines, file_path, confirmers)
        )

        # Check 7: NEW - Dynamic tool loading (LangChain load_tools, etc.)
        findings.extend(
            self._check_dynamic_tool_loading(source_lines, file_path)
        )

        # Check 8: NEW - External code execution (eval/exec on non-literals)
        findings.extend(
            self._check_external_code_execution(source_lines, file_path, confirmers)
        )

        return findings

    def _detect_confirmers(
        self,
        source_lines: List[str],
        imports: List[Dict[str, Any]]
    ) -> Dict[str, bool]:
        """
        Detect dynamic execution/loading patterns that confirm supply chain risk.

        Returns dict of confirmer signals:
        - dynamic_loading: importlib, __import__, entry_points, plugin frameworks
        - code_execution: exec/eval/compile on non-literal strings
        - subprocess_exec: subprocess with dynamic commands
        - network_fetch: requests/urllib/httpx downloads
        - pip_install: programmatic pip install
        - fetch_and_exec: network fetch followed by execution (highest risk)
        """
        source_code = '\n'.join(source_lines)
        source_lower = source_code.lower()

        confirmers = {
            'dynamic_loading': False,
            'code_execution': False,
            'subprocess_exec': False,
            'network_fetch': False,
            'pip_install': False,
            'fetch_and_exec': False,
            'any': False,  # Convenience: any confirmer present
        }

        # Check for dynamic loading patterns
        for pattern in self.DYNAMIC_LOADING_PATTERNS:
            if pattern.lower() in source_lower:
                confirmers['dynamic_loading'] = True
                break

        # Check imports for dynamic loading modules
        import_modules = {imp.get('module', '').lower() for imp in imports}
        if any(mod in import_modules for mod in ['importlib', 'pkg_resources', 'pluggy', 'stevedore']):
            confirmers['dynamic_loading'] = True

        # Check for code execution patterns
        for pattern in self.CODE_EXEC_PATTERNS:
            # Look for exec/eval with non-literal args (not just exec("literal"))
            exec_pattern = rf'\b{pattern}\s*\([^"\')\s]'
            if re.search(exec_pattern, source_code):
                confirmers['code_execution'] = True
                break

        # Check for subprocess execution
        for pattern in self.SUBPROCESS_EXEC_PATTERNS:
            if pattern.lower() in source_lower:
                confirmers['subprocess_exec'] = True
                break

        # Check for network fetch
        for pattern in self.NETWORK_FETCH_PATTERNS:
            if pattern.lower() in source_lower:
                confirmers['network_fetch'] = True
                break

        # Check for pip install patterns
        for pattern in self.PIP_INSTALL_PATTERNS:
            if re.search(pattern, source_code, re.IGNORECASE):
                confirmers['pip_install'] = True
                break

        # Check for fetch + execute combination (highest risk)
        if confirmers['network_fetch'] and (
            confirmers['code_execution'] or
            confirmers['subprocess_exec'] or
            confirmers['pip_install']
        ):
            confirmers['fetch_and_exec'] = True

        # Set convenience flag
        confirmers['any'] = any([
            confirmers['dynamic_loading'],
            confirmers['code_execution'],
            confirmers['subprocess_exec'],
            confirmers['pip_install'],
            # Note: network_fetch alone is not a confirmer
        ])

        return confirmers

    def _detect_integrity_checks(self, source_lines: List[str]) -> bool:
        """Detect if file has integrity verification (positive signal)."""
        source_lower = '\n'.join(source_lines).lower()
        return any(
            pattern.lower() in source_lower
            for pattern in self.INTEGRITY_CHECK_PATTERNS
        )

    def _check_unpinned_models(
        self,
        llm_calls: List[Dict[str, Any]],
        assignments: List[Dict[str, Any]],
        source_lines: List[str],
        file_path: str,
        confirmers: Dict[str, bool],
        has_integrity_checks: bool
    ) -> List[Finding]:
        """
        Check for unpinned model versions.

        Severity logic with confirmers:
        - WITH dynamic loading confirmers: MEDIUM (real risk)
        - WITHOUT confirmers: LOW/INFO (advisory only)
        - WITH integrity checks: further demoted
        """
        findings = []

        for llm_call in llm_calls:
            func_name = llm_call.get('function', '')
            line_num = llm_call.get('line', 0)
            keywords = llm_call.get('keywords', {})

            # Check if model is specified
            model_arg = keywords.get('model') or keywords.get('model_name')

            if model_arg and line_num > 0:
                # Check if version is pinned
                has_pinning = any(
                    pattern in model_arg
                    for pattern in self.VERIFICATION_PATTERNS['pinning']
                )

                if not has_pinning and self._is_model_identifier(model_arg):
                    # Determine severity based on confirmers
                    if confirmers['any']:
                        severity = Severity.MEDIUM
                        confidence = 0.75
                    else:
                        # No dynamic execution = advisory only
                        severity = Severity.LOW
                        confidence = 0.5

                    # Further demote if integrity checks present
                    if has_integrity_checks:
                        severity = Severity.INFO
                        confidence = max(0.4, confidence - 0.15)

                    evidence = {
                        'function': func_name,
                        'model_arg': model_arg,
                        'has_pinning': False,
                        'line': line_num,
                        'has_confirmers': confirmers['any'],
                        'confirmer_types': [k for k, v in confirmers.items() if v and k != 'any'],
                        'has_integrity_checks': has_integrity_checks,
                    }

                    findings.append(Finding(
                        id=f"{self.detector_id}_{file_path}_{line_num}_unpinned",
                        category=f"{self.detector_id}: Supply Chain Vulnerabilities",
                        severity=severity,
                        confidence=confidence,
                        title="Unpinned model version in API call",
                        description=(
                            f"Model '{model_arg}' is used without version pinning on line {line_num}. "
                            f"Unpinned models can change unexpectedly, introducing breaking changes, "
                            f"security vulnerabilities, or behavioral shifts."
                            + (" This file contains dynamic code execution patterns, increasing risk."
                               if confirmers['any'] else
                               " (Advisory: no dynamic execution detected in this file.)")
                        ),
                        file_path=file_path,
                        line_number=line_num,
                        code_snippet=self._get_code_snippet(source_lines, line_num, 3),
                        recommendation=(
                            "Supply Chain Security Best Practices:\n"
                            "1. Pin model versions explicitly (model='gpt-4-0613')\n"
                            "2. Use model registries with version control\n"
                            "3. Document model versions in requirements.txt or similar\n"
                            "4. Implement model versioning in CI/CD pipelines"
                        ),
                        evidence=evidence
                    ))

        return findings

    def _check_untrusted_sources(
        self,
        source_lines: List[str],
        file_path: str,
        confirmers: Dict[str, bool],
        has_integrity_checks: bool
    ) -> List[Finding]:
        """
        Check for untrusted model sources - ONLY in model loading contexts.

        Severity logic with confirmers:
        - Dynamic model path from user input: Always CRITICAL (direct injection)
        - Untrusted URL + exec confirmers: HIGH
        - Untrusted URL without confirmers: MEDIUM (still a risk)
        - With integrity checks: demoted one level
        """
        findings = []
        source_code = '\n'.join(source_lines)

        # Check 1: URLs that look like model downloads (have model file extensions)
        model_url_pattern = r'["\']https?://[^"\']+\.(?:pt|pth|bin|h5|hdf5|ckpt|safetensors|onnx|pb|tflite|model)["\']'
        for match in re.finditer(model_url_pattern, source_code, re.IGNORECASE):
            url = match.group(0).strip('"\'')
            line_num = source_code[:match.start()].count('\n') + 1

            # Skip if from trusted source
            if any(trusted in url.lower() for trusted in self.TRUSTED_SOURCES):
                continue

            # Severity based on confirmers
            if confirmers['fetch_and_exec']:
                severity = Severity.CRITICAL
                confidence = 0.9
            elif confirmers['any']:
                severity = Severity.HIGH
                confidence = 0.85
            else:
                severity = Severity.MEDIUM
                confidence = 0.7

            # Demote if integrity checks present
            if has_integrity_checks:
                if severity == Severity.CRITICAL:
                    severity = Severity.HIGH
                elif severity == Severity.HIGH:
                    severity = Severity.MEDIUM
                else:
                    severity = Severity.LOW
                confidence = max(0.5, confidence - 0.15)

            evidence = {
                'pattern_type': 'untrusted_model_url',
                'url': url,
                'line': line_num,
                'has_confirmers': confirmers['any'],
                'fetch_and_exec': confirmers['fetch_and_exec'],
                'has_integrity_checks': has_integrity_checks,
            }

            findings.append(Finding(
                id=f"{self.detector_id}_{file_path}_{line_num}_model_url",
                category=f"{self.detector_id}: Supply Chain Vulnerabilities",
                severity=severity,
                confidence=confidence,
                title="Model downloaded from untrusted URL",
                description=(
                    f"Model file downloaded from untrusted URL '{url}' on line {line_num}. "
                    f"Loading models from arbitrary URLs poses security risks."
                    + (" File contains network fetch + code execution - HIGH RISK."
                       if confirmers['fetch_and_exec'] else "")
                ),
                file_path=file_path,
                line_number=line_num,
                code_snippet=self._get_code_snippet(source_lines, line_num, 3),
                recommendation=(
                    "Secure Model Loading:\n"
                    "1. Only load models from trusted registries (HuggingFace, PyTorch Hub)\n"
                    "2. Verify model checksums/signatures before loading\n"
                    "3. Pin specific model versions with revision hashes\n"
                    "4. Consider using safetensors format"
                ),
                evidence=evidence
            ))

        # Check 2: Dynamic model paths from user/request input (always high severity)
        dynamic_patterns = [
            (r'model_name\s*=\s*request\.', 'request input'),
            (r'model_path\s*=\s*request\.', 'request input'),
            (r'model_id\s*=\s*os\.getenv', 'environment variable'),
            (r'from_pretrained\s*\(\s*user_', 'user input'),
            (r'from_pretrained\s*\(\s*request\.', 'request input'),
            (r'torch\.load\s*\(\s*user_', 'user input'),
            (r'torch\.load\s*\(\s*request\.', 'request input'),
        ]

        for pattern, source_type in dynamic_patterns:
            for match in re.finditer(pattern, source_code, re.IGNORECASE):
                line_num = source_code[:match.start()].count('\n') + 1

                # Dynamic paths are always dangerous (direct user control)
                severity = Severity.CRITICAL
                confidence = 0.9

                if has_integrity_checks:
                    severity = Severity.HIGH
                    confidence = 0.8

                evidence = {
                    'pattern_type': 'dynamic_model_path',
                    'source': source_type,
                    'line': line_num,
                    'has_integrity_checks': has_integrity_checks,
                }

                findings.append(Finding(
                    id=f"{self.detector_id}_{file_path}_{line_num}_dynamic",
                    category=f"{self.detector_id}: Supply Chain Vulnerabilities",
                    severity=severity,
                    confidence=confidence,
                    title=f"Dynamic model path from {source_type}",
                    description=(
                        f"Model path determined by {source_type} on line {line_num}. "
                        f"Allowing external control of model paths enables attackers to "
                        f"load malicious models or access unauthorized model files."
                    ),
                    file_path=file_path,
                    line_number=line_num,
                    code_snippet=self._get_code_snippet(source_lines, line_num, 3),
                    recommendation=(
                        "Secure Model Selection:\n"
                        "1. Use allowlists for permitted model names\n"
                        "2. Validate and sanitize model identifiers\n"
                        "3. Never allow arbitrary file paths from user input\n"
                        "4. Use model registries with access controls"
                    ),
                    evidence=evidence
                ))

        return findings

    def _check_missing_verification(
        self,
        llm_calls: List[Dict[str, Any]],
        source_lines: List[str],
        file_path: str,
        confirmers: Dict[str, bool],
        has_integrity_checks: bool
    ) -> List[Finding]:
        """
        Check for model loading without verification.

        Severity logic:
        - WITH dynamic loading + no verification: MEDIUM
        - WITHOUT confirmers: INFO (advisory only)
        - Already has integrity checks: skip entirely
        """
        findings = []

        # If integrity checks already present, skip this check
        if has_integrity_checks:
            return findings

        source_code = ' '.join(source_lines).lower()

        # Check if any verification is present
        has_verification = any(
            any(pattern in source_code for pattern in patterns)
            for patterns in self.VERIFICATION_PATTERNS.values()
        )

        if has_verification:
            return findings

        # Look for model loading without verification
        for llm_call in llm_calls:
            func_name = llm_call.get('function', '')
            line_num = llm_call.get('line', 0)

            # Check if this is a model loading function
            is_model_loading = any(
                pattern.lower() in func_name.lower()
                for pattern in self.MODEL_LOADING_FUNCTIONS
            )

            if is_model_loading and line_num > 0:
                # Check nearby lines for verification (within 10 lines)
                nearby_verification = self._check_verification_nearby(
                    line_num, source_lines, window=10
                )

                if not nearby_verification:
                    # Severity based on confirmers
                    if confirmers['any']:
                        severity = Severity.MEDIUM
                        confidence = 0.65
                    else:
                        # No dynamic execution = advisory only
                        severity = Severity.INFO
                        confidence = 0.45

                    evidence = {
                        'function': llm_call.get('function'),
                        'has_verification': False,
                        'line': line_num,
                        'has_confirmers': confirmers['any'],
                    }

                    findings.append(Finding(
                        id=f"{self.detector_id}_{file_path}_{line_num}_no_verification",
                        category=f"{self.detector_id}: Supply Chain Vulnerabilities",
                        severity=severity,
                        confidence=confidence,
                        title="Model loaded without integrity verification",
                        description=(
                            f"Model loading on line {line_num} lacks integrity verification."
                            + (" File contains dynamic code execution - verification recommended."
                               if confirmers['any'] else
                               " (Advisory: consider adding checksum verification.)")
                        ),
                        file_path=file_path,
                        line_number=line_num,
                        code_snippet=self._get_code_snippet(source_lines, line_num, 3),
                        recommendation=(
                            "Model Verification:\n"
                            "1. Verify SHA256 checksums before loading models\n"
                            "2. Use model registries with built-in verification\n"
                            "3. Store expected hashes in version control"
                        ),
                        evidence=evidence
                    ))
                    break  # Only report once per file

        return findings

    def _check_vulnerable_libraries(
        self,
        imports: List[Dict[str, Any]],
        file_path: str,
        confirmers: Dict[str, bool],
        has_integrity_checks: bool
    ) -> List[Finding]:
        """
        Check for known vulnerable ML libraries.

        Severity logic:
        - pickle/dill + network fetch + loading external data: HIGH
        - pickle/dill + dynamic loading patterns: MEDIUM
        - pickle/dill import alone: INFO (advisory - common for internal use)
        """
        findings = []

        # Known vulnerable patterns
        vulnerable_imports = {
            'pickle': ('arbitrary_code_execution', 'pickle'),
            'joblib': ('arbitrary_code_execution', 'joblib'),
            'dill': ('arbitrary_code_execution', 'dill'),
        }

        for imp in imports:
            module = imp.get('module', '')
            line_num = imp.get('line', 0)

            for vuln_module, (vuln_type, vuln_name) in vulnerable_imports.items():
                if vuln_module in module.lower():
                    # Severity based on confirmers
                    if confirmers['fetch_and_exec'] or confirmers['network_fetch']:
                        # Loading external data with pickle = HIGH risk
                        severity = Severity.HIGH
                        confidence = 0.8
                    elif confirmers['any']:
                        # Dynamic patterns with pickle = MEDIUM
                        severity = Severity.MEDIUM
                        confidence = 0.65
                    else:
                        # Just pickle import = advisory only
                        severity = Severity.INFO
                        confidence = 0.4

                    # Demote if integrity checks present
                    if has_integrity_checks and severity != Severity.INFO:
                        if severity == Severity.HIGH:
                            severity = Severity.MEDIUM
                        elif severity == Severity.MEDIUM:
                            severity = Severity.LOW
                        confidence = max(0.4, confidence - 0.1)

                    evidence = {
                        'module': module,
                        'vulnerability': vuln_type,
                        'line': line_num,
                        'has_confirmers': confirmers['any'],
                        'network_fetch': confirmers['network_fetch'],
                        'has_integrity_checks': has_integrity_checks,
                    }

                    findings.append(Finding(
                        id=f"{self.detector_id}_{file_path}_{line_num}_{vuln_name}",
                        category=f"{self.detector_id}: Supply Chain Vulnerabilities",
                        severity=severity,
                        confidence=confidence,
                        title=f"Use of {vuln_name} for serialization",
                        description=(
                            f"Import of '{module}' on line {line_num}. "
                            f"This library can execute arbitrary code during deserialization."
                            + (" File fetches external data - HIGH RISK if deserializing remote content."
                               if confirmers['network_fetch'] else
                               " (Advisory: safe if only used with trusted local data.)")
                        ),
                        file_path=file_path,
                        line_number=line_num,
                        code_snippet=f"import {module}",
                        recommendation=(
                            "Secure Serialization:\n"
                            "1. Use safer alternatives like safetensors\n"
                            "2. Never deserialize from untrusted sources\n"
                            "3. Consider using ONNX for model exchange"
                        ),
                        evidence=evidence
                    ))

        return findings

    def _check_fetch_and_execute(
        self,
        source_lines: List[str],
        file_path: str,
        confirmers: Dict[str, bool]
    ) -> List[Finding]:
        """
        NEW: Detect high-risk fetch + execute patterns.

        This is the highest-confidence supply chain finding:
        downloading code/models and executing them.
        """
        findings = []

        if not confirmers['fetch_and_exec']:
            return findings

        source_code = '\n'.join(source_lines)

        # Find lines with network fetch
        fetch_lines = []
        for i, line in enumerate(source_lines, 1):
            line_lower = line.lower()
            if any(pattern.lower() in line_lower for pattern in self.NETWORK_FETCH_PATTERNS):
                fetch_lines.append(i)

        # Find lines with code execution
        exec_lines = []
        for i, line in enumerate(source_lines, 1):
            line_lower = line.lower()
            if any(pattern.lower() in line_lower for pattern in
                   list(self.CODE_EXEC_PATTERNS) + list(self.SUBPROCESS_EXEC_PATTERNS)):
                exec_lines.append(i)

        # Report the fetch + exec combination
        if fetch_lines and exec_lines:
            # Use the first exec line as the finding location
            line_num = exec_lines[0]

            evidence = {
                'pattern_type': 'fetch_and_execute',
                'fetch_lines': fetch_lines[:3],  # First 3
                'exec_lines': exec_lines[:3],
                'line': line_num,
            }

            findings.append(Finding(
                id=f"{self.detector_id}_{file_path}_{line_num}_fetch_exec",
                category=f"{self.detector_id}: Supply Chain Vulnerabilities",
                severity=Severity.CRITICAL,
                confidence=0.85,
                title="Network fetch combined with code execution",
                description=(
                    f"This file downloads external content (lines {fetch_lines[:3]}) "
                    f"and executes code (lines {exec_lines[:3]}). "
                    f"This pattern enables remote code execution attacks if the fetched "
                    f"content is not properly validated."
                ),
                file_path=file_path,
                line_number=line_num,
                code_snippet=self._get_code_snippet(source_lines, line_num, 5),
                recommendation=(
                    "Secure Remote Code Patterns:\n"
                    "1. NEVER execute code fetched from network without verification\n"
                    "2. Use cryptographic signatures to verify downloaded code\n"
                    "3. Pin URLs and verify checksums\n"
                    "4. Use package managers instead of direct downloads\n"
                    "5. Sandbox execution in isolated environments"
                ),
                evidence=evidence
            ))

        return findings

    def _check_unsafe_loading_patterns(
        self,
        source_lines: List[str],
        file_path: str,
        confirmers: Dict[str, bool]
    ) -> List[Finding]:
        """
        Check for unsafe model loading patterns:
        - trust_remote_code=True
        - torch.load without weights_only
        - joblib.load on external files
        """
        findings = []
        source_code = '\n'.join(source_lines)

        for pattern, description in self.UNSAFE_LOADING_PATTERNS:
            for match in re.finditer(pattern, source_code, re.IGNORECASE):
                line_num = source_code[:match.start()].count('\n') + 1

                # These are high-confidence findings (direct vulnerability)
                severity = Severity.HIGH if 'trust_remote_code' in pattern else Severity.MEDIUM
                confidence = 0.9 if 'trust_remote_code' in pattern else 0.8

                # Boost if confirmers present
                if confirmers['any']:
                    if severity == Severity.MEDIUM:
                        severity = Severity.HIGH
                    confidence = min(0.95, confidence + 0.1)

                evidence = {
                    'pattern': pattern,
                    'description': description,
                    'line': line_num,
                    'has_confirmers': confirmers['any'],
                }

                findings.append(Finding(
                    id=f"{self.detector_id}_{file_path}_{line_num}_unsafe_load",
                    category=f"{self.detector_id}: Supply Chain Vulnerabilities",
                    severity=severity,
                    confidence=confidence,
                    title="Unsafe model loading pattern",
                    description=f"{description} on line {line_num}.",
                    file_path=file_path,
                    line_number=line_num,
                    code_snippet=self._get_code_snippet(source_lines, line_num, 3),
                    recommendation=(
                        "Secure Model Loading:\n"
                        "1. Set trust_remote_code=False\n"
                        "2. Use torch.load(..., weights_only=True)\n"
                        "3. Verify model sources and checksums\n"
                        "4. Use safetensors format instead of pickle"
                    ),
                    evidence=evidence
                ))

        return findings

    def _check_dynamic_tool_loading(
        self,
        source_lines: List[str],
        file_path: str
    ) -> List[Finding]:
        """
        Check for dynamic tool/plugin loading patterns.
        These are always medium+ severity since they load external code.
        """
        findings = []
        source_code = '\n'.join(source_lines)

        for pattern, description in self.DYNAMIC_TOOL_PATTERNS:
            for match in re.finditer(pattern, source_code, re.IGNORECASE):
                line_num = source_code[:match.start()].count('\n') + 1

                evidence = {
                    'pattern': pattern,
                    'description': description,
                    'line': line_num,
                }

                findings.append(Finding(
                    id=f"{self.detector_id}_{file_path}_{line_num}_dynamic_tool",
                    category=f"{self.detector_id}: Supply Chain Vulnerabilities",
                    severity=Severity.MEDIUM,
                    confidence=0.75,
                    title="Dynamic tool/plugin loading",
                    description=f"{description} on line {line_num}.",
                    file_path=file_path,
                    line_number=line_num,
                    code_snippet=self._get_code_snippet(source_lines, line_num, 3),
                    recommendation=(
                        "Secure Tool Loading:\n"
                        "1. Validate tool names against an allowlist\n"
                        "2. Only load tools from trusted sources\n"
                        "3. Review tool permissions before loading\n"
                        "4. Sandbox tool execution"
                    ),
                    evidence=evidence
                ))

        return findings

    def _check_external_code_execution(
        self,
        source_lines: List[str],
        file_path: str,
        confirmers: Dict[str, bool]
    ) -> List[Finding]:
        """
        Check for eval/exec on external (non-literal) content.
        This is a supply chain risk when the content comes from files/network.
        """
        findings = []
        source_code = '\n'.join(source_lines)

        for pattern, description in self.EXTERNAL_CODE_EXEC_PATTERNS:
            for match in re.finditer(pattern, source_code):
                line_num = source_code[:match.start()].count('\n') + 1

                # High severity if combined with network fetch
                if confirmers['network_fetch']:
                    severity = Severity.CRITICAL
                    confidence = 0.9
                elif confirmers['any']:
                    severity = Severity.HIGH
                    confidence = 0.85
                else:
                    severity = Severity.MEDIUM
                    confidence = 0.7

                evidence = {
                    'pattern': pattern,
                    'description': description,
                    'line': line_num,
                    'network_fetch': confirmers['network_fetch'],
                    'has_confirmers': confirmers['any'],
                }

                findings.append(Finding(
                    id=f"{self.detector_id}_{file_path}_{line_num}_code_exec",
                    category=f"{self.detector_id}: Supply Chain Vulnerabilities",
                    severity=severity,
                    confidence=confidence,
                    title="Code execution on external content",
                    description=(
                        f"{description} on line {line_num}. "
                        + ("File fetches external content - HIGH RISK."
                           if confirmers['network_fetch'] else "")
                    ),
                    file_path=file_path,
                    line_number=line_num,
                    code_snippet=self._get_code_snippet(source_lines, line_num, 3),
                    recommendation=(
                        "Secure Code Execution:\n"
                        "1. NEVER use eval/exec on untrusted input\n"
                        "2. Use safe alternatives (json.loads, ast.literal_eval)\n"
                        "3. Validate and sanitize all external content\n"
                        "4. Use sandboxed execution environments"
                    ),
                    evidence=evidence
                ))

        return findings

    def calculate_confidence(self, evidence: Dict[str, Any]) -> float:
        """
        Calculate confidence based on evidence

        High confidence (0.8-1.0):
        - Direct pattern match (URLs, local paths)
        - Explicit unpinned versions

        Medium confidence (0.6-0.8):
        - Missing verification (could be elsewhere)
        - Vulnerable library usage

        Low confidence (0.4-0.6):
        - Heuristic-based detection
        """
        confidence = 0.7  # Base confidence

        # High confidence for direct matches
        if evidence.get('pattern_type') in ['arbitrary_url', 'dynamic_model']:
            confidence = 0.9

        # Medium-high for unpinned models
        if evidence.get('has_pinning') is False:
            confidence = 0.75

        # Medium for missing verification
        if evidence.get('has_verification') is False:
            confidence = 0.65

        # High for vulnerable libraries
        if evidence.get('vulnerability'):
            confidence = 0.85

        return min(confidence, 1.0)

    def _is_model_identifier(self, model_arg: str) -> bool:
        """Check if argument looks like a model identifier"""
        # Simple heuristic: contains model names or patterns
        model_patterns = ['gpt', 'claude', 'llama', 'bert', 'model']
        return any(pattern in model_arg.lower() for pattern in model_patterns)

    def _check_verification_nearby(
        self,
        line_num: int,
        source_lines: List[str],
        window: int = 10
    ) -> bool:
        """Check if verification patterns exist within a window of lines"""
        start = max(0, line_num - window)
        end = min(len(source_lines), line_num + window)

        nearby_code = ' '.join(source_lines[start:end]).lower()

        return any(
            any(pattern in nearby_code for pattern in patterns)
            for patterns in self.VERIFICATION_PATTERNS.values()
        )

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
