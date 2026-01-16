"""
Feature Extractor - Convert Python AST to ML feature vectors.

Extracts 45 features from parsed Python code for prompt injection detection.
Features are designed to capture patterns indicative of prompt injection vulnerabilities.

Feature Categories:
1. User Input Indicators (10 features)
2. LLM API Patterns (12 features)
3. String Operations (8 features)
4. Data Flow Indicators (10 features)
5. Mitigation Indicators (5 features)
"""

from dataclasses import dataclass, field
from typing import Any, Dict, List
import numpy as np


# Feature names for interpretability
FEATURE_NAMES = [
    # User Input Indicators (0-9)
    "has_request_get",
    "has_input_call",
    "has_sys_argv",
    "has_environ_access",
    "user_input_var_count",
    "user_param_in_func_args",
    "has_form_data",
    "has_json_body",
    "has_query_params",
    "has_file_upload",

    # LLM API Patterns (10-21)
    "llm_call_count",
    "has_openai_import",
    "has_anthropic_import",
    "has_langchain_import",
    "uses_chat_completion",
    "uses_messages_api",
    "prompt_var_in_llm_call",
    "system_prompt_present",
    "has_streaming",
    "uses_function_calling",
    "has_multiple_llm_calls",
    "llm_in_loop",

    # String Operations (22-29)
    "fstring_count",
    "format_call_count",
    "concat_count",
    "string_in_llm_arg",
    "user_var_in_fstring",
    "template_literal_count",
    "raw_string_in_prompt",
    "multiline_string_count",

    # Data Flow Indicators (30-39)
    "direct_user_to_llm",
    "single_hop_user_to_llm",
    "two_hop_user_to_llm",
    "function_returns_user_data",
    "cross_function_flow",
    "assignment_chain_length_max",
    "variable_reuse_count",
    "llm_output_to_sink",
    "data_transformation_count",
    "loop_with_user_data",

    # Mitigation Indicators (40-44)
    "has_input_validation",
    "has_sanitization",
    "has_prompt_template",
    "has_allowlist_check",
    "uses_structured_output",
]

# Patterns for feature detection
USER_INPUT_PATTERNS = {
    'request_get': {'request.get', 'request.args', 'request.values'},
    'input_call': {'input(', 'raw_input('},
    'sys_argv': {'sys.argv', 'argparse'},
    'environ': {'os.environ', 'os.getenv', 'environ.get'},
    'form_data': {'request.form', 'request.files', 'form.data'},
    'json_body': {'request.json', 'request.get_json', '.json()'},
    'query_params': {'request.query_params', 'query_params', 'QueryParams'},
    'file_upload': {'UploadFile', 'FileStorage', 'request.files'},
}

USER_INPUT_PARAM_NAMES = {
    'user_input', 'query', 'message', 'prompt', 'text', 'content',
    'input', 'data', 'body', 'request', 'user_message', 'question',
    'user_query', 'user_text', 'user_prompt', 'payload', 'cmd',
}

LLM_IMPORT_PATTERNS = {
    'openai': {'openai', 'OpenAI'},
    'anthropic': {'anthropic', 'Anthropic'},
    'langchain': {'langchain', 'LangChain', 'ChatOpenAI', 'ChatAnthropic'},
}

LLM_CALL_PATTERNS = {
    'chat_completion': {
        'chat.completions.create', 'ChatCompletion.create',
        'client.chat.completions.create',
    },
    'messages_api': {
        'messages.create', 'client.messages.create',
    },
    'streaming': {'stream=True', 'streaming=True'},
    'function_calling': {'functions=', 'tools=', 'tool_choice='},
}

MITIGATION_PATTERNS = {
    'validation': {
        'validate', 'validator', 'pydantic', 'jsonschema',
        'isinstance(', 'type_check',
    },
    'sanitization': {
        'sanitize', 'escape', 'clean', 'strip', 'bleach',
        'html.escape', 'shlex.quote',
    },
    'prompt_template': {
        'PromptTemplate', 'ChatPromptTemplate', 'SystemMessage',
        'HumanMessage', 'template.format',
    },
    'allowlist': {
        'allowlist', 'whitelist', 'allowed_', 'permitted_',
    },
    'structured_output': {
        'response_format', 'json_schema', 'Pydantic', 'BaseModel',
        'structured_output',
    },
}


@dataclass
class CodeFeatures:
    """Container for extracted code features."""
    features: np.ndarray = field(default_factory=lambda: np.zeros(45, dtype=np.float32))
    feature_names: List[str] = field(default_factory=lambda: FEATURE_NAMES.copy())
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, float]:
        """Convert to dictionary of feature name -> value."""
        return {name: float(val) for name, val in zip(self.feature_names, self.features)}

    def get_top_features(self, n: int = 10) -> List[tuple]:
        """Get top N features by absolute value."""
        indexed = list(enumerate(self.features))
        sorted_features = sorted(indexed, key=lambda x: abs(x[1]), reverse=True)
        return [(self.feature_names[i], float(v)) for i, v in sorted_features[:n]]


class FeatureExtractor:
    """
    Extract ML features from parsed Python code.

    Converts parsed_data from PythonASTParser into a fixed-size feature vector
    suitable for ML model inference.
    """

    def __init__(self):
        self.feature_names = FEATURE_NAMES

    def extract(self, parsed_data: Dict[str, Any]) -> CodeFeatures:
        """
        Extract all features from parsed code.

        Args:
            parsed_data: Output from PythonASTParser.parse()

        Returns:
            CodeFeatures containing 45-dimensional feature vector
        """
        features = np.zeros(45, dtype=np.float32)

        # Extract feature groups
        features[0:10] = self._extract_user_input_features(parsed_data)
        features[10:22] = self._extract_llm_features(parsed_data)
        features[22:30] = self._extract_string_features(parsed_data)
        features[30:40] = self._extract_flow_features(parsed_data)
        features[40:45] = self._extract_mitigation_features(parsed_data)

        return CodeFeatures(
            features=features,
            feature_names=FEATURE_NAMES.copy(),
            metadata={
                'file_path': parsed_data.get('file_path', ''),
                'function_count': len(parsed_data.get('functions', [])),
                'llm_call_count': len(parsed_data.get('llm_api_calls', [])),
            }
        )

    def _extract_user_input_features(self, parsed_data: Dict[str, Any]) -> np.ndarray:
        """Extract user input indicator features (10 features)."""
        features = np.zeros(10, dtype=np.float32)

        source_code = '\n'.join(parsed_data.get('source_lines', [])).lower()
        imports = [imp.get('module', '').lower() for imp in parsed_data.get('imports', [])]
        imports_str = ' '.join(imports)

        # Feature 0: has_request_get
        features[0] = float(any(p in source_code for p in USER_INPUT_PATTERNS['request_get']))

        # Feature 1: has_input_call
        features[1] = float(any(p in source_code for p in USER_INPUT_PATTERNS['input_call']))

        # Feature 2: has_sys_argv
        features[2] = float(any(p in source_code for p in USER_INPUT_PATTERNS['sys_argv']))

        # Feature 3: has_environ_access
        features[3] = float(any(p in source_code for p in USER_INPUT_PATTERNS['environ']))

        # Feature 4: user_input_var_count
        user_input_count = 0
        for assignment in parsed_data.get('assignments', []):
            target = str(assignment.get('target', '')).lower()
            if any(name in target for name in USER_INPUT_PARAM_NAMES):
                user_input_count += 1
        features[4] = min(user_input_count, 10) / 10.0  # Normalize

        # Feature 5: user_param_in_func_args
        param_count = 0
        for func in parsed_data.get('functions', []):
            for arg in func.get('args', []):
                arg_name = arg if isinstance(arg, str) else arg.get('name', '')
                if arg_name.lower() in USER_INPUT_PARAM_NAMES:
                    param_count += 1
        features[5] = min(param_count, 5) / 5.0  # Normalize

        # Feature 6: has_form_data
        features[6] = float(any(p in source_code for p in USER_INPUT_PATTERNS['form_data']))

        # Feature 7: has_json_body
        features[7] = float(any(p in source_code for p in USER_INPUT_PATTERNS['json_body']))

        # Feature 8: has_query_params
        features[8] = float(any(p in source_code for p in USER_INPUT_PATTERNS['query_params']))

        # Feature 9: has_file_upload
        features[9] = float(any(p in source_code for p in USER_INPUT_PATTERNS['file_upload']))

        return features

    def _extract_llm_features(self, parsed_data: Dict[str, Any]) -> np.ndarray:
        """Extract LLM API pattern features (12 features)."""
        features = np.zeros(12, dtype=np.float32)

        source_code = '\n'.join(parsed_data.get('source_lines', [])).lower()
        imports = parsed_data.get('imports', [])
        imports_str = ' '.join([imp.get('module', '').lower() for imp in imports])
        llm_calls = parsed_data.get('llm_api_calls', [])

        # Feature 0: llm_call_count (normalized)
        features[0] = min(len(llm_calls), 10) / 10.0

        # Feature 1: has_openai_import
        features[1] = float(any(p.lower() in imports_str for p in LLM_IMPORT_PATTERNS['openai']))

        # Feature 2: has_anthropic_import
        features[2] = float(any(p.lower() in imports_str for p in LLM_IMPORT_PATTERNS['anthropic']))

        # Feature 3: has_langchain_import
        features[3] = float(any(p.lower() in imports_str for p in LLM_IMPORT_PATTERNS['langchain']))

        # Feature 4: uses_chat_completion
        features[4] = float(any(p in source_code for p in LLM_CALL_PATTERNS['chat_completion']))

        # Feature 5: uses_messages_api
        features[5] = float(any(p in source_code for p in LLM_CALL_PATTERNS['messages_api']))

        # Feature 6: prompt_var_in_llm_call
        # Check if variables with prompt-like names are used in LLM calls
        prompt_in_call = False
        for call in llm_calls:
            call_str = str(call).lower()
            if any(name in call_str for name in ['prompt', 'message', 'query', 'input']):
                prompt_in_call = True
                break
        features[6] = float(prompt_in_call)

        # Feature 7: system_prompt_present
        features[7] = float('system' in source_code and ('prompt' in source_code or 'message' in source_code))

        # Feature 8: has_streaming
        features[8] = float(any(p in source_code for p in LLM_CALL_PATTERNS['streaming']))

        # Feature 9: uses_function_calling
        features[9] = float(any(p in source_code for p in LLM_CALL_PATTERNS['function_calling']))

        # Feature 10: has_multiple_llm_calls
        features[10] = float(len(llm_calls) > 1)

        # Feature 11: llm_in_loop
        # Heuristic: check for LLM calls inside for/while loops
        llm_in_loop = False
        for func in parsed_data.get('functions', []):
            func_source = str(func).lower()
            if ('for ' in func_source or 'while ' in func_source) and any(
                p in func_source for p in ['openai', 'anthropic', 'llm', 'chat', 'completion']
            ):
                llm_in_loop = True
                break
        features[11] = float(llm_in_loop)

        return features

    def _extract_string_features(self, parsed_data: Dict[str, Any]) -> np.ndarray:
        """Extract string operation features (8 features)."""
        features = np.zeros(8, dtype=np.float32)

        source_code = '\n'.join(parsed_data.get('source_lines', []))
        string_ops = parsed_data.get('string_operations', [])

        # Feature 0: fstring_count (normalized)
        fstring_count = sum(1 for op in string_ops if op.get('type') == 'f-string')
        fstring_count += source_code.count('f"') + source_code.count("f'")
        features[0] = min(fstring_count, 20) / 20.0

        # Feature 1: format_call_count (normalized)
        format_count = source_code.lower().count('.format(')
        features[1] = min(format_count, 10) / 10.0

        # Feature 2: concat_count (normalized)
        concat_count = sum(1 for op in string_ops if op.get('type') == 'concatenation')
        features[2] = min(concat_count, 10) / 10.0

        # Feature 3: string_in_llm_arg
        # Check if string operations appear near LLM calls
        llm_calls = parsed_data.get('llm_api_calls', [])
        string_near_llm = False
        for call in llm_calls:
            call_line = call.get('line', 0)
            for op in string_ops:
                if abs(op.get('line', 0) - call_line) <= 5:
                    string_near_llm = True
                    break
        features[3] = float(string_near_llm)

        # Feature 4: user_var_in_fstring
        # Check if user input variable names appear in f-strings
        user_in_fstring = False
        for op in string_ops:
            if op.get('type') == 'f-string':
                op_content = str(op.get('content', '')).lower()
                if any(name in op_content for name in USER_INPUT_PARAM_NAMES):
                    user_in_fstring = True
                    break
        features[4] = float(user_in_fstring)

        # Feature 5: template_literal_count
        template_count = source_code.count('"""') + source_code.count("'''")
        features[5] = min(template_count, 10) / 10.0

        # Feature 6: raw_string_in_prompt
        # Check for raw strings near prompt-related code
        has_raw_prompt = False
        lines = parsed_data.get('source_lines', [])
        for i, line in enumerate(lines):
            if 'prompt' in line.lower() and ('r"' in line or "r'" in line):
                has_raw_prompt = True
                break
        features[6] = float(has_raw_prompt)

        # Feature 7: multiline_string_count
        multiline_count = source_code.count('"""') // 2 + source_code.count("'''") // 2
        features[7] = min(multiline_count, 5) / 5.0

        return features

    def _extract_flow_features(self, parsed_data: Dict[str, Any]) -> np.ndarray:
        """Extract data flow indicator features (10 features)."""
        features = np.zeros(10, dtype=np.float32)

        source_code = '\n'.join(parsed_data.get('source_lines', [])).lower()
        assignments = parsed_data.get('assignments', [])
        functions = parsed_data.get('functions', [])
        llm_calls = parsed_data.get('llm_api_calls', [])
        structured_calls = parsed_data.get('structured_calls', [])

        # Build simple variable dependency tracking
        user_vars = set()
        llm_output_vars = set()

        for assignment in assignments:
            target = str(assignment.get('target', '')).lower()
            value = str(assignment.get('value', '')).lower()

            # Track user input variables
            if any(p in value for p in ['request', 'input(', 'argv', 'environ']):
                user_vars.add(target)

            # Track LLM output variables
            if any(p in value for p in ['openai', 'anthropic', 'llm', 'completion', 'message']):
                llm_output_vars.add(target)

        # Feature 0: direct_user_to_llm
        direct_flow = False
        for call in llm_calls:
            call_str = str(call).lower()
            if any(var in call_str for var in user_vars):
                direct_flow = True
                break
        features[0] = float(direct_flow)

        # Feature 1: single_hop_user_to_llm (user -> var -> llm)
        single_hop = False
        for assignment in assignments:
            value_vars = assignment.get('value_vars', [])
            target = str(assignment.get('target', '')).lower()
            if any(v.lower() in user_vars for v in value_vars if isinstance(v, str)):
                # Check if target is used in LLM call
                for call in llm_calls:
                    if target in str(call).lower():
                        single_hop = True
                        break
        features[1] = float(single_hop)

        # Feature 2: two_hop_user_to_llm
        features[2] = float(features[0] > 0 or features[1] > 0)  # Approximation

        # Feature 3: function_returns_user_data
        returns_user = False
        for func in functions:
            func_str = str(func).lower()
            if 'return' in func_str and any(var in func_str for var in user_vars):
                returns_user = True
                break
        features[3] = float(returns_user)

        # Feature 4: cross_function_flow
        cross_func = len(functions) > 1 and (features[0] > 0 or features[1] > 0)
        features[4] = float(cross_func)

        # Feature 5: assignment_chain_length_max (normalized)
        # Simple heuristic: count assignments that reference other assigned vars
        chain_length = 0
        assigned_vars = {str(a.get('target', '')).lower() for a in assignments}
        for assignment in assignments:
            value_vars = assignment.get('value_vars', [])
            refs = sum(1 for v in value_vars if str(v).lower() in assigned_vars)
            chain_length = max(chain_length, refs)
        features[5] = min(chain_length, 5) / 5.0

        # Feature 6: variable_reuse_count (normalized)
        var_counts = {}
        for assignment in assignments:
            target = str(assignment.get('target', '')).lower()
            var_counts[target] = var_counts.get(target, 0) + 1
        max_reuse = max(var_counts.values()) if var_counts else 0
        features[6] = min(max_reuse, 5) / 5.0

        # Feature 7: llm_output_to_sink
        llm_to_sink = False
        dangerous_patterns = ['exec', 'eval', 'subprocess', 'os.system', 'execute']
        for call in structured_calls:
            call_str = str(call).lower()
            if any(p in call_str for p in dangerous_patterns):
                if any(var in call_str for var in llm_output_vars):
                    llm_to_sink = True
                    break
        features[7] = float(llm_to_sink)

        # Feature 8: data_transformation_count (normalized)
        transform_patterns = ['strip', 'lower', 'upper', 'replace', 'split', 'join']
        transform_count = sum(source_code.count(p) for p in transform_patterns)
        features[8] = min(transform_count, 20) / 20.0

        # Feature 9: loop_with_user_data
        loop_with_data = False
        if 'for ' in source_code or 'while ' in source_code:
            if any(var in source_code for var in user_vars):
                loop_with_data = True
        features[9] = float(loop_with_data)

        return features

    def _extract_mitigation_features(self, parsed_data: Dict[str, Any]) -> np.ndarray:
        """Extract mitigation indicator features (5 features)."""
        features = np.zeros(5, dtype=np.float32)

        source_code = '\n'.join(parsed_data.get('source_lines', [])).lower()

        # Feature 0: has_input_validation
        features[0] = float(any(p in source_code for p in MITIGATION_PATTERNS['validation']))

        # Feature 1: has_sanitization
        features[1] = float(any(p in source_code for p in MITIGATION_PATTERNS['sanitization']))

        # Feature 2: has_prompt_template
        features[2] = float(any(p.lower() in source_code for p in MITIGATION_PATTERNS['prompt_template']))

        # Feature 3: has_allowlist_check
        features[3] = float(any(p in source_code for p in MITIGATION_PATTERNS['allowlist']))

        # Feature 4: uses_structured_output
        features[4] = float(any(p.lower() in source_code for p in MITIGATION_PATTERNS['structured_output']))

        return features
