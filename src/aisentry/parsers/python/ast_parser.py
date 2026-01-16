"""Python AST parser - extracts structure from Python source code"""

import ast
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional

# Handle ast.unparse for Python 3.8 compatibility
try:
    from ast import unparse
except ImportError:
    from astunparse import unparse  # type: ignore

logger = logging.getLogger(__name__)


class PythonASTParser:
    """
    Parse Python files using AST (Abstract Syntax Tree)

    Extracts:
    - Imports and dependencies
    - Function definitions
    - Class definitions
    - Variable assignments
    - String operations (f-strings, concatenation)
    - LLM API calls
    """

    # Known LLM libraries for import tracking
    LLM_LIBRARIES = {
        'openai', 'anthropic', 'langchain', 'langchain_core', 'langchain_openai',
        'langchain_anthropic', 'langchain_community', 'llama_index', 'ollama',
        'vllm', 'together', 'mistralai', 'groq', 'cohere', 'replicate',
        'transformers', 'vertexai', 'google.generativeai', 'bedrock', 'boto3',
        'azure.ai', 'litellm', 'guidance', 'dspy', 'semantic_kernel',
    }

    # LLM library patterns to detect - SPECIFIC patterns only (no generic ones)
    LLM_PATTERNS = [
        # OpenAI - specific API calls
        'openai.chat.completions.create',
        'openai.completions.create',
        'client.chat.completions.create',
        'client.completions.create',
        'OpenAI(',
        'ChatOpenAI(',
        'AsyncOpenAI(',
        # Anthropic - specific API calls
        'anthropic.messages.create',
        'client.messages.create',
        'Anthropic(',
        'ChatAnthropic(',
        'AsyncAnthropic(',
        # LangChain - specific classes/methods
        'langchain',
        'llama_index',
        '.invoke',            # LangChain invoke method
        '.ainvoke',           # LangChain async invoke
        '.stream',            # LangChain streaming (not http stream)
        '.astream',           # LangChain async streaming
        'ChatVertexAI(',
        'ChatBedrock(',
        'ChatOllama(',
        # Ollama - specific patterns
        'ollama.chat',
        'ollama.generate',
        'Ollama(',
        'localhost:11434',    # Default Ollama port
        'api/generate',       # Ollama API endpoint
        'api/chat',           # Ollama chat endpoint
        # vLLM - specific classes
        'vllm.LLM(',
        'SamplingParams(',
        # Together AI
        'together.Complete',
        'Together(',
        # Mistral
        'mistralai.chat',
        'Mistral(',
        # Groq
        'groq.chat',
        'Groq(',
        # Cohere
        'cohere.generate',
        'cohere.chat',
        'Cohere(',
        # Replicate
        'replicate.run',
        'Replicate(',
        # Hugging Face - specific classes
        'AutoModelForCausalLM',
        'InferenceClient(',
        # AWS Bedrock - specific
        'invoke_model',
        'bedrock-runtime',
        # Google Vertex AI - specific
        'GenerativeModel(',
        'generate_content',
        'vertexai.generative_models',
        # Azure OpenAI
        'AzureOpenAI(',
        # LiteLLM
        'litellm.completion',
        'litellm.acompletion',
        # Fine-tuning API patterns
        '.fine_tuning.jobs.create',
        'FineTuningJob(',
    ]

    # Patterns that should NOT be considered LLM calls (exclusions)
    NON_LLM_PATTERNS = {
        # Django/SQLAlchemy ORM
        'models.', 'Model.', '.objects.', '.query(', '.filter(', '.save(', '.delete(',
        'session.query', 'Session(',
        # HTTP libraries (generic responses, not LLM)
        'requests.get', 'requests.post', 'httpx.get', 'httpx.post',
        'aiohttp.ClientSession', 'urllib.',
        # Standard library
        'subprocess.', 'os.path', 'sys.', 'pathlib.',
        'json.', 'pickle.', 're.', 'datetime.',
        # ML (non-LLM) - sklearn, torch, tensorflow
        'sklearn.', 'torch.nn', 'tensorflow.', 'keras.',
        'numpy.', 'pandas.', 'scipy.',
        # Database
        'sqlite3.', 'psycopg2.', 'mysql.', 'pymongo.',
        # Common false positive methods
        '.to_dict(', '.to_json(', '.serialize(', '.validate(',
    }

    def __init__(self, file_path: str):
        """
        Initialize parser

        Args:
            file_path: Path to Python file to parse
        """
        self.file_path = Path(file_path)
        self.source_code: Optional[str] = None
        self.tree: Optional[ast.Module] = None

    def parse(self) -> Dict[str, Any]:
        """
        Parse Python file and extract relevant information

        Returns:
            Dictionary with parsed data structure

        Raises:
            FileNotFoundError: If file doesn't exist
            SyntaxError: If Python syntax is invalid
        """
        # Read source code
        try:
            with open(self.file_path, 'r', encoding='utf-8') as f:
                self.source_code = f.read()
        except FileNotFoundError:
            logger.error(f"File not found: {self.file_path}")
            return {'error': 'File not found', 'parsable': False}

        # Parse to AST
        try:
            self.tree = ast.parse(self.source_code, filename=str(self.file_path))
        except SyntaxError as e:
            logger.warning(f"Syntax error in {self.file_path}: {e}")
            return {
                'error': str(e),
                'parsable': False,
                'file_path': str(self.file_path)
            }

        # Extract all information
        return {
            'file_path': str(self.file_path),
            'parsable': True,
            'imports': self._extract_imports(),
            'functions': self._extract_functions(),
            'classes': self._extract_classes(),
            'assignments': self._extract_assignments(),
            'string_operations': self._extract_string_operations(),
            'llm_api_calls': self._extract_llm_calls(),
            'source_lines': self.source_code.splitlines(),
            # Enhanced structured data for evidence-based scoring
            'structured_calls': self._extract_structured_calls(),
            'decorators': self._extract_decorators(),
            'config_assignments': self._extract_config_assignments(),
            'instantiations': self._extract_instantiations(),
        }

    def _extract_imports(self) -> List[Dict[str, Any]]:
        """Extract all imports"""
        imports = []

        for node in ast.walk(self.tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    imports.append({
                        'type': 'import',
                        'module': alias.name,
                        'alias': alias.asname,
                        'line': node.lineno
                    })
            elif isinstance(node, ast.ImportFrom):
                imports.append({
                    'type': 'from_import',
                    'module': node.module or '',  # Can be None for relative imports
                    'names': [n.name for n in node.names],
                    'line': node.lineno
                })

        return imports

    def _extract_llm_imports(self) -> Dict[str, str]:
        """
        Extract imports from known LLM libraries.

        Returns:
            Dict mapping local name -> library module
            e.g., {'client': 'openai', 'Claude': 'anthropic', 'ChatOpenAI': 'langchain_openai'}
        """
        llm_imports: Dict[str, str] = {}

        for node in ast.walk(self.tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    module = alias.name
                    local_name = alias.asname or alias.name
                    # Check if this is an LLM library
                    base_module = module.split('.')[0]
                    if base_module in self.LLM_LIBRARIES or module in self.LLM_LIBRARIES:
                        llm_imports[local_name] = module

            elif isinstance(node, ast.ImportFrom):
                module = node.module or ''
                base_module = module.split('.')[0]
                is_llm_module = base_module in self.LLM_LIBRARIES or module in self.LLM_LIBRARIES

                if is_llm_module:
                    for alias in node.names:
                        local_name = alias.asname or alias.name
                        llm_imports[local_name] = f"{module}.{alias.name}"

        return llm_imports

    def _is_confirmed_llm_call(self, call_str: str, llm_imports: Dict[str, str]) -> bool:
        """
        Check if a call is confirmed to be an LLM API call.

        Args:
            call_str: The unparsed call string (e.g., 'client.chat.completions.create')
            llm_imports: Dict of local names to LLM library modules

        Returns:
            True if the call is confirmed to be from an LLM library
        """
        # First check exclusions - if it matches an exclusion pattern, reject it
        for excl in self.NON_LLM_PATTERNS:
            if excl in call_str:
                return False

        # Check if call matches a specific LLM pattern
        if any(pattern in call_str for pattern in self.LLM_PATTERNS):
            return True

        # Check if the call's base object is from an LLM import
        # e.g., if 'client' is imported from openai, then client.chat.completions.create is LLM
        call_parts = call_str.split('.')
        if call_parts:
            base_name = call_parts[0]
            if base_name in llm_imports:
                return True

        return False

    def _extract_functions(self) -> List[Dict[str, Any]]:
        """Extract function definitions"""
        functions = []

        for node in ast.walk(self.tree):
            if isinstance(node, ast.FunctionDef):
                functions.append({
                    'name': node.name,
                    'args': [arg.arg for arg in node.args.args],
                    'decorators': [self._unparse_safe(d) for d in node.decorator_list],
                    'line': node.lineno,
                    'end_line': node.end_lineno if hasattr(node, 'end_lineno') else None,
                })

        return functions

    def _extract_classes(self) -> List[Dict[str, Any]]:
        """Extract class definitions"""
        classes = []

        for node in ast.walk(self.tree):
            if isinstance(node, ast.ClassDef):
                classes.append({
                    'name': node.name,
                    'bases': [self._unparse_safe(b) for b in node.bases],
                    'decorators': [self._unparse_safe(d) for d in node.decorator_list],
                    'line': node.lineno,
                })

        return classes

    def _extract_assignments(self) -> List[Dict[str, Any]]:
        """Extract variable assignments with referenced variables"""
        assignments = []

        for node in ast.walk(self.tree):
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        value_str = self._unparse_safe(node.value)
                        # Extract variables referenced in the value
                        value_vars = self._extract_names_from_node(node.value)
                        assignments.append({
                            'name': target.id,
                            'value': value_str,
                            'line': node.lineno,
                            'value_vars': value_vars,
                        })

        return assignments

    def _extract_names_from_node(self, node: ast.AST) -> List[str]:
        """Extract all variable names referenced in an AST node"""
        names = []
        for child in ast.walk(node):
            if isinstance(child, ast.Name):
                names.append(child.id)
        return names

    # HTTP client patterns that might call LLM APIs
    HTTP_CLIENT_PATTERNS = ['httpx.post', 'requests.post', 'aiohttp']

    # URL patterns for local/self-hosted LLMs
    LOCAL_LLM_URL_PATTERNS = [
        'localhost:11434',  # Ollama default
        '127.0.0.1:11434',
        'api/generate',     # Ollama generate endpoint
        'api/chat',         # Ollama chat endpoint
        '/v1/completions',  # OpenAI-compatible local
        '/v1/chat/completions',
    ]

    def _extract_llm_calls(self) -> List[Dict[str, Any]]:
        """
        Extract LLM API calls with import-aware validation.

        Detects calls to: openai, anthropic, langchain, ollama, etc.
        Also detects HTTP calls to local LLM endpoints.

        Uses import tracking to reduce false positives from generic patterns
        like model.generate() or response.content.
        """
        llm_calls = []

        # Get LLM imports for validation
        llm_imports = self._extract_llm_imports()

        # Build a map of call nodes to their assignment targets
        call_to_target = {}
        for node in ast.walk(self.tree):
            if isinstance(node, ast.Assign):
                if isinstance(node.value, ast.Call):
                    if node.targets and isinstance(node.targets[0], ast.Name):
                        call_to_target[id(node.value)] = node.targets[0].id

        for node in ast.walk(self.tree):
            if isinstance(node, ast.Call):
                call_str = self._unparse_safe(node.func)

                # Use import-aware validation to check if this is an LLM call
                is_llm_call = self._is_confirmed_llm_call(call_str, llm_imports)

                # Also check HTTP clients calling LLM endpoints (e.g., Ollama)
                if not is_llm_call and any(p in call_str for p in self.HTTP_CLIENT_PATTERNS):
                    # Check if URL argument contains LLM endpoint pattern
                    args_str = ' '.join(self._extract_call_args(node))
                    keywords_str = ' '.join(
                        self._unparse_safe(kw.value) for kw in node.keywords if kw.arg
                    )
                    full_args = args_str + ' ' + keywords_str
                    if any(p in full_args for p in self.LOCAL_LLM_URL_PATTERNS):
                        is_llm_call = True

                if is_llm_call:
                    llm_calls.append({
                        'function': call_str,
                        'line': node.lineno,
                        'args': self._extract_call_args(node),
                        'keywords': {
                            kw.arg: self._unparse_safe(kw.value)
                            for kw in node.keywords
                            if kw.arg is not None
                        },
                        'assignment_target': call_to_target.get(id(node)),
                        'confirmed_llm_library': llm_imports.get(call_str.split('.')[0], None)
                    })

        return llm_calls

    def _extract_call_args(self, call_node: ast.Call) -> List[str]:
        """Extract positional arguments from a call"""
        return [self._unparse_safe(arg) for arg in call_node.args]

    def _extract_string_operations(self) -> List[Dict[str, Any]]:
        """
        Extract f-strings, concatenations, format calls

        Critical for detecting prompt injection
        Enhanced to track assignment targets for taint analysis
        """
        string_ops = []

        # First pass: track assignments
        for node in ast.walk(self.tree):
            if isinstance(node, ast.Assign):
                # Check if the value is a string operation
                target_names = []
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        target_names.append(target.id)

                # Check what's being assigned
                if isinstance(node.value, ast.JoinedStr):  # f-string
                    string_ops.append({
                        'type': 'f-string',
                        'line': node.lineno,
                        'values': [self._unparse_safe(v) for v in node.value.values],
                        'target': target_names[0] if target_names else None
                    })
                elif isinstance(node.value, ast.BinOp) and isinstance(node.value.op, ast.Add):
                    # String concatenation
                    string_ops.append({
                        'type': 'concatenation',
                        'line': node.lineno,
                        'left': self._unparse_safe(node.value.left),
                        'right': self._unparse_safe(node.value.right),
                        'target': target_names[0] if target_names else None
                    })
                elif isinstance(node.value, ast.Call):
                    func_str = self._unparse_safe(node.value.func)
                    if '.format' in func_str:
                        string_ops.append({
                            'type': 'format_call',
                            'line': node.lineno,
                            'function': func_str,
                            'target': target_names[0] if target_names else None
                        })

        # Second pass: inline string operations (not assigned)
        for node in ast.walk(self.tree):
            if isinstance(node, ast.JoinedStr):
                # Check if this f-string is not already tracked via assignment
                already_tracked = any(
                    op['line'] == node.lineno and op['type'] == 'f-string'
                    for op in string_ops
                )
                if not already_tracked:
                    string_ops.append({
                        'type': 'f-string',
                        'line': node.lineno,
                        'values': [self._unparse_safe(v) for v in node.values],
                        'target': None  # Inline, no target
                    })
            elif isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
                already_tracked = any(
                    op['line'] == node.lineno and op['type'] == 'concatenation'
                    for op in string_ops
                )
                if not already_tracked:
                    string_ops.append({
                        'type': 'concatenation',
                        'line': node.lineno,
                        'left': self._unparse_safe(node.left),
                        'right': self._unparse_safe(node.right),
                        'target': None
                    })

        return string_ops

    def _unparse_safe(self, node: ast.AST) -> str:
        """
        Safely unparse an AST node to string

        Works on Python 3.8+ (uses astunparse backport if needed)
        """
        try:
            return unparse(node)
        except Exception as e:
            logger.debug(f"Failed to unparse node: {e}")
            return f"<{node.__class__.__name__}>"

    def get_source_lines(self, start_line: int, end_line: Optional[int] = None) -> str:
        """
        Get source code snippet

        Args:
            start_line: Starting line number (1-indexed)
            end_line: Ending line number (inclusive), defaults to start_line

        Returns:
            Source code snippet
        """
        if self.source_code is None:
            return ""

        lines = self.source_code.splitlines()
        if end_line is None:
            end_line = start_line

        # Convert to 0-indexed
        start_idx = max(0, start_line - 1)
        end_idx = min(len(lines), end_line)

        return '\n'.join(lines[start_idx:end_idx])

    def get_context_lines(
        self,
        line_number: int,
        before: int = 2,
        after: int = 2
    ) -> str:
        """
        Get code context around a line

        Args:
            line_number: Center line number
            before: Lines before
            after: Lines after

        Returns:
            Code snippet with context
        """
        start = max(1, line_number - before)
        end = line_number + after
        return self.get_source_lines(start, end)

    def _extract_structured_calls(self) -> List[Dict[str, Any]]:
        """
        Extract structured function/method calls with module and function names

        Returns calls as:
        {
            'module': 'boto3.client',  # Resolved module if possible
            'function': 'get_secret_value',
            'full_call': 'secretsmanager.get_secret_value',
            'line': 42,
            'arguments': [...],
            'keywords': {...},
            'assignment_target': 'result'  # Variable receiving return value
        }
        """
        calls = []

        # Build import mapping for name resolution
        import_map = {}
        for imp in self._extract_imports():
            if imp['type'] == 'import':
                alias = imp.get('alias') or imp['module']
                import_map[alias] = imp['module']
            elif imp['type'] == 'from_import':
                for name in imp['names']:
                    import_map[name] = f"{imp['module']}.{name}"

        # Build a map of call nodes to their assignment targets
        call_to_target = {}
        for node in ast.walk(self.tree):
            if isinstance(node, ast.Assign):
                if isinstance(node.value, ast.Call):
                    if node.targets and isinstance(node.targets[0], ast.Name):
                        call_to_target[id(node.value)] = node.targets[0].id

        for node in ast.walk(self.tree):
            if isinstance(node, ast.Call):
                func_info = self._resolve_call_target(node.func, import_map)
                if func_info:
                    calls.append({
                        'module': func_info['module'],
                        'function': func_info['function'],
                        'full_call': func_info['full_call'],
                        'line': node.lineno,
                        'arguments': [self._unparse_safe(arg) for arg in node.args],
                        'keywords': {
                            kw.arg: self._unparse_safe(kw.value)
                            for kw in node.keywords
                            if kw.arg is not None
                        },
                        'assignment_target': call_to_target.get(id(node))
                    })

        return calls

    def _resolve_call_target(self, func_node: ast.AST, import_map: Dict[str, str]) -> Optional[Dict[str, str]]:
        """
        Resolve a call target to module.function format

        Args:
            func_node: AST node representing the function being called
            import_map: Mapping of aliases to actual module names

        Returns:
            Dict with module, function, and full_call, or None if unresolvable
        """
        if isinstance(func_node, ast.Name):
            # Simple function call: func()
            func_name = func_node.id
            module = import_map.get(func_name, '')
            return {
                'module': module,
                'function': func_name,
                'full_call': f"{module}.{func_name}" if module else func_name
            }
        elif isinstance(func_node, ast.Attribute):
            # Method call: obj.method() or module.function()
            parts = []
            current = func_node

            # Walk the attribute chain backwards
            while isinstance(current, ast.Attribute):
                parts.append(current.attr)
                current = current.value

            if isinstance(current, ast.Name):
                parts.append(current.id)

            parts.reverse()

            # Resolve the base name
            base_name = parts[0] if parts else ''
            resolved_base = import_map.get(base_name, base_name)

            # Reconstruct the full path
            if len(parts) > 1:
                function = parts[-1]
                module_parts = [resolved_base] + parts[1:-1]
                module = '.'.join(p for p in module_parts if p)
                full_call = '.'.join(parts) if not resolved_base else f"{resolved_base}.{'.'.join(parts[1:])}"

                return {
                    'module': module,
                    'function': function,
                    'full_call': full_call
                }

        return None

    def _extract_decorators(self) -> List[Dict[str, Any]]:
        """
        Extract all decorators with their targets and arguments

        Returns:
        [{
            'decorator': '@limiter.limit',
            'decorator_name': 'limit',
            'decorator_module': 'limiter',
            'target_type': 'function',
            'target_name': 'api_endpoint',
            'arguments': ['100/hour'],
            'line': 42
        }, ...]
        """
        decorators = []

        for node in ast.walk(self.tree):
            if isinstance(node, (ast.FunctionDef, ast.ClassDef)):
                for decorator in node.decorator_list:
                    decorator_info = {
                        'decorator': self._unparse_safe(decorator),
                        'target_type': 'function' if isinstance(node, ast.FunctionDef) else 'class',
                        'target_name': node.name,
                        'line': decorator.lineno if hasattr(decorator, 'lineno') else node.lineno
                    }

                    # Extract decorator name and module
                    if isinstance(decorator, ast.Name):
                        decorator_info['decorator_name'] = decorator.id
                        decorator_info['decorator_module'] = ''
                    elif isinstance(decorator, ast.Attribute):
                        decorator_info['decorator_name'] = decorator.attr
                        if isinstance(decorator.value, ast.Name):
                            decorator_info['decorator_module'] = decorator.value.id
                        else:
                            decorator_info['decorator_module'] = self._unparse_safe(decorator.value)
                    elif isinstance(decorator, ast.Call):
                        # Decorator with arguments: @decorator(args)
                        if isinstance(decorator.func, ast.Name):
                            decorator_info['decorator_name'] = decorator.func.id
                            decorator_info['decorator_module'] = ''
                        elif isinstance(decorator.func, ast.Attribute):
                            decorator_info['decorator_name'] = decorator.func.attr
                            if isinstance(decorator.func.value, ast.Name):
                                decorator_info['decorator_module'] = decorator.func.value.id

                        decorator_info['arguments'] = [self._unparse_safe(arg) for arg in decorator.args]
                        decorator_info['keywords'] = {
                            kw.arg: self._unparse_safe(kw.value)
                            for kw in decorator.keywords
                            if kw.arg
                        }

                    decorators.append(decorator_info)

        return decorators

    def _extract_config_assignments(self) -> List[Dict[str, Any]]:
        """
        Extract configuration assignments (settings, dict literals, etc.)

        Focuses on security-relevant configs like:
        - settings['API_KEY'] = os.getenv(...)
        - config = {'api_key': '...'}
        - llm = ChatOpenAI(api_key=...)
        """
        config_assignments = []

        for node in ast.walk(self.tree):
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    assignment_info = {
                        'line': node.lineno,
                        'value': self._unparse_safe(node.value)
                    }

                    # Dict/Subscript assignment: settings['KEY'] = value
                    if isinstance(target, ast.Subscript):
                        if isinstance(target.value, ast.Name):
                            assignment_info['target_type'] = 'subscript'
                            assignment_info['target_name'] = target.value.id
                            assignment_info['key'] = self._unparse_safe(target.slice)
                            config_assignments.append(assignment_info)

                    # Simple assignment: api_key = value
                    elif isinstance(target, ast.Name):
                        # Check if value is a config-like object (dict, call with api_key, etc.)
                        if isinstance(node.value, ast.Dict):
                            assignment_info['target_type'] = 'dict'
                            assignment_info['target_name'] = target.id
                            assignment_info['dict_keys'] = [self._unparse_safe(k) for k in node.value.keys if k]
                            config_assignments.append(assignment_info)
                        elif isinstance(node.value, ast.Call):
                            # Check if call has security-relevant keyword args
                            security_keywords = {'api_key', 'secret', 'password', 'token', 'credentials'}
                            has_security_kwarg = any(
                                kw.arg and kw.arg.lower() in security_keywords
                                for kw in node.value.keywords
                            )
                            if has_security_kwarg:
                                assignment_info['target_type'] = 'call_with_secrets'
                                assignment_info['target_name'] = target.id
                                assignment_info['call_func'] = self._unparse_safe(node.value.func)
                                config_assignments.append(assignment_info)

        return config_assignments

    def _extract_instantiations(self) -> List[Dict[str, Any]]:
        """
        Extract class instantiations to detect security library usage

        Tracks patterns like:
        - vault_client = hvac.Client(url=...)
        - limiter = Limiter(app, key_func=...)
        - analyzer = AnalyzerEngine()
        """
        instantiations = []

        for node in ast.walk(self.tree):
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name) and isinstance(node.value, ast.Call):
                        # Extract class being instantiated
                        class_info = {
                            'variable_name': target.id,
                            'line': node.lineno,
                            'arguments': [self._unparse_safe(arg) for arg in node.value.args],
                            'keywords': {
                                kw.arg: self._unparse_safe(kw.value)
                                for kw in node.value.keywords
                                if kw.arg
                            }
                        }

                        # Resolve class name
                        if isinstance(node.value.func, ast.Name):
                            class_info['class_name'] = node.value.func.id
                            class_info['module'] = ''
                        elif isinstance(node.value.func, ast.Attribute):
                            class_info['class_name'] = node.value.func.attr
                            if isinstance(node.value.func.value, ast.Name):
                                class_info['module'] = node.value.func.value.id
                            else:
                                class_info['module'] = self._unparse_safe(node.value.func.value)

                        instantiations.append(class_info)

        return instantiations
