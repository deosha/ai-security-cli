"""
AST Utility Functions for Static Analysis

Provides helper functions for AST-based taint tracking and analysis.
"""

import ast
from typing import Set, List, Dict, Any, Optional, Tuple


def names_in_expr(node: ast.AST) -> Set[str]:
    """
    Extract all variable names referenced in an AST expression.

    Walks the AST and collects all Name.id values, including those
    inside f-strings (JoinedStr), binary operations, and calls.

    Args:
        node: Any AST node

    Returns:
        Set of variable names referenced in the expression

    Examples:
        >>> names_in_expr(ast.parse("x + y").body[0].value)
        {'x', 'y'}
        >>> names_in_expr(ast.parse("f'{user_input}'").body[0].value)
        {'user_input'}
    """
    names = set()

    for child in ast.walk(node):
        if isinstance(child, ast.Name):
            names.add(child.id)

    return names


def names_in_fstring(node: ast.JoinedStr) -> Set[str]:
    """
    Extract variable names specifically from an f-string.

    F-strings have their interpolated values in .values as FormattedValue nodes.

    Args:
        node: JoinedStr AST node (f-string)

    Returns:
        Set of variable names used in the f-string interpolations
    """
    names = set()

    for value in node.values:
        if isinstance(value, ast.FormattedValue):
            # The actual expression is in value.value
            names.update(names_in_expr(value.value))

    return names


def is_sanitization_call(node: ast.Call) -> bool:
    """
    Check if a Call node represents a sanitization/escape function.

    Args:
        node: ast.Call node

    Returns:
        True if the call appears to be sanitization
    """
    SANITIZATION_PATTERNS = {
        'sanitize', 'escape', 'clean', 'strip', 'filter',
        'validate', 'allowlist', 'whitelist', 'html_escape',
        'quote', 'safe', 'secure', 'encode'
    }

    func_name = get_call_name(node)
    if func_name:
        func_lower = func_name.lower()
        return any(pattern in func_lower for pattern in SANITIZATION_PATTERNS)

    return False


def is_prompt_template_usage(node: ast.AST) -> bool:
    """
    Check if a node involves safe LangChain-style PromptTemplate patterns.

    These are safe because they use parameterized templates with automatic escaping.
    NOTE: Python's string.Template is NOT safe and should not match.

    Args:
        node: Any AST node

    Returns:
        True if safe PromptTemplate variant is used
    """
    # Only LangChain-style PromptTemplates are safe - NOT generic Template
    SAFE_TEMPLATE_PATTERNS = {
        'PromptTemplate', 'ChatPromptTemplate', 'SystemMessagePromptTemplate',
        'HumanMessagePromptTemplate', 'FewShotPromptTemplate',
        'AIMessagePromptTemplate', 'MessagesPlaceholder',
        'from_template',  # PromptTemplate.from_template()
    }

    for child in ast.walk(node):
        if isinstance(child, ast.Name):
            if child.id in SAFE_TEMPLATE_PATTERNS:
                return True
        elif isinstance(child, ast.Attribute):
            if child.attr in SAFE_TEMPLATE_PATTERNS:
                return True
        elif isinstance(child, ast.Call):
            func_name = get_call_name(child)
            if func_name and func_name in SAFE_TEMPLATE_PATTERNS:
                return True

    return False


def get_call_name(node: ast.Call) -> Optional[str]:
    """
    Get the function name from a Call node.

    Args:
        node: ast.Call node

    Returns:
        Function name as string, or None if unresolvable
    """
    if isinstance(node.func, ast.Name):
        return node.func.id
    elif isinstance(node.func, ast.Attribute):
        return node.func.attr
    return None


def get_full_call_name(node: ast.Call) -> str:
    """
    Get the full dotted name from a Call node (e.g., 'client.chat.completions.create').

    Args:
        node: ast.Call node

    Returns:
        Full dotted function name
    """
    parts = []
    current = node.func

    while isinstance(current, ast.Attribute):
        parts.append(current.attr)
        current = current.value

    if isinstance(current, ast.Name):
        parts.append(current.id)

    parts.reverse()
    return '.'.join(parts)


def find_assignments_in_scope(
    body: List[ast.stmt],
    target_var: str
) -> List[Tuple[int, ast.AST]]:
    """
    Find all assignments to a variable within a function body.

    Args:
        body: List of AST statements (function body)
        target_var: Variable name to find assignments for

    Returns:
        List of (line_number, value_node) tuples
    """
    assignments = []

    for stmt in body:
        if isinstance(stmt, ast.Assign):
            for target in stmt.targets:
                if isinstance(target, ast.Name) and target.id == target_var:
                    assignments.append((stmt.lineno, stmt.value))

    return assignments


def resolve_single_hop(
    body: List[ast.stmt],
    var_name: str,
    max_line: int
) -> Optional[ast.AST]:
    """
    Resolve a variable to its assigned value (single hop).

    Looks backwards from max_line to find the most recent assignment.

    Args:
        body: Function body statements
        var_name: Variable to resolve
        max_line: Only consider assignments before this line

    Returns:
        The AST node of the assigned value, or None
    """
    assignments = find_assignments_in_scope(body, var_name)

    # Filter to assignments before max_line, get most recent
    valid = [(line, value) for line, value in assignments if line < max_line]

    if valid:
        # Return the most recent assignment
        return max(valid, key=lambda x: x[0])[1]

    return None


def extract_dict_content_names(node: ast.AST) -> Set[str]:
    """
    Extract variable names used in 'content' keys of dict literals.

    For patterns like: [{"role": "user", "content": msg}]

    Args:
        node: AST node (typically a List of Dicts)

    Returns:
        Set of variable names used as content values
    """
    names = set()

    for child in ast.walk(node):
        if isinstance(child, ast.Dict):
            for key, value in zip(child.keys, child.values):
                if key is not None:
                    # Check if key is 'content' (or similar)
                    key_name = None
                    if isinstance(key, ast.Constant) and isinstance(key.value, str):
                        key_name = key.value
                    elif isinstance(key, ast.Str):  # Python 3.7 compat
                        key_name = key.s

                    if key_name and key_name.lower() in {'content', 'text', 'message'}:
                        names.update(names_in_expr(value))

    return names


def is_passthrough_call(node: ast.Call) -> bool:
    """
    Check if a call is a passthrough (doesn't sanitize).

    Methods like .strip(), .lower(), .upper() don't sanitize.

    Args:
        node: ast.Call node

    Returns:
        True if the call is a passthrough operation
    """
    PASSTHROUGH_METHODS = {
        'strip', 'lstrip', 'rstrip',
        'lower', 'upper', 'title', 'capitalize',
        'replace',  # replace could sanitize but often doesn't
        'split', 'join',
        'encode', 'decode',
        'format',  # format is not sanitization
    }

    if isinstance(node.func, ast.Attribute):
        return node.func.attr in PASSTHROUGH_METHODS

    return False


def find_call_at_line(
    body: List[ast.stmt],
    line: int,
    func_pattern: Optional[str] = None
) -> Optional[ast.Call]:
    """
    Find a Call node at a specific line number.

    Args:
        body: Function body statements
        line: Line number to find
        func_pattern: Optional function name pattern to match

    Returns:
        The ast.Call node, or None
    """
    for node in ast.walk(ast.Module(body=body, type_ignores=[])):
        if isinstance(node, ast.Call) and hasattr(node, 'lineno') and node.lineno == line:
            if func_pattern is None:
                return node
            else:
                func_name = get_full_call_name(node)
                if func_pattern in func_name:
                    return node

    return None


# Accepted sink keywords for LLM calls
LLM_SINK_KEYWORDS = {
    'prompt', 'messages', 'input', 'text', 'query',
    'instruction', 'system', 'user', 'content'
}

# Common LLM API methods
LLM_API_METHODS = {
    'generate', 'complete', 'chat', 'create',
    'invoke', 'call', 'run', 'predict'
}


def is_llm_sink_keyword(keyword: str) -> bool:
    """Check if a keyword argument is an LLM sink."""
    return keyword.lower() in LLM_SINK_KEYWORDS


def is_llm_api_call(func_name: str) -> bool:
    """Check if a function name looks like an LLM API call."""
    func_lower = func_name.lower()
    return any(method in func_lower for method in LLM_API_METHODS)
