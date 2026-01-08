"""
AST Analyzer for detecting code patterns.
"""

import ast
import re
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple
from dataclasses import dataclass


@dataclass
class ASTMatch:
    """Result of an AST pattern match."""
    file_path: str
    line_number: int
    node_type: str
    name: str
    snippet: str
    context: Optional[str] = None


class ASTAnalyzer:
    """
    Analyzes Python AST for security control patterns.
    """

    def __init__(self):
        self.cache: Dict[str, ast.AST] = {}
        self._function_calls: Dict[str, List[ASTMatch]] = {}
        self._imports: Dict[str, List[ASTMatch]] = {}
        self._decorators: Dict[str, List[ASTMatch]] = {}
        self._class_defs: Dict[str, List[ASTMatch]] = {}
        self._assignments: Dict[str, List[ASTMatch]] = {}

    def analyze_file(self, file_path: Path) -> bool:
        """Parse and analyze a Python file."""
        try:
            content = file_path.read_text(encoding="utf-8", errors="ignore")
            tree = ast.parse(content, filename=str(file_path))
            self.cache[str(file_path)] = tree
            self._extract_patterns(tree, str(file_path), content)
            return True
        except SyntaxError:
            return False
        except Exception:
            return False

    def analyze_directory(self, directory: Path) -> int:
        """Analyze all Python files in a directory."""
        count = 0
        for py_file in directory.rglob("*.py"):
            if self.analyze_file(py_file):
                count += 1
        return count

    def _extract_patterns(self, tree: ast.AST, file_path: str, content: str) -> None:
        """Extract all patterns from AST."""
        lines = content.splitlines()

        for node in ast.walk(tree):
            # Function/method calls
            if isinstance(node, ast.Call):
                call_name = self._get_call_name(node)
                if call_name:
                    line_num = getattr(node, "lineno", 0)
                    snippet = lines[line_num - 1] if 0 < line_num <= len(lines) else ""
                    match = ASTMatch(
                        file_path=file_path,
                        line_number=line_num,
                        node_type="call",
                        name=call_name,
                        snippet=snippet.strip(),
                    )
                    if call_name not in self._function_calls:
                        self._function_calls[call_name] = []
                    self._function_calls[call_name].append(match)

            # Imports
            elif isinstance(node, ast.Import):
                for alias in node.names:
                    line_num = getattr(node, "lineno", 0)
                    snippet = lines[line_num - 1] if 0 < line_num <= len(lines) else ""
                    match = ASTMatch(
                        file_path=file_path,
                        line_number=line_num,
                        node_type="import",
                        name=alias.name,
                        snippet=snippet.strip(),
                    )
                    if alias.name not in self._imports:
                        self._imports[alias.name] = []
                    self._imports[alias.name].append(match)

            elif isinstance(node, ast.ImportFrom):
                module = node.module or ""
                for alias in node.names:
                    full_name = f"{module}.{alias.name}" if module else alias.name
                    line_num = getattr(node, "lineno", 0)
                    snippet = lines[line_num - 1] if 0 < line_num <= len(lines) else ""
                    match = ASTMatch(
                        file_path=file_path,
                        line_number=line_num,
                        node_type="import_from",
                        name=full_name,
                        snippet=snippet.strip(),
                        context=module,
                    )
                    # Store both full name and just the imported name
                    for name in [full_name, alias.name, module]:
                        if name:
                            if name not in self._imports:
                                self._imports[name] = []
                            self._imports[name].append(match)

            # Function definitions with decorators
            elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                for decorator in node.decorator_list:
                    dec_name = self._get_decorator_name(decorator)
                    if dec_name:
                        line_num = getattr(decorator, "lineno", 0)
                        snippet = lines[line_num - 1] if 0 < line_num <= len(lines) else ""
                        match = ASTMatch(
                            file_path=file_path,
                            line_number=line_num,
                            node_type="decorator",
                            name=dec_name,
                            snippet=snippet.strip(),
                            context=node.name,
                        )
                        if dec_name not in self._decorators:
                            self._decorators[dec_name] = []
                        self._decorators[dec_name].append(match)

            # Class definitions
            elif isinstance(node, ast.ClassDef):
                line_num = getattr(node, "lineno", 0)
                snippet = lines[line_num - 1] if 0 < line_num <= len(lines) else ""
                match = ASTMatch(
                    file_path=file_path,
                    line_number=line_num,
                    node_type="class",
                    name=node.name,
                    snippet=snippet.strip(),
                )
                if node.name not in self._class_defs:
                    self._class_defs[node.name] = []
                self._class_defs[node.name].append(match)

            # Assignments (for config detection)
            elif isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        line_num = getattr(node, "lineno", 0)
                        snippet = lines[line_num - 1] if 0 < line_num <= len(lines) else ""
                        match = ASTMatch(
                            file_path=file_path,
                            line_number=line_num,
                            node_type="assignment",
                            name=target.id,
                            snippet=snippet.strip(),
                        )
                        if target.id not in self._assignments:
                            self._assignments[target.id] = []
                        self._assignments[target.id].append(match)

    def _get_call_name(self, node: ast.Call) -> Optional[str]:
        """Extract function call name."""
        if isinstance(node.func, ast.Name):
            return node.func.id
        elif isinstance(node.func, ast.Attribute):
            parts = []
            current = node.func
            while isinstance(current, ast.Attribute):
                parts.append(current.attr)
                current = current.value
            if isinstance(current, ast.Name):
                parts.append(current.id)
            return ".".join(reversed(parts))
        return None

    def _get_decorator_name(self, node: ast.expr) -> Optional[str]:
        """Extract decorator name."""
        if isinstance(node, ast.Name):
            return node.id
        elif isinstance(node, ast.Attribute):
            return self._get_call_name(ast.Call(func=node, args=[], keywords=[]))
        elif isinstance(node, ast.Call):
            return self._get_call_name(node)
        return None

    def find_function_calls(self, pattern: str, regex: bool = False) -> List[ASTMatch]:
        """Find function calls matching pattern."""
        results = []
        if regex:
            compiled = re.compile(pattern, re.IGNORECASE)
            for name, matches in self._function_calls.items():
                if compiled.search(name):
                    results.extend(matches)
        else:
            pattern_lower = pattern.lower()
            for name, matches in self._function_calls.items():
                if pattern_lower in name.lower():
                    results.extend(matches)
        return results

    def find_imports(self, pattern: str, regex: bool = False) -> List[ASTMatch]:
        """Find imports matching pattern."""
        results = []
        if regex:
            compiled = re.compile(pattern, re.IGNORECASE)
            for name, matches in self._imports.items():
                if compiled.search(name):
                    results.extend(matches)
        else:
            pattern_lower = pattern.lower()
            for name, matches in self._imports.items():
                if pattern_lower in name.lower():
                    results.extend(matches)
        return results

    def find_decorators(self, pattern: str, regex: bool = False) -> List[ASTMatch]:
        """Find decorators matching pattern."""
        results = []
        if regex:
            compiled = re.compile(pattern, re.IGNORECASE)
            for name, matches in self._decorators.items():
                if compiled.search(name):
                    results.extend(matches)
        else:
            pattern_lower = pattern.lower()
            for name, matches in self._decorators.items():
                if pattern_lower in name.lower():
                    results.extend(matches)
        return results

    def find_classes(self, pattern: str, regex: bool = False) -> List[ASTMatch]:
        """Find class definitions matching pattern."""
        results = []
        if regex:
            compiled = re.compile(pattern, re.IGNORECASE)
            for name, matches in self._class_defs.items():
                if compiled.search(name):
                    results.extend(matches)
        else:
            pattern_lower = pattern.lower()
            for name, matches in self._class_defs.items():
                if pattern_lower in name.lower():
                    results.extend(matches)
        return results

    def find_assignments(self, pattern: str, regex: bool = False) -> List[ASTMatch]:
        """Find variable assignments matching pattern."""
        results = []
        if regex:
            compiled = re.compile(pattern, re.IGNORECASE)
            for name, matches in self._assignments.items():
                if compiled.search(name):
                    results.extend(matches)
        else:
            pattern_lower = pattern.lower()
            for name, matches in self._assignments.items():
                if pattern_lower in name.lower():
                    results.extend(matches)
        return results

    def has_import(self, module_name: str) -> bool:
        """Check if a module is imported anywhere."""
        return any(
            module_name.lower() in name.lower()
            for name in self._imports.keys()
        )

    def has_decorator(self, decorator_name: str) -> bool:
        """Check if a decorator is used anywhere."""
        return any(
            decorator_name.lower() in name.lower()
            for name in self._decorators.keys()
        )

    def get_all_imports(self) -> Set[str]:
        """Get all unique import names."""
        return set(self._imports.keys())

    def get_all_function_calls(self) -> Set[str]:
        """Get all unique function call names."""
        return set(self._function_calls.keys())

    def clear(self) -> None:
        """Clear all cached data."""
        self.cache.clear()
        self._function_calls.clear()
        self._imports.clear()
        self._decorators.clear()
        self._class_defs.clear()
        self._assignments.clear()
