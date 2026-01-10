"""Tests for the Python AST parser."""

import tempfile
import os

from aisentry.parsers.python.ast_parser import PythonASTParser


def create_temp_file(code: str) -> str:
    """Create a temporary Python file with the given code."""
    fd, path = tempfile.mkstemp(suffix='.py')
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as f:
            f.write(code)
    except:
        os.close(fd)
        raise
    return path


class TestPythonASTParser:
    """Tests for PythonASTParser."""

    def test_parse_simple_function(self):
        """Test parsing a simple function definition."""
        code = '''
def hello(name):
    """Say hello."""
    return f"Hello, {name}!"
'''
        path = create_temp_file(code)
        try:
            parser = PythonASTParser(path)
            result = parser.parse()

            assert result["parsable"] is True
            assert "functions" in result
            assert len(result["functions"]) == 1
            assert result["functions"][0]["name"] == "hello"
            assert "name" in result["functions"][0]["args"]
        finally:
            os.unlink(path)

    def test_parse_imports(self):
        """Test parsing import statements."""
        code = '''
import os
import sys
from pathlib import Path
from typing import List, Dict
'''
        path = create_temp_file(code)
        try:
            parser = PythonASTParser(path)
            result = parser.parse()

            assert result["parsable"] is True
            assert "imports" in result
            imports = result["imports"]

            # Check for os import
            os_imports = [i for i in imports if i.get("module") == "os"]
            assert len(os_imports) >= 1

            # Check for pathlib from import
            pathlib_imports = [i for i in imports if i.get("module") == "pathlib"]
            assert len(pathlib_imports) >= 1
        finally:
            os.unlink(path)

    def test_parse_class(self):
        """Test parsing a class definition."""
        code = '''
class MyClass:
    """A simple class."""

    def __init__(self, value):
        self.value = value

    def get_value(self):
        return self.value
'''
        path = create_temp_file(code)
        try:
            parser = PythonASTParser(path)
            result = parser.parse()

            assert result["parsable"] is True
            assert "classes" in result
            assert len(result["classes"]) >= 1
            assert result["classes"][0]["name"] == "MyClass"
        finally:
            os.unlink(path)

    def test_parse_function_calls(self):
        """Test parsing function calls."""
        code = '''
import openai

client = openai.OpenAI()
response = client.chat.completions.create(
    model="gpt-4",
    messages=[{"role": "user", "content": "Hello"}]
)
'''
        path = create_temp_file(code)
        try:
            parser = PythonASTParser(path)
            result = parser.parse()

            assert result["parsable"] is True
            # Should detect LLM API calls
            assert "llm_api_calls" in result or "structured_calls" in result
        finally:
            os.unlink(path)

    def test_parse_strings(self):
        """Test parsing string literals and f-strings."""
        code = '''
prompt = "Tell me about {topic}"
system_message = f"You are a helpful assistant"
'''
        path = create_temp_file(code)
        try:
            parser = PythonASTParser(path)
            result = parser.parse()

            assert result["parsable"] is True
            # String operations are extracted
            assert "string_operations" in result or "assignments" in result
        finally:
            os.unlink(path)

    def test_parse_empty_file(self):
        """Test parsing an empty file."""
        path = create_temp_file("")
        try:
            parser = PythonASTParser(path)
            result = parser.parse()

            assert result is not None
            assert isinstance(result, dict)
            assert result["parsable"] is True
        finally:
            os.unlink(path)

    def test_parse_syntax_error(self):
        """Test that syntax errors return error result without crashing."""
        code = '''
def broken(
    # Missing closing paren
'''
        path = create_temp_file(code)
        try:
            parser = PythonASTParser(path)
            result = parser.parse()

            # Should return error result, not crash
            assert result is not None
            assert isinstance(result, dict)
            assert result["parsable"] is False
            assert "error" in result
        finally:
            os.unlink(path)

    def test_parse_relative_import(self):
        """Test parsing relative imports (from . import x)."""
        code = '''
from . import utils
from .. import base
from .helpers import helper_func
'''
        path = create_temp_file(code)
        try:
            parser = PythonASTParser(path)
            result = parser.parse()

            # Should not crash on relative imports (module can be empty string)
            assert result["parsable"] is True
            assert "imports" in result
            imports = result["imports"]
            assert len(imports) >= 1
        finally:
            os.unlink(path)

    def test_parse_f_strings(self):
        """Test parsing f-string expressions."""
        code = '''
name = "Alice"
prompt = f"Hello, {name}! How can I help you today?"
'''
        path = create_temp_file(code)
        try:
            parser = PythonASTParser(path)
            result = parser.parse()

            assert result["parsable"] is True
            # F-strings should be captured in string_operations
            assert "string_operations" in result
        finally:
            os.unlink(path)

    def test_parse_decorators(self):
        """Test parsing function decorators."""
        code = '''
@app.route("/api/chat")
def chat_endpoint():
    pass
'''
        path = create_temp_file(code)
        try:
            parser = PythonASTParser(path)
            result = parser.parse()

            assert result["parsable"] is True
            assert "functions" in result
            functions = result["functions"]
            assert len(functions) >= 1
            # Decorators should be captured
            assert "decorators" in functions[0]
        finally:
            os.unlink(path)

    def test_file_not_found(self):
        """Test handling of non-existent file."""
        parser = PythonASTParser("/nonexistent/path/file.py")
        result = parser.parse()

        assert result["parsable"] is False
        assert "error" in result
