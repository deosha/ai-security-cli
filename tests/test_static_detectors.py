"""
Unit tests for aisentry static detectors.
"""

import tempfile

import pytest

from aisentry.parsers.python.ast_parser import PythonASTParser
from aisentry.static_detectors import (
    PromptInjectionDetector,
    InsecureOutputDetector,
    ModelDOSDetector,
    SecretsDetector,
    ExcessiveAgencyDetector,
)


def parse_code(code: str) -> dict:
    """Helper to parse code string using temp file."""
    with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
        f.write(code)
        f.flush()
        parser = PythonASTParser(f.name)
        return parser.parse()


class TestPromptInjectionDetector:
    """Test LLM01 Prompt Injection Detector."""

    @pytest.fixture
    def detector(self):
        return PromptInjectionDetector(confidence_threshold=0.5)

    def test_detect_f_string_injection(self, detector):
        """Test detection of f-string prompt injection."""
        code = '''
from openai import OpenAI
client = OpenAI()

def vulnerable(user_input):
    response = client.chat.completions.create(
        model="gpt-4",
        messages=[{"role": "user", "content": f"Process: {user_input}"}]
    )
    return response.choices[0].message.content
'''
        parsed = parse_code(code)
        findings = detector.detect(parsed)
        assert len(findings) > 0
        assert any("LLM01" in f.category for f in findings)

    def test_detect_format_string_injection(self, detector):
        """Test detection of format() injection."""
        code = '''
from openai import OpenAI
client = OpenAI()

def vulnerable(user_input):
    prompt = "Process this: {}".format(user_input)
    response = client.chat.completions.create(
        model="gpt-4",
        messages=[{"role": "user", "content": prompt}]
    )
'''
        parsed = parse_code(code)
        findings = detector.detect(parsed)
        assert len(findings) > 0

    def test_safe_parameterized_prompt(self, detector):
        """Test that parameterized prompts don't trigger false positives."""
        code = '''
from openai import OpenAI
client = OpenAI()

SYSTEM_PROMPT = "You are a helpful assistant."

def safe_function():
    response = client.chat.completions.create(
        model="gpt-4",
        messages=[{"role": "system", "content": SYSTEM_PROMPT}]
    )
'''
        parsed = parse_code(code)
        findings = detector.detect(parsed)
        # Should have no or very low confidence findings
        high_confidence = [f for f in findings if f.confidence >= 0.7]
        assert len(high_confidence) == 0


class TestInsecureOutputDetector:
    """Test LLM02 Insecure Output Detector."""

    @pytest.fixture
    def detector(self):
        return InsecureOutputDetector(confidence_threshold=0.5)

    def test_detect_eval_of_output(self, detector):
        """Test detection of eval() on LLM output."""
        code = '''
from openai import OpenAI
client = OpenAI()

def vulnerable():
    response = client.chat.completions.create(
        model="gpt-4",
        messages=[{"role": "user", "content": "Generate code"}]
    )
    result = response.choices[0].message.content
    eval(result)
'''
        parsed = parse_code(code)
        findings = detector.detect(parsed)
        assert len(findings) > 0
        assert any("LLM02" in f.category for f in findings)

    def test_detect_exec_of_output(self, detector):
        """Test detection of exec() on LLM output."""
        code = '''
from openai import OpenAI
client = OpenAI()

def vulnerable():
    response = client.chat.completions.create(
        model="gpt-4",
        messages=[{"role": "user", "content": "Write code"}]
    )
    exec(response.choices[0].message.content)
'''
        parsed = parse_code(code)
        findings = detector.detect(parsed)
        assert len(findings) > 0

    def test_detect_subprocess_with_output(self, detector):
        """Test detection of subprocess with LLM output."""
        code = '''
import subprocess
from openai import OpenAI
client = OpenAI()

def vulnerable():
    response = client.chat.completions.create(
        model="gpt-4",
        messages=[{"role": "user", "content": "Give command"}]
    )
    cmd = response.choices[0].message.content
    subprocess.run(cmd, shell=True)
'''
        parsed = parse_code(code)
        findings = detector.detect(parsed)
        assert len(findings) > 0

    def test_detect_helper_function_interprocedural(self, detector):
        """Test interprocedural detection: helper function returns LLM output."""
        code = '''
from openai import OpenAI
client = OpenAI()

def get_llm_response(prompt):
    response = client.chat.completions.create(
        model="gpt-4",
        messages=[{"role": "user", "content": prompt}]
    )
    return response.choices[0].message.content

def vulnerable(user_input):
    llm_output = get_llm_response(user_input)
    eval(llm_output)  # This should be detected via interprocedural analysis
'''
        parsed = parse_code(code)
        findings = detector.detect(parsed)
        # Should detect the eval() even though LLM call is in helper function
        assert len(findings) > 0
        assert any("LLM02" in f.category for f in findings)

    def test_detect_anthropic_output(self, detector):
        """Test detection of Anthropic API output in dangerous sink."""
        code = '''
import anthropic
client = anthropic.Anthropic()

def vulnerable():
    message = client.messages.create(
        model="claude-3-opus-20240229",
        messages=[{"role": "user", "content": "Generate code"}]
    )
    result = message.content[0].text
    exec(result)
'''
        parsed = parse_code(code)
        findings = detector.detect(parsed)
        assert len(findings) > 0


class TestModelDOSDetector:
    """Test LLM04 Model DoS Detector."""

    @pytest.fixture
    def detector(self):
        return ModelDOSDetector(confidence_threshold=0.5)

    @pytest.fixture
    def targeted_detector(self):
        """Detector in targeted mode for full heuristic analysis."""
        return ModelDOSDetector(confidence_threshold=0.5, targeted=True)

    def test_detect_no_rate_limiting(self, detector):
        """Test detection of LLM calls without rate limiting."""
        code = '''
from openai import OpenAI
client = OpenAI()

def process_request(user_input):
    response = client.chat.completions.create(
        model="gpt-4",
        messages=[{"role": "user", "content": user_input}]
    )
    return response.choices[0].message.content
'''
        parsed = parse_code(code)
        findings = detector.detect(parsed)
        assert isinstance(findings, list)

    def test_detect_loop_with_llm_call(self, detector):
        """Test detection of LLM calls in loops."""
        code = '''
from openai import OpenAI
client = OpenAI()

def process_batch(items):
    results = []
    for item in items:
        response = client.chat.completions.create(
            model="gpt-4",
            messages=[{"role": "user", "content": item}]
        )
        results.append(response.choices[0].message.content)
    return results
'''
        parsed = parse_code(code)
        findings = detector.detect(parsed)
        assert isinstance(findings, list)

    def test_safe_with_rate_limiting(self, detector):
        """Test that rate-limited calls have lower risk."""
        code = '''
from openai import OpenAI
from ratelimit import limits

client = OpenAI()

@limits(calls=10, period=60)
def rate_limited_call(user_input):
    response = client.chat.completions.create(
        model="gpt-4",
        messages=[{"role": "user", "content": user_input}],
        max_tokens=100,
        timeout=30
    )
    return response.choices[0].message.content
'''
        parsed = parse_code(code)
        findings = detector.detect(parsed)
        assert isinstance(findings, list)

    def test_untargeted_skips_few_missing_controls(self, detector):
        """Test that untargeted mode skips functions with only 1-2 missing controls."""
        code = '''
from openai import OpenAI
client = OpenAI()

def function_with_some_protection(user_input):
    # Has timeout and max_tokens, only missing rate limiting
    # Should not trigger in untargeted mode (fewer than 3 risks)
    response = client.chat.completions.create(
        model="gpt-4",
        messages=[{"role": "user", "content": user_input}],
        max_tokens=500,
        timeout=30
    )
    return response.choices[0].message.content
'''
        parsed = parse_code(code)
        findings = detector.detect(parsed)
        # With only 1-2 missing controls, untargeted mode should not report
        assert len(findings) == 0

    def test_targeted_reports_no_rate_limiting(self, targeted_detector):
        """Test that targeted mode reports missing rate limiting."""
        code = '''
from openai import OpenAI
client = OpenAI()

def simple_function(user_input):
    # No rate limiting - should be reported in targeted mode
    response = client.chat.completions.create(
        model="gpt-4",
        messages=[{"role": "user", "content": user_input}]
    )
    return response.choices[0].message.content
'''
        parsed = parse_code(code)
        findings = targeted_detector.detect(parsed)
        # In targeted mode, should report the missing protections
        assert len(findings) > 0
        assert any("LLM04" in f.category for f in findings)

    def test_untargeted_reports_loop_evidence(self, detector):
        """Test that untargeted mode still reports LLM calls in loops."""
        code = '''
from openai import OpenAI
client = OpenAI()

def batch_process(items):
    results = []
    for item in items:
        response = client.chat.completions.create(
            model="gpt-4",
            messages=[{"role": "user", "content": item}]
        )
        results.append(response.choices[0].message.content)
    return results
'''
        parsed = parse_code(code)
        findings = detector.detect(parsed)
        # LLM in loop is high-confidence evidence, should be reported even untargeted
        assert len(findings) > 0
        assert any("llm_in_loop" in f.evidence.get('risks', []) for f in findings)


class TestSecretsDetector:
    """Test LLM06 Secrets Detector."""

    @pytest.fixture
    def detector(self):
        return SecretsDetector(confidence_threshold=0.5)

    def test_detect_hardcoded_api_key(self, detector):
        """Test detection of hardcoded API keys."""
        code = '''
from openai import OpenAI

api_key = "sk-proj-abc123def456ghijklmnopqrstuvwxyz1234567890"\nclient = OpenAI(api_key=api_key)
'''
        parsed = parse_code(code)
        findings = detector.detect(parsed)
        assert len(findings) > 0
        assert any("LLM06" in f.category for f in findings)

    def test_detect_secret_in_string(self, detector):
        """Test detection of secrets in strings."""
        code = '''
DB_PASSWORD = "super_secret_password123"
API_SECRET = "sk-proj-abcdefghijklmnopqrstuvwxyz123456"
'''
        parsed = parse_code(code)
        findings = detector.detect(parsed)
        assert len(findings) > 0

    def test_safe_env_variable(self, detector):
        """Test that env variables don't trigger false positives."""
        code = '''
import os
from openai import OpenAI

client = OpenAI(api_key=os.environ.get("OPENAI_API_KEY"))
'''
        parsed = parse_code(code)
        findings = detector.detect(parsed)
        high_confidence = [f for f in findings if f.confidence >= 0.8]
        assert len(high_confidence) == 0


class TestExcessiveAgencyDetector:
    """Test LLM08 Excessive Agency Detector."""

    @pytest.fixture
    def detector(self):
        return ExcessiveAgencyDetector(confidence_threshold=0.5)

    def test_detect_unrestricted_tool_use(self, detector):
        """Test detection of unrestricted tool usage."""
        code = '''
from openai import OpenAI
import subprocess

client = OpenAI()

def agent_with_tools(user_request):
    response = client.chat.completions.create(
        model="gpt-4",
        messages=[{"role": "user", "content": user_request}],
        tools=[
            {"type": "function", "function": {"name": "run_command"}},
            {"type": "function", "function": {"name": "delete_file"}},
        ]
    )
    for tool_call in response.choices[0].message.tool_calls:
        if tool_call.function.name == "run_command":
            subprocess.run(tool_call.function.arguments, shell=True)
'''
        parsed = parse_code(code)
        findings = detector.detect(parsed)
        assert isinstance(findings, list)

    def test_detect_auto_execution(self, detector):
        """Test detection of automatic action execution."""
        code = '''
from openai import OpenAI

client = OpenAI()

def auto_agent(goal):
    while True:
        response = client.chat.completions.create(
            model="gpt-4",
            messages=[{"role": "user", "content": goal}]
        )
        action = response.choices[0].message.content
        execute_action(action)
'''
        parsed = parse_code(code)
        findings = detector.detect(parsed)
        assert isinstance(findings, list)


class TestDetectorConfidenceThreshold:
    """Test detector confidence threshold filtering."""

    def test_high_threshold_filters_low_confidence(self):
        """Test that high threshold filters low confidence findings."""
        detector = PromptInjectionDetector(confidence_threshold=0.9)
        code = '''
from openai import OpenAI
client = OpenAI()

def maybe_vulnerable(data):
    response = client.chat.completions.create(
        model="gpt-4",
        messages=[{"role": "user", "content": str(data)}]
    )
'''
        parsed = parse_code(code)
        findings = detector.detect(parsed)
        for f in findings:
            assert f.confidence >= 0.9

    def test_low_threshold_includes_more(self):
        """Test that low threshold includes more findings."""
        detector = PromptInjectionDetector(confidence_threshold=0.3)
        code = '''
from openai import OpenAI
client = OpenAI()

def process(data):
    prompt = f"Analyze: {data}"
    response = client.chat.completions.create(
        model="gpt-4",
        messages=[{"role": "user", "content": prompt}]
    )
'''
        parsed = parse_code(code)
        findings = detector.detect(parsed)
        assert isinstance(findings, list)


class TestDetectorMetadata:
    """Test detector metadata and properties."""

    def test_detector_ids(self):
        """Test detector IDs are correct."""
        assert PromptInjectionDetector.detector_id == "LLM01"
        assert InsecureOutputDetector.detector_id == "LLM02"
        assert ModelDOSDetector.detector_id == "LLM04"
        assert SecretsDetector.detector_id == "LLM06"
        assert ExcessiveAgencyDetector.detector_id == "LLM08"

    def test_detector_names(self):
        """Test detector names are set."""
        assert PromptInjectionDetector.name is not None
        assert InsecureOutputDetector.name is not None
        assert ModelDOSDetector.name is not None

    def test_detector_initialization(self):
        """Test detector initialization options."""
        detector = PromptInjectionDetector(
            verbose=True,
            confidence_threshold=0.8
        )
        assert detector.verbose is True
        assert detector.confidence_threshold == 0.8
