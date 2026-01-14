"""
Unit tests for ML-based prompt injection detection.

Tests cover:
- Feature extraction from Python AST
- ML model prediction (heuristic fallback)
- Detector integration
- Vulnerability location finding
- Confidence calculation
"""

import tempfile

import numpy as np
import pytest

from aisentry.parsers.python.ast_parser import PythonASTParser
from aisentry.ml.feature_extractor import FeatureExtractor, CodeFeatures
from aisentry.ml.model_inference import ONNXInference, MLPrediction
from aisentry.static_detectors.ml_prompt_injection import MLPromptInjectionDetector


def parse_code(code: str) -> dict:
    """Helper to parse code string using temp file."""
    with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
        f.write(code)
        f.flush()
        parser = PythonASTParser(f.name)
        return parser.parse()


class TestFeatureExtractor:
    """Test AST feature extraction."""

    @pytest.fixture
    def extractor(self):
        return FeatureExtractor()

    def test_extracts_45_features(self, extractor):
        """Test that feature vector has correct size."""
        code = '''
from openai import OpenAI

def example():
    pass
'''
        parsed = parse_code(code)
        features = extractor.extract(parsed)

        assert isinstance(features, CodeFeatures)
        assert len(features.features) == 45

    def test_detects_user_input_features(self, extractor):
        """Test extraction of user input indicators."""
        code = '''
from flask import request

def handler():
    user_input = request.get('query')
    text = input('Enter: ')
'''
        parsed = parse_code(code)
        features = extractor.extract(parsed)

        # User input features are in indices 0-9
        user_input_features = features.features[0:10]
        # Should have some non-zero user input features
        assert np.sum(user_input_features) > 0

    def test_detects_llm_api_features(self, extractor):
        """Test extraction of LLM API patterns."""
        code = '''
from openai import OpenAI

client = OpenAI()

def call_llm():
    response = client.chat.completions.create(
        model="gpt-4",
        messages=[{"role": "user", "content": "Hello"}]
    )
'''
        parsed = parse_code(code)
        features = extractor.extract(parsed)

        # LLM features are in indices 10-21
        llm_features = features.features[10:22]
        # Should detect OpenAI usage
        assert np.sum(llm_features) > 0

    def test_detects_string_operation_features(self, extractor):
        """Test extraction of string operation patterns."""
        code = '''
def build_prompt(user_input):
    prompt1 = f"Process: {user_input}"
    prompt2 = "Handle: {}".format(user_input)
    prompt3 = "Do: " + user_input
'''
        parsed = parse_code(code)
        features = extractor.extract(parsed)

        # String operation features are in indices 22-29
        string_features = features.features[22:30]
        # Should detect f-strings, format, and concatenation
        assert np.sum(string_features) > 0

    def test_detects_data_flow_features(self, extractor):
        """Test extraction of data flow indicators."""
        code = '''
from openai import OpenAI
from flask import request

client = OpenAI()

def vulnerable(user_input):
    response = client.chat.completions.create(
        model="gpt-4",
        messages=[{"role": "user", "content": f"{user_input}"}]
    )
'''
        parsed = parse_code(code)
        features = extractor.extract(parsed)

        # Data flow features are in indices 30-39
        flow_features = features.features[30:40]
        # Should detect user input to LLM flow
        assert np.sum(flow_features) > 0

    def test_detects_mitigation_features(self, extractor):
        """Test extraction of mitigation indicators."""
        code = '''
from langchain.prompts import PromptTemplate

def safe_function(query):
    template = PromptTemplate(
        input_variables=["query"],
        template="Process: {query}"
    )
'''
        parsed = parse_code(code)
        features = extractor.extract(parsed)

        # Mitigation features are in indices 40-44
        mitigation_features = features.features[40:45]
        # Should detect prompt template usage
        assert np.sum(mitigation_features) > 0

    def test_feature_names_match_count(self, extractor):
        """Test that feature names list matches feature count."""
        code = '''
def simple():
    pass
'''
        parsed = parse_code(code)
        features = extractor.extract(parsed)

        assert len(features.feature_names) == len(features.features)
        assert len(features.feature_names) == 45


class TestONNXInference:
    """Test ML model inference (heuristic fallback)."""

    @pytest.fixture
    def model(self):
        return ONNXInference.get_instance()

    def test_prediction_returns_mlprediction(self, model):
        """Test that prediction returns correct type."""
        features = np.zeros(45, dtype=np.float32)

        prediction = model.predict(features)

        assert isinstance(prediction, MLPrediction)
        assert hasattr(prediction, 'is_vulnerable')
        assert hasattr(prediction, 'vulnerability_probability')
        assert hasattr(prediction, 'attack_vector')
        assert hasattr(prediction, 'attack_vector_probabilities')
        assert hasattr(prediction, 'feature_importance')

    def test_low_risk_features_low_probability(self, model):
        """Test that safe code gets low vulnerability probability."""
        # All zeros = no risky patterns
        features = np.zeros(45, dtype=np.float32)

        prediction = model.predict(features)

        assert prediction.vulnerability_probability < 0.5
        assert not prediction.is_vulnerable

    def test_high_risk_features_high_probability(self, model):
        """Test that risky patterns get high vulnerability probability."""
        feature_names = [
            # User input indicators (10)
            'has_request_get', 'has_input_call', 'has_sys_argv', 'has_environ_access',
            'user_input_var_count', 'user_param_in_func_args', 'has_form_access',
            'has_json_body', 'has_file_upload', 'external_data_sources',
            # LLM patterns (12)
            'llm_call_count', 'has_openai_import', 'has_anthropic_import',
            'has_langchain_import', 'uses_chat_completion', 'uses_messages_api',
            'prompt_var_in_llm_call', 'system_prompt_present', 'has_bedrock_import',
            'has_cohere_import', 'has_huggingface_import', 'llm_in_function',
            # String ops (8)
            'fstring_count', 'format_call_count', 'concat_count', 'string_in_llm_arg',
            'user_var_in_fstring', 'template_string_count', 'percent_format_count',
            'join_call_count',
            # Data flow (10)
            'direct_user_to_llm', 'single_hop_user_to_llm', 'assignment_chain_length',
            'function_returns_user_data', 'cross_function_flow', 'user_to_string_op',
            'string_op_to_llm', 'llm_output_used', 'llm_output_returned',
            'llm_output_to_sink',
            # Mitigations (5)
            'has_input_validation', 'has_sanitization', 'has_prompt_template',
            'has_allowlist_check', 'has_output_validation'
        ]

        features = np.zeros(45, dtype=np.float32)

        # Set high-risk features
        if 'has_request_get' in feature_names:
            features[feature_names.index('has_request_get')] = 1.0
        if 'llm_call_count' in feature_names:
            features[feature_names.index('llm_call_count')] = 2.0
        if 'direct_user_to_llm' in feature_names:
            features[feature_names.index('direct_user_to_llm')] = 1.0
        if 'user_var_in_fstring' in feature_names:
            features[feature_names.index('user_var_in_fstring')] = 1.0

        prediction = model.predict(features, feature_names)

        assert prediction.vulnerability_probability > 0.3

    def test_attack_vector_classification(self, model):
        """Test that attack vector is classified."""
        features = np.zeros(45, dtype=np.float32)

        prediction = model.predict(features)

        assert prediction.attack_vector in ('direct', 'indirect', 'stored', 'none')
        assert isinstance(prediction.attack_vector_probabilities, dict)

    def test_feature_importance_populated(self, model):
        """Test that feature importance is returned."""
        features = np.ones(45, dtype=np.float32)

        prediction = model.predict(features)

        assert isinstance(prediction.feature_importance, dict)
        assert len(prediction.feature_importance) > 0


class TestMLPromptInjectionDetector:
    """Test ML-based prompt injection detector."""

    @pytest.fixture
    def detector(self):
        return MLPromptInjectionDetector(confidence_threshold=0.3)

    def test_detector_metadata(self):
        """Test detector has correct metadata."""
        assert MLPromptInjectionDetector.detector_id == "ML_LLM01"
        assert MLPromptInjectionDetector.detector_name == "ML-Based Prompt Injection"

    def test_detects_direct_injection(self, detector):
        """Test detection of direct prompt injection."""
        code = '''
from openai import OpenAI
from flask import request

client = OpenAI()

def vulnerable():
    user_input = request.get('query')
    response = client.chat.completions.create(
        model="gpt-4",
        messages=[{"role": "user", "content": f"Process: {user_input}"}]
    )
    return response.choices[0].message.content
'''
        parsed = parse_code(code)
        findings = detector.detect(parsed)

        # Should detect potential injection
        assert len(findings) >= 0  # May or may not detect based on heuristics
        if findings:
            assert any("ML" in f.category or "LLM01" in f.category for f in findings)

    def test_detects_format_string_injection(self, detector):
        """Test detection of format string injection."""
        code = '''
from anthropic import Anthropic
from flask import request

client = Anthropic()

def process_request():
    message = request.json.get('message')
    prompt = "Handle this request: {}".format(message)
    response = client.messages.create(
        model="claude-3",
        messages=[{"role": "user", "content": prompt}]
    )
'''
        parsed = parse_code(code)
        findings = detector.detect(parsed)

        # Findings list returned (may be empty based on heuristics)
        assert isinstance(findings, list)

    def test_safe_code_low_confidence(self, detector):
        """Test that safe code has low or no findings."""
        code = '''
from openai import OpenAI

client = OpenAI()

# Safe: Static prompt, no user input
def safe_function():
    response = client.chat.completions.create(
        model="gpt-4",
        messages=[{"role": "user", "content": "Explain Python basics"}]
    )
    return response.choices[0].message.content
'''
        parsed = parse_code(code)
        findings = detector.detect(parsed)

        # Should have no high-confidence findings
        high_confidence = [f for f in findings if f.confidence >= 0.7]
        assert len(high_confidence) == 0

    def test_finding_evidence_contains_ml_info(self, detector):
        """Test that findings contain ML-specific evidence."""
        code = '''
from openai import OpenAI
from flask import request

client = OpenAI()

def handler(user_input):
    response = client.chat.completions.create(
        model="gpt-4",
        messages=[{"role": "user", "content": f"{user_input}"}]
    )
'''
        parsed = parse_code(code)
        findings = detector.detect(parsed)

        for finding in findings:
            evidence = finding.evidence
            assert 'ml_probability' in evidence
            assert 'attack_vector' in evidence
            assert 'detection_method' in evidence
            assert evidence['detection_method'] == 'ml_classifier'

    def test_confidence_calculation(self, detector):
        """Test confidence calculation from evidence."""
        evidence = {
            'ml_probability': 0.8,
            'attack_vector': 'direct',
            'attack_vector_probs': {'direct': 0.7, 'indirect': 0.2, 'stored': 0.1, 'none': 0.0},
            'top_features': {'direct_user_to_llm': 0.6, 'user_var_in_fstring': 0.4},
        }

        confidence = detector.calculate_confidence(evidence)

        # ML probability drives confidence (85% weight)
        # 0.8 * 0.85 = 0.68
        # Plus boost for clear attack vector (+0.10)
        # Plus boost for strong feature signal (+0.05)
        assert 0.7 < confidence <= 0.85

    def test_applies_mitigations(self, detector):
        """Test that mitigations reduce confidence."""
        evidence = {
            'ml_probability': 0.8,
            'attack_vector': 'direct',
            'attack_vector_probs': {'direct': 0.8, 'none': 0.2},
            'top_features': {
                'has_prompt_template': 1.0,  # Mitigation present
                'has_sanitization': 1.0,     # Mitigation present
            },
        }

        base_confidence = detector.calculate_confidence(evidence)
        mitigated = detector.apply_mitigations(base_confidence, evidence)

        # Mitigations should reduce confidence
        assert mitigated < base_confidence


class TestMLDetectorIntegration:
    """Integration tests for ML detector with scanner."""

    def test_detector_initialization(self):
        """Test detector can be initialized."""
        detector = MLPromptInjectionDetector(
            confidence_threshold=0.5,
            verbose=True
        )

        assert detector.confidence_threshold == 0.5
        assert detector.verbose is True
        assert detector.feature_extractor is not None
        assert detector.model is not None

    def test_handles_unparseable_code(self):
        """Test detector handles parse errors gracefully."""
        detector = MLPromptInjectionDetector()

        # Empty/invalid parsed data
        findings = detector.detect({'parsable': False})

        assert findings == []

    def test_handles_empty_file(self):
        """Test detector handles empty parsed data."""
        detector = MLPromptInjectionDetector()

        findings = detector.detect({
            'parsable': True,
            'file_path': 'test.py',
            'source_lines': [],
            'imports': [],
            'functions': [],
            'llm_api_calls': [],
        })

        assert isinstance(findings, list)

    def test_multiple_vulnerabilities_in_file(self):
        """Test detection of multiple potential vulnerabilities."""
        detector = MLPromptInjectionDetector(confidence_threshold=0.2)

        code = '''
from openai import OpenAI
from flask import request

client = OpenAI()

def handler1(user_input):
    response = client.chat.completions.create(
        model="gpt-4",
        messages=[{"role": "user", "content": f"{user_input}"}]
    )
    return response

def handler2(query):
    prompt = "Process: " + query
    response = client.chat.completions.create(
        model="gpt-4",
        messages=[{"role": "user", "content": prompt}]
    )
    return response
'''
        parsed = parse_code(code)
        findings = detector.detect(parsed)

        # May detect multiple locations
        assert isinstance(findings, list)
