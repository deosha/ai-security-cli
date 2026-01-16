"""
ML-Based Prompt Injection Detector.

Uses machine learning to detect prompt injection vulnerabilities,
complementing the pattern-based LLM01 detector.

Features:
- 45-dimensional feature vector from AST analysis
- ONNX model inference for fast prediction
- Attack vector classification (direct, indirect, stored)
- Heuristic fallback when ONNX Runtime unavailable
"""

import logging
from typing import Any, Dict, List, Optional

from aisentry.models.finding import Finding, Severity
from aisentry.static_detectors.base_detector import BaseDetector
from aisentry.ml.feature_extractor import FeatureExtractor
from aisentry.ml.model_inference import ONNXInference, MLPrediction

logger = logging.getLogger(__name__)


class MLPromptInjectionDetector(BaseDetector):
    """
    ML-based detector for prompt injection vulnerabilities.

    Extracts features from Python AST and uses trained classifier
    to predict vulnerability probability and attack vector type.
    """

    detector_id = "ML_LLM01"
    detector_name = "ML-Based Prompt Injection"

    # Lower threshold to catch more potential issues
    default_confidence_threshold = 0.55

    # Attack vector descriptions
    ATTACK_VECTOR_DESCRIPTIONS = {
        "direct": "Direct prompt injection: User input is directly included in the LLM prompt",
        "indirect": "Indirect prompt injection: Malicious instructions from external data sources",
        "stored": "Stored prompt injection: Malicious prompts stored in database/files for later execution",
        "none": "No attack vector detected",
    }

    def __init__(
        self,
        confidence_threshold: Optional[float] = None,
        verbose: bool = False,
        model_path: Optional[str] = None
    ):
        """
        Initialize ML detector.

        Args:
            confidence_threshold: Minimum confidence to report
            verbose: Enable debug logging
            model_path: Optional path to custom ONNX model
        """
        super().__init__(confidence_threshold, verbose)
        self.feature_extractor = FeatureExtractor()
        self.model = ONNXInference.get_instance()

    def _gather_potential_findings(self, parsed_data: Dict[str, Any]) -> List[Finding]:
        """
        Gather potential findings using ML prediction.

        Steps:
        1. Extract features from parsed code
        2. Run ML prediction
        3. Locate specific vulnerable locations
        4. Generate findings for each location
        """
        findings = []
        file_path = parsed_data.get('file_path', '')
        source_lines = parsed_data.get('source_lines', [])

        # Extract features
        code_features = self.feature_extractor.extract(parsed_data)

        # Run ML prediction
        prediction = self.model.predict(
            code_features.features,
            code_features.feature_names
        )

        # Only proceed if model indicates potential vulnerability
        if prediction.vulnerability_probability < 0.3:
            return findings

        # Locate specific vulnerable code locations
        vulnerable_locations = self._locate_vulnerabilities(
            parsed_data,
            prediction,
            code_features
        )

        # Create finding for each location
        for loc in vulnerable_locations:
            finding = self._create_finding(
                location=loc,
                prediction=prediction,
                file_path=file_path,
                source_lines=source_lines,
                code_features=code_features
            )
            findings.append(finding)

        return findings

    def _locate_vulnerabilities(
        self,
        parsed_data: Dict[str, Any],
        prediction: MLPrediction,
        features: Any
    ) -> List[Dict[str, Any]]:
        """
        Locate specific lines/functions that are vulnerable.

        Uses feature importance and code patterns to pinpoint
        the most likely vulnerable locations.
        """
        locations = []
        llm_calls = parsed_data.get('llm_api_calls', [])
        functions = parsed_data.get('functions', [])
        source_lines = parsed_data.get('source_lines', [])

        # Get important features to guide location search
        important_features = prediction.feature_importance

        # Priority 1: LLM API calls with user input
        for call in llm_calls:
            line = call.get('line', 0)
            func_name = call.get('function', 'unknown')

            # Check if this call has user input indicators
            call_context = self._get_context(source_lines, line, 3)
            has_user_input = any(
                pattern in call_context.lower()
                for pattern in ['user', 'input', 'query', 'message', 'request', 'prompt']
            )

            if has_user_input or important_features.get('direct_user_to_llm', 0) > 0.3:
                locations.append({
                    'line': line,
                    'function': func_name,
                    'type': 'llm_call',
                    'snippet': call_context,
                    'reason': 'LLM call with potential user input'
                })

        # Priority 2: Functions with user input parameters and LLM usage
        for func in functions:
            func_name = func.get('name', 'unknown')
            func_line = func.get('line', 0)
            args = func.get('args', [])

            # Check for user input parameter names
            has_user_param = any(
                (arg.lower() if isinstance(arg, str) else arg.get('name', '').lower())
                in {'user_input', 'query', 'message', 'prompt', 'text', 'content', 'input'}
                for arg in args
            )

            # Check if function contains LLM calls
            func_end = func.get('end_line', func_line + 20)
            has_llm = any(
                func_line <= call.get('line', 0) <= func_end
                for call in llm_calls
            )

            if has_user_param and has_llm:
                locations.append({
                    'line': func_line,
                    'function': func_name,
                    'type': 'vulnerable_function',
                    'snippet': self._get_context(source_lines, func_line, 5),
                    'reason': 'Function with user input parameter and LLM call'
                })

        # Priority 3: String operations that might be prompt construction
        string_ops = parsed_data.get('string_operations', [])
        for op in string_ops:
            if op.get('type') == 'f-string':
                line = op.get('line', 0)
                content = str(op.get('content', ''))

                # Check if f-string contains user variables
                if any(var in content.lower() for var in ['user', 'input', 'query', 'message']):
                    locations.append({
                        'line': line,
                        'function': 'f-string',
                        'type': 'prompt_construction',
                        'snippet': self._get_context(source_lines, line, 2),
                        'reason': 'F-string potentially building prompt with user input'
                    })

        # If no specific locations found, use file-level finding
        if not locations and prediction.vulnerability_probability > 0.5:
            locations.append({
                'line': 1,
                'function': 'module',
                'type': 'file_level',
                'snippet': '\n'.join(source_lines[:10]) if source_lines else '',
                'reason': 'ML model detected vulnerability patterns in file'
            })

        return locations

    def _create_finding(
        self,
        location: Dict[str, Any],
        prediction: MLPrediction,
        file_path: str,
        source_lines: List[str],
        code_features: Any
    ) -> Finding:
        """Create a Finding from ML prediction and location."""

        attack_vector = prediction.attack_vector
        attack_desc = self.ATTACK_VECTOR_DESCRIPTIONS.get(attack_vector, "Unknown attack vector")

        # Build title based on attack vector
        if attack_vector == "none":
            title = "Potential prompt injection vulnerability (ML-detected)"
        else:
            title = f"Potential {attack_vector} prompt injection (ML-detected)"

        # Build description
        description = self._build_description(prediction, location, attack_desc)

        # Build recommendation
        recommendation = self._get_recommendation(attack_vector)

        # Determine severity based on probability and attack vector
        severity = self._map_severity(prediction.vulnerability_probability, attack_vector)

        return Finding(
            id=f"ML_LLM01_{file_path}_{location['line']}",
            category="LLM01: Prompt Injection (ML-Detected)",
            severity=severity,
            confidence=0.0,  # Will be calculated by calculate_confidence
            title=title,
            description=description,
            file_path=file_path,
            line_number=location['line'],
            code_snippet=location.get('snippet', ''),
            recommendation=recommendation,
            cwe_id="CWE-77",  # Command Injection (closest match)
            owasp_category="LLM01",
            evidence={
                'ml_probability': prediction.vulnerability_probability,
                'attack_vector': attack_vector,
                'attack_vector_probs': prediction.attack_vector_probabilities,
                'top_features': prediction.feature_importance,
                'location_type': location.get('type', 'unknown'),
                'location_reason': location.get('reason', ''),
                'detection_method': 'ml_classifier',
            }
        )

    def _build_description(
        self,
        prediction: MLPrediction,
        location: Dict[str, Any],
        attack_desc: str
    ) -> str:
        """Build detailed finding description."""
        prob = prediction.vulnerability_probability
        attack_vector = prediction.attack_vector

        desc = [
            f"ML model detected prompt injection vulnerability with {prob:.0%} confidence.",
            "",
            f"**Attack Vector:** {attack_desc}",
            "",
            f"**Location:** {location.get('reason', 'N/A')}",
            "",
            "**Top Contributing Factors:**",
        ]

        for feature, importance in list(prediction.feature_importance.items())[:5]:
            if importance > 0.1:
                desc.append(f"  - {feature.replace('_', ' ').title()}: {importance:.0%}")

        if attack_vector == "direct":
            desc.extend([
                "",
                "**Risk:** Direct injection allows attackers to manipulate LLM behavior "
                "by crafting malicious input that becomes part of the prompt."
            ])
        elif attack_vector == "indirect":
            desc.extend([
                "",
                "**Risk:** Indirect injection allows attackers to embed malicious instructions "
                "in external data sources (websites, documents) that are processed by the LLM."
            ])
        elif attack_vector == "stored":
            desc.extend([
                "",
                "**Risk:** Stored injection persists malicious prompts in storage (database, files) "
                "that execute when later retrieved and used in LLM prompts."
            ])

        return "\n".join(desc)

    def _get_recommendation(self, attack_vector: str) -> str:
        """Get remediation recommendation based on attack vector."""
        base = (
            "1. Use structured prompt templates (e.g., LangChain PromptTemplate) to separate "
            "user input from instructions.\n"
            "2. Implement input validation and sanitization.\n"
            "3. Use system prompts to establish boundaries.\n"
        )

        specific = {
            "direct": (
                "4. Consider using input length limits.\n"
                "5. Implement output validation to detect instruction following.\n"
                "6. Use content filtering on both input and output."
            ),
            "indirect": (
                "4. Validate and sanitize all external data before including in prompts.\n"
                "5. Use data isolation - don't mix untrusted content with instructions.\n"
                "6. Consider using separate LLM calls for processing external data."
            ),
            "stored": (
                "4. Sanitize data before storage.\n"
                "5. Validate stored prompts before execution.\n"
                "6. Implement access controls on prompt storage."
            ),
        }

        return base + specific.get(attack_vector, "4. Review and secure all prompt construction paths.")

    def _map_severity(self, probability: float, attack_vector: str) -> Severity:
        """Map ML probability and attack vector to severity."""
        # Base severity on probability
        if probability >= 0.85:
            base_severity = Severity.CRITICAL
        elif probability >= 0.7:
            base_severity = Severity.HIGH
        elif probability >= 0.55:
            base_severity = Severity.MEDIUM
        else:
            base_severity = Severity.LOW

        # Adjust based on attack vector
        if attack_vector == "direct" and base_severity == Severity.HIGH:
            return Severity.CRITICAL  # Direct injection is most dangerous
        elif attack_vector == "none" and base_severity != Severity.LOW:
            return Severity.MEDIUM  # Uncertain attack vector

        return base_severity

    def _get_context(self, source_lines: List[str], line: int, context: int = 3) -> str:
        """Get code context around a line."""
        if not source_lines:
            return ""

        start = max(0, line - context - 1)
        end = min(len(source_lines), line + context)

        return '\n'.join(source_lines[start:end])

    def calculate_confidence(self, evidence: Dict[str, Any]) -> float:
        """
        Calculate confidence score based on evidence.

        Primary driver is ML probability, with adjustments for:
        - Attack vector clarity
        - Feature importance distribution
        """
        ml_prob = evidence.get('ml_probability', 0.5)

        # ML probability is primary confidence driver (85% weight)
        confidence = ml_prob * 0.85

        # Boost for clear attack vector
        attack_probs = evidence.get('attack_vector_probs', {})
        if attack_probs:
            max_attack_prob = max(
                prob for vec, prob in attack_probs.items() if vec != 'none'
            )
            if max_attack_prob > 0.6:
                confidence += 0.10

        # Boost for strong feature signals
        top_features = evidence.get('top_features', {})
        if top_features:
            top_importance = max(top_features.values())
            if top_importance > 0.5:
                confidence += 0.05

        return max(0.0, min(1.0, confidence))

    def apply_mitigations(self, confidence: float, evidence: Dict[str, Any]) -> float:
        """Apply mitigation-based confidence demotions."""
        # Check if mitigations were detected in features
        top_features = evidence.get('top_features', {})

        # Reduce confidence if mitigations present
        if 'has_prompt_template' in top_features and top_features['has_prompt_template'] > 0:
            confidence -= 0.15

        if 'has_sanitization' in top_features and top_features['has_sanitization'] > 0:
            confidence -= 0.10

        if 'has_input_validation' in top_features and top_features['has_input_validation'] > 0:
            confidence -= 0.10

        return max(0.0, confidence)
