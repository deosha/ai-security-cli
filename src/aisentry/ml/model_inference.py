"""
ONNX Model Inference for Prompt Injection Detection.

Provides lightweight model inference using ONNX Runtime for:
- Binary classification: vulnerable vs safe
- Multi-class classification: attack vector type (direct, indirect, stored)

Model loading is lazy and thread-safe.
"""

import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional
import numpy as np

logger = logging.getLogger(__name__)


@dataclass
class MLPrediction:
    """Result of ML model prediction."""
    is_vulnerable: bool
    vulnerability_probability: float  # 0.0-1.0
    attack_vector: str  # "direct", "indirect", "stored", "none"
    attack_vector_probabilities: Dict[str, float]
    feature_importance: Dict[str, float]  # Top contributing features


class ONNXInference:
    """
    ONNX Runtime inference wrapper for prompt injection detection.

    Handles model loading, inference, and result interpretation.
    Falls back to heuristic scoring if ONNX Runtime is not available.
    """

    # Attack vector labels
    ATTACK_VECTORS = ["none", "direct", "indirect", "stored"]

    # Default model paths (relative to package)
    DEFAULT_ONNX_PATH = Path(__file__).parent / "models" / "prompt_injection_v1.onnx"
    DEFAULT_PICKLE_PATH = Path(__file__).parent / "models" / "prompt_injection_v1.pkl"

    _instance: Optional["ONNXInference"] = None
    _ort_available: Optional[bool] = None

    def __init__(self, model_path: Optional[Path] = None):
        """
        Initialize inference.

        Args:
            model_path: Path to model file (ONNX or pickle). If None, uses default.
        """
        self.model_path = model_path
        self._session = None
        self._pickle_model = None
        self._use_heuristics = False

        # Find default model if not specified
        if self.model_path is None:
            if self.DEFAULT_PICKLE_PATH.exists():
                self.model_path = self.DEFAULT_PICKLE_PATH
            elif self.DEFAULT_ONNX_PATH.exists():
                self.model_path = self.DEFAULT_ONNX_PATH
            else:
                self.model_path = self.DEFAULT_ONNX_PATH  # Will fall back to heuristics

        # Check ONNX Runtime availability
        if ONNXInference._ort_available is None:
            import importlib.util
            ONNXInference._ort_available = importlib.util.find_spec("onnxruntime") is not None
            if not ONNXInference._ort_available:
                logger.info("ONNX Runtime not available")

    @classmethod
    def get_instance(cls, model_path: Optional[Path] = None) -> "ONNXInference":
        """Get singleton instance of inference engine."""
        if cls._instance is None:
            cls._instance = cls(model_path)
        return cls._instance

    @classmethod
    def load_model(cls, model_name: str) -> "ONNXInference":
        """
        Load a model by name.

        Args:
            model_name: Model filename (without path)

        Returns:
            ONNXInference instance
        """
        model_path = Path(__file__).parent / "models" / model_name
        return cls(model_path)

    def _load_session(self) -> bool:
        """
        Lazily load model (ONNX or pickle).

        Returns:
            True if model loaded successfully, False otherwise
        """
        if self._session is not None or self._pickle_model is not None:
            return True

        if not self.model_path.exists():
            logger.warning(f"Model file not found: {self.model_path}")
            self._use_heuristics = True
            return False

        # Check if it's a pickle model
        if str(self.model_path).endswith('.pkl'):
            return self._load_pickle_model()

        # Try ONNX
        if not ONNXInference._ort_available:
            self._use_heuristics = True
            return False

        try:
            import onnxruntime as ort

            # Configure session options
            sess_options = ort.SessionOptions()
            sess_options.graph_optimization_level = ort.GraphOptimizationLevel.ORT_ENABLE_ALL
            sess_options.intra_op_num_threads = 1  # Single thread for predictable latency

            self._session = ort.InferenceSession(
                str(self.model_path),
                sess_options=sess_options,
                providers=['CPUExecutionProvider']
            )

            logger.info(f"Loaded ONNX model from {self.model_path}")
            return True

        except Exception as e:
            logger.warning(f"Failed to load ONNX model: {e}")
            self._use_heuristics = True
            return False

    def _load_pickle_model(self) -> bool:
        """Load sklearn/lightgbm model from pickle file."""
        try:
            import pickle
            with open(self.model_path, 'rb') as f:
                self._pickle_model = pickle.load(f)
            logger.info(f"Loaded pickle model from {self.model_path}")
            return True
        except Exception as e:
            logger.warning(f"Failed to load pickle model: {e}")
            self._use_heuristics = True
            return False

    def predict(
        self,
        features: np.ndarray,
        feature_names: Optional[List[str]] = None
    ) -> MLPrediction:
        """
        Run prediction on feature vector.

        Args:
            features: 1D numpy array of features (45 elements)
            feature_names: Optional list of feature names for importance

        Returns:
            MLPrediction with vulnerability assessment
        """
        # Ensure features is 2D
        if features.ndim == 1:
            features = features.reshape(1, -1)

        # Load model if needed
        self._load_session()

        # Try pickle model first (sklearn/lightgbm)
        if self._pickle_model is not None:
            return self._pickle_predict(features, feature_names)

        # Try ONNX inference
        if self._session is not None:
            return self._onnx_predict(features, feature_names)

        # Fallback to heuristic scoring
        return self._heuristic_predict(features, feature_names)

    def _pickle_predict(
        self,
        features: np.ndarray,
        feature_names: Optional[List[str]] = None
    ) -> MLPrediction:
        """Run prediction using sklearn/lightgbm pickle model."""
        try:
            vuln_clf = self._pickle_model.get('vulnerability_clf')
            attack_clf = self._pickle_model.get('attack_type_clf')
            model_feature_names = self._pickle_model.get('feature_names', [])

            # Binary vulnerability prediction
            vuln_proba = vuln_clf.predict_proba(features)[0]
            vuln_prob = float(vuln_proba[1]) if len(vuln_proba) > 1 else float(vuln_proba[0])

            # Attack type prediction (for vulnerable samples)
            if vuln_prob > 0.5 and attack_clf is not None:
                attack_proba = attack_clf.predict_proba(features)[0]
                # Pad with zeros if needed
                attack_probs = np.zeros(4)
                for i, p in enumerate(attack_proba):
                    if i < len(attack_probs):
                        attack_probs[i] = p
            else:
                attack_probs = np.array([1.0, 0.0, 0.0, 0.0])

            attack_idx = int(np.argmax(attack_probs))
            attack_vector = self.ATTACK_VECTORS[attack_idx]

            # Feature importance from model
            importance = {}
            if hasattr(vuln_clf, 'feature_importances_') and model_feature_names:
                importances = vuln_clf.feature_importances_
                indices = np.argsort(importances)[::-1][:10]
                for i in indices:
                    if i < len(model_feature_names):
                        importance[model_feature_names[i]] = float(importances[i])

            return MLPrediction(
                is_vulnerable=vuln_prob > 0.5,
                vulnerability_probability=vuln_prob,
                attack_vector=attack_vector if vuln_prob > 0.5 else "none",
                attack_vector_probabilities={
                    vec: float(prob) for vec, prob in zip(self.ATTACK_VECTORS, attack_probs)
                },
                feature_importance=importance
            )

        except Exception as e:
            logger.warning(f"Pickle model inference failed: {e}, using heuristics")
            return self._heuristic_predict(features, feature_names)

    def _onnx_predict(
        self,
        features: np.ndarray,
        feature_names: Optional[List[str]] = None
    ) -> MLPrediction:
        """Run ONNX model inference."""
        try:
            # Get input name
            input_name = self._session.get_inputs()[0].name

            # Run inference
            outputs = self._session.run(None, {input_name: features.astype(np.float32)})

            # Parse outputs (assuming model outputs: [vuln_prob, attack_probs])
            if len(outputs) >= 2:
                vuln_prob = float(outputs[0][0])
                attack_probs = outputs[1][0]
            else:
                # Single output model
                vuln_prob = float(outputs[0][0])
                attack_probs = np.array([1 - vuln_prob, vuln_prob * 0.6, vuln_prob * 0.3, vuln_prob * 0.1])

            # Determine attack vector
            attack_idx = int(np.argmax(attack_probs))
            attack_vector = self.ATTACK_VECTORS[attack_idx]

            # Calculate feature importance (simple approach: feature magnitude)
            importance = self._calculate_feature_importance(features[0], feature_names)

            return MLPrediction(
                is_vulnerable=vuln_prob > 0.5,
                vulnerability_probability=vuln_prob,
                attack_vector=attack_vector if vuln_prob > 0.5 else "none",
                attack_vector_probabilities={
                    vec: float(prob) for vec, prob in zip(self.ATTACK_VECTORS, attack_probs)
                },
                feature_importance=importance
            )

        except Exception as e:
            logger.warning(f"ONNX inference failed: {e}, using heuristics")
            return self._heuristic_predict(features, feature_names)

    def _heuristic_predict(
        self,
        features: np.ndarray,
        feature_names: Optional[List[str]] = None
    ) -> MLPrediction:
        """
        Heuristic-based prediction when ONNX is unavailable.

        Uses weighted feature scoring to approximate ML model behavior.
        """
        features_1d = features[0] if features.ndim > 1 else features

        # Define feature weights for vulnerability scoring
        # These weights are derived from domain knowledge about prompt injection patterns
        weights = np.array([
            # User Input Indicators (indices 0-9) - strong positive signals
            0.3,   # has_request_get
            0.25,  # has_input_call
            0.15,  # has_sys_argv
            0.1,   # has_environ_access
            0.4,   # user_input_var_count
            0.35,  # user_param_in_func_args
            0.2,   # has_form_data
            0.25,  # has_json_body
            0.2,   # has_query_params
            0.15,  # has_file_upload

            # LLM API Patterns (indices 10-21) - moderate positive signals
            0.5,   # llm_call_count
            0.1,   # has_openai_import
            0.1,   # has_anthropic_import
            0.1,   # has_langchain_import
            0.15,  # uses_chat_completion
            0.15,  # uses_messages_api
            0.4,   # prompt_var_in_llm_call - strong signal
            0.1,   # system_prompt_present
            0.05,  # has_streaming
            0.05,  # uses_function_calling
            0.2,   # has_multiple_llm_calls
            0.25,  # llm_in_loop

            # String Operations (indices 22-29) - moderate positive signals
            0.3,   # fstring_count
            0.25,  # format_call_count
            0.2,   # concat_count
            0.45,  # string_in_llm_arg - strong signal
            0.5,   # user_var_in_fstring - very strong signal
            0.1,   # template_literal_count
            0.05,  # raw_string_in_prompt
            0.1,   # multiline_string_count

            # Data Flow Indicators (indices 30-39) - strong positive signals
            0.6,   # direct_user_to_llm - very strong
            0.5,   # single_hop_user_to_llm
            0.4,   # two_hop_user_to_llm
            0.3,   # function_returns_user_data
            0.25,  # cross_function_flow
            0.2,   # assignment_chain_length_max
            0.15,  # variable_reuse_count
            0.5,   # llm_output_to_sink - strong signal
            0.1,   # data_transformation_count
            0.2,   # loop_with_user_data

            # Mitigation Indicators (indices 40-44) - negative signals
            -0.25, # has_input_validation
            -0.3,  # has_sanitization
            -0.35, # has_prompt_template - strong mitigation
            -0.2,  # has_allowlist_check
            -0.2,  # uses_structured_output
        ])

        # Calculate weighted score
        raw_score = np.dot(features_1d, weights)

        # Normalize to probability (sigmoid-like)
        # Adjusted so typical vulnerable code scores ~0.6-0.8
        vuln_prob = 1.0 / (1.0 + np.exp(-2.0 * (raw_score - 0.5)))
        vuln_prob = float(np.clip(vuln_prob, 0.0, 1.0))

        # Determine attack vector based on feature patterns
        attack_probs = self._estimate_attack_vector(features_1d)

        attack_idx = int(np.argmax(attack_probs))
        attack_vector = self.ATTACK_VECTORS[attack_idx]

        # Calculate feature importance
        importance = self._calculate_feature_importance(features_1d, feature_names, weights)

        return MLPrediction(
            is_vulnerable=vuln_prob > 0.5,
            vulnerability_probability=vuln_prob,
            attack_vector=attack_vector if vuln_prob > 0.5 else "none",
            attack_vector_probabilities={
                vec: float(prob) for vec, prob in zip(self.ATTACK_VECTORS, attack_probs)
            },
            feature_importance=importance
        )

    def _estimate_attack_vector(self, features: np.ndarray) -> np.ndarray:
        """Estimate attack vector probabilities from features."""
        # Default: no attack
        probs = np.array([0.7, 0.1, 0.15, 0.05])  # none, direct, indirect, stored

        # Direct injection indicators
        direct_score = (
            features[0] * 0.3 +  # has_request_get
            features[30] * 0.4 + # direct_user_to_llm
            features[24] * 0.3   # user_var_in_fstring
        )

        # Indirect injection indicators (through LLM output)
        indirect_score = (
            features[37] * 0.5 + # llm_output_to_sink
            features[10] * 0.3 + # llm_call_count
            features[34] * 0.2   # cross_function_flow
        )

        # Stored injection indicators (from database/file)
        stored_score = (
            features[3] * 0.3 +  # has_environ_access
            features[9] * 0.4 +  # has_file_upload
            features[8] * 0.3    # has_query_params
        )

        # Normalize to probabilities
        total = direct_score + indirect_score + stored_score + 0.1
        if total > 0.3:
            probs[0] = 0.1  # Reduce "none" probability
            probs[1] = direct_score / total * 0.9
            probs[2] = indirect_score / total * 0.9
            probs[3] = stored_score / total * 0.9

        # Ensure they sum to 1
        probs = probs / probs.sum()

        return probs

    def _calculate_feature_importance(
        self,
        features: np.ndarray,
        feature_names: Optional[List[str]] = None,
        weights: Optional[np.ndarray] = None
    ) -> Dict[str, float]:
        """Calculate feature importance based on contribution to prediction."""
        if feature_names is None:
            feature_names = [f"feature_{i}" for i in range(len(features))]

        if weights is None:
            # Use feature magnitude as proxy for importance
            importance = np.abs(features)
        else:
            # Use weighted contribution
            importance = np.abs(features * weights)

        # Normalize
        if importance.max() > 0:
            importance = importance / importance.max()

        # Return top 10 features
        indexed = list(zip(feature_names, importance))
        sorted_features = sorted(indexed, key=lambda x: x[1], reverse=True)

        return {name: float(val) for name, val in sorted_features[:10]}

    def is_available(self) -> bool:
        """Check if ML inference is available (ONNX or model exists)."""
        return ONNXInference._ort_available or self._use_heuristics
