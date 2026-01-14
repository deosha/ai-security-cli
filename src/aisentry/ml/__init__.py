"""
ML-Based Detection Module for AISentry.

This module provides machine learning-based detection capabilities:
- Feature extraction from Python AST
- ONNX model inference for prompt injection classification
- Training pipeline for model development
"""

from aisentry.ml.feature_extractor import FeatureExtractor, CodeFeatures
from aisentry.ml.model_inference import ONNXInference, MLPrediction

__all__ = [
    "FeatureExtractor",
    "CodeFeatures",
    "ONNXInference",
    "MLPrediction",
]
