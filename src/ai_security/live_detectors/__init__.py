"""Live security detectors for LLM testing"""

from .adversarial_inputs import AdversarialInputsDetector
from .base_live_detector import BaseLiveDetector, TestPayload
from .behavioral_anomaly import BehavioralAnomalyDetector
from .bias import BiasDetector
from .data_leakage import DataLeakageDetector
from .dos import DosDetector
from .hallucination import HallucinationDetector
from .jailbreak import JailbreakDetector
from .model_extraction import ModelExtractionDetector
from .output_manipulation import OutputManipulationDetector
from .prompt_injection import PromptInjectionDetector
from .supply_chain import SupplyChainDetector

__all__ = [
    # Base classes
    "BaseLiveDetector",
    "TestPayload",
    # Detectors
    "PromptInjectionDetector",
    "JailbreakDetector",
    "DataLeakageDetector",
    "HallucinationDetector",
    "DosDetector",
    "BiasDetector",
    "ModelExtractionDetector",
    "AdversarialInputsDetector",
    "OutputManipulationDetector",
    "SupplyChainDetector",
    "BehavioralAnomalyDetector",
    # Registry helpers
    "DETECTOR_REGISTRY",
    "get_detector",
    "get_all_detectors",
    "get_detector_ids",
]

# Mapping of detector IDs to detector classes
DETECTOR_REGISTRY = {
    "PI": PromptInjectionDetector,
    "JB": JailbreakDetector,
    "DL": DataLeakageDetector,
    "HAL": HallucinationDetector,
    "DOS": DosDetector,
    "BIAS": BiasDetector,
    "MEX": ModelExtractionDetector,
    "ADV": AdversarialInputsDetector,
    "OM": OutputManipulationDetector,
    "SC": SupplyChainDetector,
    "BA": BehavioralAnomalyDetector,
}


def get_detector(detector_id: str):
    """Get detector class by ID."""
    return DETECTOR_REGISTRY.get(detector_id.upper())


def get_all_detectors():
    """Get all detector classes."""
    return list(DETECTOR_REGISTRY.values())


def get_detector_ids():
    """Get all detector IDs."""
    return list(DETECTOR_REGISTRY.keys())
