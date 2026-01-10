"""Static security detectors for OWASP LLM Top 10"""

from .base_detector import BaseDetector
from .llm01_prompt_injection import PromptInjectionDetector
from .llm02_insecure_output import InsecureOutputDetector
from .llm03_training_poisoning import TrainingPoisoningDetector
from .llm04_model_dos import ModelDOSDetector
from .llm05_supply_chain import SupplyChainDetector
from .llm06_secrets import SecretsDetector
from .llm07_insecure_plugin import InsecurePluginDetector
from .llm08_excessive_agency import ExcessiveAgencyDetector
from .llm09_overreliance import OverrelianceDetector
from .llm10_model_theft import ModelTheftDetector

# All available static detectors
ALL_DETECTORS = [
    PromptInjectionDetector,
    InsecureOutputDetector,
    TrainingPoisoningDetector,
    ModelDOSDetector,
    SupplyChainDetector,
    SecretsDetector,
    InsecurePluginDetector,
    ExcessiveAgencyDetector,
    OverrelianceDetector,
    ModelTheftDetector,
]

# Detector ID to class mapping
DETECTOR_MAP = {
    "LLM01": PromptInjectionDetector,
    "LLM02": InsecureOutputDetector,
    "LLM03": TrainingPoisoningDetector,
    "LLM04": ModelDOSDetector,
    "LLM05": SupplyChainDetector,
    "LLM06": SecretsDetector,
    "LLM07": InsecurePluginDetector,
    "LLM08": ExcessiveAgencyDetector,
    "LLM09": OverrelianceDetector,
    "LLM10": ModelTheftDetector,
}

__all__ = [
    "BaseDetector",
    "PromptInjectionDetector",
    "InsecureOutputDetector",
    "TrainingPoisoningDetector",
    "ModelDOSDetector",
    "SupplyChainDetector",
    "SecretsDetector",
    "InsecurePluginDetector",
    "ExcessiveAgencyDetector",
    "OverrelianceDetector",
    "ModelTheftDetector",
    "ALL_DETECTORS",
    "DETECTOR_MAP",
]
