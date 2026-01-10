"""
Evidence-Based Scoring Framework

Provides structured evidence collection and multi-signal scoring
to reduce false positives in security control detection.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List


class EvidenceStrength(Enum):
    """Strength of evidence for a security control"""
    STRONG = 3      # Import + instantiation + usage
    MEDIUM = 2      # Import + instantiation OR decorator + usage
    WEAK = 1        # Only string match or single signal
    NONE = 0        # No evidence

    def __ge__(self, other):
        """Enable >= comparison between EvidenceStrength values"""
        if self.__class__ is other.__class__:
            return self.value >= other.value
        return NotImplemented

    def __gt__(self, other):
        """Enable > comparison between EvidenceStrength values"""
        if self.__class__ is other.__class__:
            return self.value > other.value
        return NotImplemented

    def __le__(self, other):
        """Enable <= comparison between EvidenceStrength values"""
        if self.__class__ is other.__class__:
            return self.value <= other.value
        return NotImplemented

    def __lt__(self, other):
        """Enable < comparison between EvidenceStrength values"""
        if self.__class__ is other.__class__:
            return self.value < other.value
        return NotImplemented


@dataclass
class Evidence:
    """
    Represents evidence for a security control

    Tracks multiple signals to determine confidence:
    - Import statements (library is available)
    - Instantiations (library is initialized)
    - Function calls (library is used)
    - Decorators (framework integration)
    - Config assignments (security settings)
    """
    control_name: str
    strength: EvidenceStrength = EvidenceStrength.NONE
    signals: List[str] = field(default_factory=list)
    locations: List[int] = field(default_factory=list)  # Line numbers
    details: Dict[str, Any] = field(default_factory=dict)

    def add_signal(self, signal_type: str, line: int, detail: Any = None):
        """Add a detection signal"""
        self.signals.append(signal_type)
        self.locations.append(line)
        if detail:
            if signal_type not in self.details:
                self.details[signal_type] = []
            self.details[signal_type].append(detail)

    def calculate_strength(self) -> EvidenceStrength:
        """
        Calculate evidence strength based on signal types

        Strong: Multiple complementary signals (import + instantiation + call)
        Medium: Two signals (import + instantiation OR import + call)
        Weak: Single signal (only import or only string match)
        """
        signal_types = set(self.signals)

        # Strong evidence: Import + Instantiation + Usage
        if {'import', 'instantiation', 'call'}.issubset(signal_types):
            self.strength = EvidenceStrength.STRONG
        # Strong evidence: Import + Decorator (implies usage)
        elif {'import', 'decorator'}.issubset(signal_types):
            self.strength = EvidenceStrength.STRONG
        # Medium evidence: Two complementary signals
        elif len(signal_types & {'import', 'instantiation', 'call', 'decorator'}) >= 2:
            self.strength = EvidenceStrength.MEDIUM
        # Weak evidence: Single signal
        elif len(signal_types) >= 1:
            self.strength = EvidenceStrength.WEAK
        else:
            self.strength = EvidenceStrength.NONE

        return self.strength

    def is_confident(self) -> bool:
        """Check if evidence is strong enough to count as implemented"""
        self.calculate_strength()
        return self.strength in (EvidenceStrength.STRONG, EvidenceStrength.MEDIUM)


class EvidenceCollector:
    """
    Collects and analyzes evidence from parsed AST data

    Provides helper methods for scorers to gather structured evidence
    instead of relying on string matching.
    """

    def __init__(self, parsed_data: Dict[str, Any]):
        """
        Initialize evidence collector

        Args:
            parsed_data: Parsed AST data from PythonASTParser
        """
        self.parsed_data = parsed_data
        self.evidence_cache: Dict[str, Evidence] = {}

        # Extract structured data
        self.imports = {imp.get('module', ''): imp for imp in parsed_data.get('imports', [])}
        self.structured_calls = parsed_data.get('structured_calls', [])
        self.decorators = parsed_data.get('decorators', [])
        self.instantiations = parsed_data.get('instantiations', [])
        self.config_assignments = parsed_data.get('config_assignments', [])

    def collect_library_evidence(
        self,
        control_name: str,
        module_names: List[str],
        class_names: List[str] = None,
        function_names: List[str] = None
    ) -> Evidence:
        """
        Collect evidence for a security library

        Args:
            control_name: Name of the security control
            module_names: List of module names to check (e.g., ['hvac', 'azure.keyvault'])
            class_names: List of class names to check for instantiation
            function_names: List of function names to check for calls

        Returns:
            Evidence object with collected signals
        """
        if control_name in self.evidence_cache:
            return self.evidence_cache[control_name]

        evidence = Evidence(control_name=control_name)
        class_names = class_names or []
        function_names = function_names or []

        # Signal 1: Check imports
        for module_name in module_names:
            if self._has_import(module_name):
                import_data = self._get_import_data(module_name)
                evidence.add_signal('import', import_data.get('line', 0), module_name)

        # Signal 2: Check instantiations
        if class_names:
            for inst in self.instantiations:
                if inst.get('class_name') in class_names:
                    # Verify the module matches
                    inst_module = inst.get('module', '')
                    if any(m in inst_module or inst_module in m for m in module_names):
                        evidence.add_signal('instantiation', inst.get('line', 0), inst)

        # Signal 3: Check function calls
        if function_names:
            for call in self.structured_calls:
                if call.get('function') in function_names:
                    # Verify the module matches
                    call_module = call.get('module', '')
                    if any(m in call_module or call_module in m for m in module_names):
                        evidence.add_signal('call', call.get('line', 0), call)

        evidence.calculate_strength()
        self.evidence_cache[control_name] = evidence
        return evidence

    def collect_decorator_evidence(
        self,
        control_name: str,
        decorator_names: List[str],
        decorator_modules: List[str] = None
    ) -> Evidence:
        """
        Collect evidence for decorator-based controls (e.g., rate limiting)

        Args:
            control_name: Name of the security control
            decorator_names: List of decorator names (e.g., ['limit', 'ratelimit'])
            decorator_modules: Optional list of decorator modules (e.g., ['limiter'])

        Returns:
            Evidence object
        """
        if control_name in self.evidence_cache:
            return self.evidence_cache[control_name]

        evidence = Evidence(control_name=control_name)
        decorator_modules = decorator_modules or []

        for dec in self.decorators:
            dec_name = dec.get('decorator_name', '')
            dec_module = dec.get('decorator_module', '')

            # Check if decorator name matches
            if dec_name in decorator_names:
                # If module specified, verify it matches
                if not decorator_modules or dec_module in decorator_modules:
                    evidence.add_signal('decorator', dec.get('line', 0), dec)

                    # Also add import signal if decorator module was imported
                    if dec_module and self._has_import(dec_module):
                        evidence.add_signal('import', dec.get('line', 0), dec_module)

        evidence.calculate_strength()
        self.evidence_cache[control_name] = evidence
        return evidence

    def collect_config_evidence(
        self,
        control_name: str,
        config_keys: List[str],
        required_functions: List[str] = None
    ) -> Evidence:
        """
        Collect evidence for configuration-based controls

        Args:
            control_name: Name of the security control
            config_keys: Keys to look for (e.g., ['api_key', 'secret'])
            required_functions: Functions that should be used (e.g., ['os.getenv'])

        Returns:
            Evidence object
        """
        if control_name in self.evidence_cache:
            return self.evidence_cache[control_name]

        evidence = Evidence(control_name=control_name)
        required_functions = required_functions or []

        for config in self.config_assignments:
            # Check dict keys
            if config.get('target_type') == 'dict':
                dict_keys = config.get('dict_keys', [])
                if any(key.lower() in [k.lower() for k in config_keys] for key in dict_keys):
                    evidence.add_signal('config', config.get('line', 0), config)

            # Check subscript assignments
            elif config.get('target_type') == 'subscript':
                config_key = config.get('key', '')
                if any(k.lower() in config_key.lower() for k in config_keys):
                    # Check if using secure function
                    if required_functions:
                        value = config.get('value', '')
                        if any(fn in value for fn in required_functions):
                            evidence.add_signal('config', config.get('line', 0), config)
                    else:
                        evidence.add_signal('config', config.get('line', 0), config)

            # Check call with security keywords
            elif config.get('target_type') == 'call_with_secrets':
                evidence.add_signal('config', config.get('line', 0), config)

        evidence.calculate_strength()
        self.evidence_cache[control_name] = evidence
        return evidence

    def has_multi_signal_evidence(self, control_name: str) -> bool:
        """
        Check if control has multi-signal evidence (reduces false positives)

        Returns True only if at least 2 different signal types detected
        """
        if control_name not in self.evidence_cache:
            return False

        evidence = self.evidence_cache[control_name]
        signal_types = set(evidence.signals)
        return len(signal_types) >= 2

    def _has_import(self, module_name: str) -> bool:
        """Check if module is imported (exact or partial match)"""
        for imp_module in self.imports.keys():
            if module_name in imp_module or imp_module in module_name:
                return True
        return False

    def _get_import_data(self, module_name: str) -> Dict[str, Any]:
        """Get import data for a module"""
        for imp_module, imp_data in self.imports.items():
            if module_name in imp_module or imp_module in module_name:
                return imp_data
        return {}

    def get_evidence_summary(self) -> Dict[str, Dict[str, Any]]:
        """
        Get summary of all collected evidence

        Returns:
            Dictionary mapping control names to evidence summaries
        """
        summary = {}
        for control_name, evidence in self.evidence_cache.items():
            summary[control_name] = {
                'strength': evidence.strength.name,
                'is_confident': evidence.is_confident(),
                'signal_count': len(evidence.signals),
                'signal_types': list(set(evidence.signals)),
                'locations': evidence.locations
            }
        return summary
