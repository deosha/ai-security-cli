"""
Data Privacy control detectors.
"""

from typing import List

from ..models import ControlEvidence, ControlLevel, EvidenceItem
from .base_control import BaseControlDetector, ControlCategory


class PIIDetectionDetector(BaseControlDetector):
    """Detect PII detection controls."""

    control_id = "DP-01"
    control_name = "PII Detection"
    category = "data_privacy"
    description = "Detection of personally identifiable information in data"
    recommendations = [
        "Use Presidio or similar for PII detection",
        "Implement NER-based PII detection with spaCy",
        "Add custom regex patterns for domain-specific PII",
    ]

    def detect(self) -> ControlEvidence:
        evidence_items: List[EvidenceItem] = []

        # Check for PII detection libraries
        pii_libs = [
            "presidio-analyzer", "presidio-anonymizer", "scrubadub",
            "pii-codex", "spacy", "flair"
        ]
        for lib in pii_libs:
            if self.deps.has_package(lib):
                evidence_items.append(self._evidence_from_dependency(
                    "", lib, f"PII detection library {lib} found"
                ))

        # Check for PII-related imports
        pii_imports = ["presidio", "scrubadub", "pii"]
        for pattern in pii_imports:
            matches = self.ast.find_imports(pattern)
            for match in matches[:2]:
                evidence_items.append(self._evidence_from_import(
                    match.file_path, match.line_number, match.name,
                    f"PII library imported: {match.name}"
                ))

        # Check for PII detection function calls
        detect_patterns = [
            "detect_pii", "find_pii", "analyze", "scan_pii",
            "identify_pii", "extract_entities"
        ]
        for pattern in detect_patterns:
            matches = self.ast.find_function_calls(pattern)
            for match in matches[:2]:
                evidence_items.append(self._evidence_from_ast(
                    match.file_path, match.line_number, match.snippet,
                    f"PII detection function: {match.name}"
                ))

        # Determine level
        if not evidence_items:
            level = ControlLevel.NONE
        elif len(evidence_items) >= 4:
            level = ControlLevel.ADVANCED
        elif len(evidence_items) >= 2:
            level = ControlLevel.INTERMEDIATE
        else:
            level = ControlLevel.BASIC

        return self._create_evidence(
            detected=len(evidence_items) > 0,
            level=level,
            evidence_items=evidence_items,
        )


class DataRedactionDetector(BaseControlDetector):
    """Detect data redaction controls."""

    control_id = "DP-02"
    control_name = "Data Redaction"
    category = "data_privacy"
    description = "Redaction or masking of sensitive data"
    recommendations = [
        "Implement data masking for sensitive fields",
        "Use tokenization for reversible anonymization",
        "Apply redaction before logging or storage",
    ]

    def detect(self) -> ControlEvidence:
        evidence_items: List[EvidenceItem] = []

        # Check for redaction function calls
        redact_patterns = [
            "redact", "mask", "anonymize", "tokenize",
            "obfuscate", "scrub", "sanitize_pii"
        ]
        for pattern in redact_patterns:
            matches = self.ast.find_function_calls(pattern)
            for match in matches[:3]:
                evidence_items.append(self._evidence_from_ast(
                    match.file_path, match.line_number, match.snippet,
                    f"Redaction function: {match.name}"
                ))

        # Check for anonymizer libraries
        if self.deps.has_package("presidio-anonymizer"):
            evidence_items.append(self._evidence_from_dependency(
                "", "presidio-anonymizer", "Presidio anonymizer found"
            ))

        # Check for faker (for test data generation)
        if self.deps.has_package("faker"):
            evidence_items.append(self._evidence_from_dependency(
                "", "faker", "Faker library for data anonymization"
            ))

        # Determine level
        if not evidence_items:
            level = ControlLevel.NONE
        elif len(evidence_items) >= 4:
            level = ControlLevel.ADVANCED
        elif len(evidence_items) >= 2:
            level = ControlLevel.INTERMEDIATE
        else:
            level = ControlLevel.BASIC

        return self._create_evidence(
            detected=len(evidence_items) > 0,
            level=level,
            evidence_items=evidence_items,
        )


class EncryptionDetector(BaseControlDetector):
    """Detect encryption controls."""

    control_id = "DP-03"
    control_name = "Data Encryption"
    category = "data_privacy"
    description = "Encryption of sensitive data at rest and in transit"
    recommendations = [
        "Use cryptography library for data encryption",
        "Implement Fernet for symmetric encryption",
        "Encrypt sensitive data before storage",
    ]

    def detect(self) -> ControlEvidence:
        evidence_items: List[EvidenceItem] = []

        # Check for encryption libraries
        crypto_libs = ["cryptography", "pycryptodome", "nacl", "fernet"]
        for lib in crypto_libs:
            if self.deps.has_package(lib):
                evidence_items.append(self._evidence_from_dependency(
                    "", lib, f"Encryption library {lib} found"
                ))

        # Check for encryption imports
        crypto_imports = ["cryptography", "Fernet", "AES", "RSA"]
        for pattern in crypto_imports:
            matches = self.ast.find_imports(pattern)
            for match in matches[:2]:
                evidence_items.append(self._evidence_from_import(
                    match.file_path, match.line_number, match.name,
                    f"Encryption module imported: {match.name}"
                ))

        # Check for encryption function calls
        encrypt_patterns = ["encrypt", "decrypt", "Fernet", "cipher"]
        for pattern in encrypt_patterns:
            matches = self.ast.find_function_calls(pattern)
            for match in matches[:2]:
                evidence_items.append(self._evidence_from_ast(
                    match.file_path, match.line_number, match.snippet,
                    f"Encryption function: {match.name}"
                ))

        # Determine level
        if not evidence_items:
            level = ControlLevel.NONE
        elif len(evidence_items) >= 4:
            level = ControlLevel.ADVANCED
        elif len(evidence_items) >= 2:
            level = ControlLevel.INTERMEDIATE
        else:
            level = ControlLevel.BASIC

        return self._create_evidence(
            detected=len(evidence_items) > 0,
            level=level,
            evidence_items=evidence_items,
        )


class AuditLoggingDetector(BaseControlDetector):
    """Detect audit logging controls."""

    control_id = "DP-04"
    control_name = "Audit Logging"
    category = "data_privacy"
    description = "Logging of data access and operations for audit trails"
    recommendations = [
        "Implement structured logging with structlog or loguru",
        "Log all data access operations",
        "Include user context in audit logs",
    ]

    def detect(self) -> ControlEvidence:
        evidence_items: List[EvidenceItem] = []

        # Check for logging libraries
        logging_libs = ["structlog", "loguru", "python-json-logger"]
        for lib in logging_libs:
            if self.deps.has_package(lib):
                evidence_items.append(self._evidence_from_dependency(
                    "", lib, f"Structured logging library {lib} found"
                ))

        # Check for logging imports
        log_imports = ["logging", "structlog", "loguru"]
        for pattern in log_imports:
            matches = self.ast.find_imports(pattern)
            for match in matches[:2]:
                evidence_items.append(self._evidence_from_import(
                    match.file_path, match.line_number, match.name,
                    f"Logging module imported: {match.name}"
                ))

        # Check for audit-specific logging
        audit_patterns = ["audit", "log_access", "log_operation", "track"]
        for pattern in audit_patterns:
            matches = self.ast.find_function_calls(pattern)
            for match in matches[:2]:
                evidence_items.append(self._evidence_from_ast(
                    match.file_path, match.line_number, match.snippet,
                    f"Audit logging: {match.name}"
                ))

        # Determine level
        if not evidence_items:
            level = ControlLevel.NONE
        elif len(evidence_items) >= 4:
            level = ControlLevel.ADVANCED
        elif len(evidence_items) >= 2:
            level = ControlLevel.INTERMEDIATE
        else:
            level = ControlLevel.BASIC

        return self._create_evidence(
            detected=len(evidence_items) > 0,
            level=level,
            evidence_items=evidence_items,
        )


class ConsentManagementDetector(BaseControlDetector):
    """Detect consent management controls."""

    control_id = "DP-05"
    control_name = "Consent Management"
    category = "data_privacy"
    description = "Management of user consent for data processing"
    recommendations = [
        "Implement consent tracking for data collection",
        "Provide opt-out mechanisms for users",
        "Store consent records with timestamps",
    ]

    def detect(self) -> ControlEvidence:
        evidence_items: List[EvidenceItem] = []

        # Check for consent-related patterns
        consent_patterns = [
            "consent", "opt_in", "opt_out", "gdpr",
            "privacy_policy", "data_consent"
        ]
        for pattern in consent_patterns:
            # Check function calls
            matches = self.ast.find_function_calls(pattern)
            for match in matches[:2]:
                evidence_items.append(self._evidence_from_ast(
                    match.file_path, match.line_number, match.snippet,
                    f"Consent function: {match.name}"
                ))

            # Check config
            config_matches = self.config.find_key(pattern)
            for match in config_matches[:2]:
                evidence_items.append(self._evidence_from_config(
                    match.file_path, match.key, str(match.value),
                    f"Consent configuration: {match.key}"
                ))

        # Check for consent models/classes
        consent_classes = self.ast.find_classes("Consent")
        for match in consent_classes[:2]:
            evidence_items.append(self._evidence_from_ast(
                match.file_path, match.line_number, match.snippet,
                f"Consent model: {match.name}"
            ))

        # Determine level
        if not evidence_items:
            level = ControlLevel.NONE
        elif len(evidence_items) >= 4:
            level = ControlLevel.ADVANCED
        elif len(evidence_items) >= 2:
            level = ControlLevel.INTERMEDIATE
        else:
            level = ControlLevel.BASIC

        return self._create_evidence(
            detected=len(evidence_items) > 0,
            level=level,
            evidence_items=evidence_items,
        )


class NERPIIDetectionDetector(BaseControlDetector):
    """Detect NER-based PII detection."""

    control_id = "DP-06"
    control_name = "NER PII Detection"
    category = "data_privacy"
    description = "Named Entity Recognition for PII detection"
    recommendations = [
        "Use Presidio or SpaCy for NER-based PII detection",
        "Implement custom NER models for domain-specific PII",
        "Run PII detection on all inputs and outputs",
    ]

    def detect(self) -> ControlEvidence:
        evidence_items: List[EvidenceItem] = []

        # Check for NER/PII libraries
        ner_libs = ["presidio_analyzer", "presidio-analyzer", "spacy", "flair", "transformers"]
        for lib in ner_libs:
            if self.deps.has_package(lib):
                # Verify NER usage
                ner_patterns = ["NER", "ner", "named_entity", "EntityRecognizer", "presidio"]
                for pattern in ner_patterns:
                    matches = self.ast.find_function_calls(pattern)
                    if matches:
                        evidence_items.append(self._evidence_from_dependency(
                            "", lib, f"NER PII detection via {lib}"
                        ))
                        break

        # Check for Presidio usage
        presidio_patterns = ["AnalyzerEngine", "AnonymizerEngine", "presidio"]
        for pattern in presidio_patterns:
            matches = self.ast.find_function_calls(pattern)
            for match in matches[:2]:
                evidence_items.append(self._evidence_from_ast(
                    match.file_path, match.line_number, match.snippet,
                    f"Presidio PII detection: {match.name}"
                ))

        # Determine level
        if not evidence_items:
            level = ControlLevel.NONE
        elif len(evidence_items) >= 2:
            level = ControlLevel.ADVANCED
        elif len(evidence_items) >= 1:
            level = ControlLevel.INTERMEDIATE
        else:
            level = ControlLevel.BASIC

        return self._create_evidence(
            detected=len(evidence_items) > 0,
            level=level,
            evidence_items=evidence_items,
        )


class DataRetentionPolicyDetector(BaseControlDetector):
    """Detect data retention policies."""

    control_id = "DP-07"
    control_name = "Data Retention Policy"
    category = "data_privacy"
    description = "Policies and implementation for data retention and deletion"
    recommendations = [
        "Define data retention policies for AI training data",
        "Implement automated data deletion after retention period",
        "Maintain data inventory with retention metadata",
    ]

    def detect(self) -> ControlEvidence:
        evidence_items: List[EvidenceItem] = []

        # Check for retention config
        retention_patterns = ["retention", "ttl", "expire", "delete_after", "data_lifecycle"]
        for pattern in retention_patterns:
            config_matches = self.config.find_key(pattern)
            for match in config_matches[:2]:
                evidence_items.append(self._evidence_from_config(
                    match.file_path, match.key, str(match.value),
                    f"Data retention config: {match.key}"
                ))

        # Check for deletion/cleanup code
        cleanup_patterns = ["cleanup", "purge", "delete_old", "expire_data", "retention"]
        for pattern in cleanup_patterns:
            matches = self.ast.find_function_calls(pattern)
            for match in matches[:2]:
                evidence_items.append(self._evidence_from_ast(
                    match.file_path, match.line_number, match.snippet,
                    f"Data cleanup: {match.name}"
                ))

        # Determine level
        if not evidence_items:
            level = ControlLevel.NONE
        elif len(evidence_items) >= 3:
            level = ControlLevel.ADVANCED
        elif len(evidence_items) >= 1:
            level = ControlLevel.INTERMEDIATE
        else:
            level = ControlLevel.BASIC

        return self._create_evidence(
            detected=len(evidence_items) > 0,
            level=level,
            evidence_items=evidence_items,
        )


class GDPRComplianceDetector(BaseControlDetector):
    """Detect GDPR/privacy compliance implementations."""

    control_id = "DP-08"
    control_name = "GDPR Compliance"
    category = "data_privacy"
    description = "User rights implementation (access, deletion, portability)"
    recommendations = [
        "Implement data export functionality for user requests",
        "Provide data deletion capabilities (right to be forgotten)",
        "Maintain records of data processing activities",
    ]

    def detect(self) -> ControlEvidence:
        evidence_items: List[EvidenceItem] = []

        # Check for GDPR-related patterns
        gdpr_patterns = [
            "export_data", "delete_user_data", "data_portability",
            "right_to_be_forgotten", "data_subject_request", "gdpr"
        ]
        for pattern in gdpr_patterns:
            matches = self.ast.find_function_calls(pattern)
            for match in matches[:2]:
                evidence_items.append(self._evidence_from_ast(
                    match.file_path, match.line_number, match.snippet,
                    f"GDPR compliance: {match.name}"
                ))

        # Check config for GDPR settings
        config_patterns = ["gdpr", "privacy", "data_subject", "user_rights"]
        for pattern in config_patterns:
            config_matches = self.config.find_key(pattern)
            for match in config_matches[:2]:
                evidence_items.append(self._evidence_from_config(
                    match.file_path, match.key, str(match.value),
                    f"Privacy config: {match.key}"
                ))

        # Check for API endpoints related to user rights
        endpoint_patterns = ["/export", "/delete", "/privacy", "/data-request"]
        for pattern in endpoint_patterns:
            matches = self.ast.find_string_literals(pattern)
            for match in matches[:2]:
                evidence_items.append(self._evidence_from_ast(
                    match.file_path, match.line_number, match.snippet,
                    "User rights endpoint detected"
                ))

        # Determine level
        if not evidence_items:
            level = ControlLevel.NONE
        elif len(evidence_items) >= 3:
            level = ControlLevel.ADVANCED
        elif len(evidence_items) >= 1:
            level = ControlLevel.INTERMEDIATE
        else:
            level = ControlLevel.BASIC

        return self._create_evidence(
            detected=len(evidence_items) > 0,
            level=level,
            evidence_items=evidence_items,
        )


class DataPrivacyControls(ControlCategory):
    """Data privacy control category."""

    category_id = "data_privacy"
    category_name = "Data Privacy"
    weight = 0.12

    def _create_detectors(self) -> List[BaseControlDetector]:
        return [
            PIIDetectionDetector(self.ast, self.config, self.deps),
            DataRedactionDetector(self.ast, self.config, self.deps),
            EncryptionDetector(self.ast, self.config, self.deps),
            AuditLoggingDetector(self.ast, self.config, self.deps),
            ConsentManagementDetector(self.ast, self.config, self.deps),
            NERPIIDetectionDetector(self.ast, self.config, self.deps),
            DataRetentionPolicyDetector(self.ast, self.config, self.deps),
            GDPRComplianceDetector(self.ast, self.config, self.deps),
        ]
