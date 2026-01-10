"""
Category 3: Data Privacy & PII Protection Scorer

Scores the project's data privacy and PII protection posture for:
- PII Detection & Handling (detection methods, redaction strategies)
- Consent Management (consent mechanisms, user rights)
- Compliance & Auditing (regulatory compliance, audit frequency)

Each subcategory is scored 0-100 based on detected controls.
"""

import logging
from typing import Any, Dict, List

from aisentry.scorers.base_scorer import BaseScorer, CategoryScore

logger = logging.getLogger(__name__)


class DataPrivacyScorer(BaseScorer):
    """
    Score Category 3: Data Privacy & PII Protection

    Evaluates:
    - 3.1 PII Detection & Handling
    - 3.2 Consent Management
    - 3.3 Compliance & Auditing

    Framework-aware scoring for LangChain, LlamaIndex, and Haystack.
    """

    category_id = "3_data_privacy"
    category_name = "Data Privacy & PII Protection"

    # Framework-specific patterns for data privacy
    LANGCHAIN_PATTERNS = {
        'memory_management': [
            'ConversationBufferMemory', 'ConversationSummaryMemory',
            'ConversationBufferWindowMemory', 'ConversationTokenBufferMemory',
            'memory.clear()', 'memory.save_context'
        ],
        'chat_history': [
            'chat_history', 'ChatMessageHistory', 'RedisChatMessageHistory',
            'FileChatMessageHistory', 'get_session_history'
        ],
        'pii_redaction': [
            'PIIRedactionTransformer', 'PresidioAnonymizer', 'PresidioReversibleAnonymizer',
            'anonymize', 'deanonymize'
        ],
        'data_filtering': [
            'metadata_filter', 'filter_documents', 'DocumentTransformer',
            'MetadataFieldFilterer'
        ]
    }

    LLAMAINDEX_PATTERNS = {
        'document_ingestion': [
            'SimpleDirectoryReader', 'load_data', 'Document',
            'from_documents', 'insert'
        ],
        'metadata_filtering': [
            'MetadataFilters', 'FilterCondition', 'metadata_dict',
            'exclude_metadata_keys'
        ],
        'storage_privacy': [
            'StorageContext', 'persist_dir', 'SimpleDocumentStore',
            'delete_document'
        ],
        'data_lifecycle': [
            'delete', 'update_docstore', 'refresh', 'delete_nodes'
        ]
    }

    HAYSTACK_PATTERNS = {
        'document_stores': [
            'InMemoryDocumentStore', 'FAISSDocumentStore',
            'delete_documents', 'update_document_meta'
        ],
        'document_cleaning': [
            'DocumentCleaner', 'PreProcessor', 'clean'
        ],
        'metadata_filtering': [
            'filter_documents', 'filters', 'FilterType'
        ],
        'access_control': [
            'authenticate', 'authorization', 'user_filter'
        ]
    }

    # 3.1 PII Detection & Handling
    PII_DETECTION_PATTERNS = {
        'pattern_matching': [
            'regex', 're.compile', 're.match', 're.search',
            'email_pattern', 'phone_pattern', 'ssn_pattern',
            'credit_card_pattern', 'pii_pattern'
        ],
        'ner_models': [
            'spacy', 'spaCy', 'transformers', 'named_entity',
            'NER', 'entity_recognition', 'en_core_web',
            'ner_pipeline'
        ],
        'ml_classifiers': [
            'presidio', 'Presidio', 'AnonymizerEngine',
            'AnalyzerEngine', 'pii_classifier', 'PII',
            'piicatcher', 'pii_detector'
        ],
        'custom_rules': [
            'pii_rules', 'detection_rules', 'custom_detector',
            'PiiDetector', 'privacy_rules'
        ]
    }

    REDACTION_PATTERNS = {
        'masking': ['mask', 'redact', '***', 'hide', 'obscure'],
        'tokenization': ['tokenize', 'pseudonymize', 'anonymize_token'],
        'encryption': ['encrypt', 'cipher', 'aes', 'fernet'],
        'smart': ['presidio', 'smart_redact', 'context_aware', 'selective']
    }

    # 3.2 Consent Management
    CONSENT_PATTERNS = {
        'explicit_optin': [
            'consent', 'opt_in', 'optin', 'user_consent',
            'accept_terms', 'agree', 'permission_granted'
        ],
        'granular_controls': [
            'preferences', 'settings', 'privacy_settings',
            'consent_preferences', 'granular_consent'
        ],
        'withdrawal': [
            'withdraw', 'revoke', 'opt_out', 'optout',
            'delete_consent', 'remove_consent'
        ],
        'purpose_limitation': [
            'purpose', 'data_purpose', 'usage_purpose',
            'processing_purpose', 'purpose_tracking'
        ]
    }

    USER_RIGHTS_PATTERNS = {
        'right_to_access': [
            'export_data', 'download_data', 'data_export',
            'get_user_data', 'retrieve_data'
        ],
        'right_to_delete': [
            'delete_user', 'remove_user', 'delete_account',
            'erase_data', 'right_to_be_forgotten'
        ],
        'right_to_portability': [
            'export', 'json', 'csv', 'xml',
            'data_portability', 'transfer_data'
        ],
        'right_to_correction': [
            'update_user', 'modify_data', 'correct_data',
            'edit_profile', 'change_information'
        ]
    }

    # 3.3 Compliance & Auditing
    COMPLIANCE_PATTERNS = {
        'gdpr': ['gdpr', 'GDPR', 'general_data_protection'],
        'ccpa': ['ccpa', 'CCPA', 'california_consumer_privacy'],
        'hipaa': ['hipaa', 'HIPAA', 'health_insurance_portability'],
        'soc2': ['soc2', 'SOC2', 'service_organization_control']
    }

    AUDIT_PATTERNS = [
        'audit_log', 'audit_trail', 'compliance_check',
        'logging', 'monitor', 'track', 'log_access',
        'access_log', 'audit'
    ]

    # Comprehensive PII Detection patterns
    COMPREHENSIVE_PII_DETECTION_PATTERNS = {
        'presidio': [
            'presidio', 'Presidio', 'AnalyzerEngine', 'RecognizerRegistry',
            'EntityRecognizer', 'PresidioAnalyzer', 'presidio_analyzer'
        ],
        'spacy_ner': [
            'spacy', 'spaCy', 'nlp', 'en_core_web', 'ner',
            'named_entity_recognition', 'ents', 'entity_recognition'
        ],
        'regex_patterns': [
            'regex', 're.compile', 're.match', 're.search', 're.findall',
            'email_pattern', 'phone_pattern', 'ssn_pattern', 'credit_card_pattern'
        ],
        'ml_classifiers': [
            'pii_classifier', 'PII', 'piicatcher', 'pii_detector',
            'transformers', 'bert', 'pii_model'
        ],
        'custom_detectors': [
            'custom_detector', 'PiiDetector', 'privacy_rules', 'pii_rules',
            'detection_rules', 'EntityDetector'
        ]
    }

    # Comprehensive PII Redaction patterns
    COMPREHENSIVE_PII_REDACTION_PATTERNS = {
        'anonymization': [
            'anonymize', 'AnonymizerEngine', 'PresidioAnonymizer',
            'anonymize_data', 'data_anonymization', 'k_anonymity'
        ],
        'pseudonymization': [
            'pseudonymize', 'pseudonym', 'hash', 'tokenize',
            'pseudonymization', 'reversible_anonymization'
        ],
        'masking': [
            'mask', 'redact', '***', 'hide', 'obscure',
            'mask_pii', 'redaction', 'data_masking'
        ],
        'encryption_redaction': [
            'encrypt_pii', 'encrypted_field', 'field_level_encryption',
            'format_preserving_encryption', 'FPE'
        ],
        'context_aware': [
            'smart_redact', 'context_aware', 'selective_redaction',
            'PresidioReversibleAnonymizer', 'conditional_redaction'
        ]
    }

    # Comprehensive Data Encryption patterns
    COMPREHENSIVE_DATA_ENCRYPTION_PATTERNS = {
        'storage_encryption': [
            'encrypt_at_rest', 'database_encryption', 'disk_encryption',
            'AES', 'RSA', 'Fernet', 'cryptography', 'encrypted_storage'
        ],
        'transmission_security': [
            'TLS', 'SSL', 'HTTPS', 'secure_transport', 'encrypted_channel',
            'end_to_end_encryption', 'E2EE', 'transport_layer_security'
        ],
        'field_level_encryption': [
            'encrypt_field', 'column_encryption', 'attribute_encryption',
            'field_level_encryption', 'encrypted_column'
        ],
        'key_management': [
            'KMS', 'key_management', 'KeyManagementService', 'encryption_key',
            'key_rotation', 'master_key', 'data_key'
        ],
        'homomorphic_encryption': [
            'homomorphic', 'FHE', 'fully_homomorphic', 'encrypted_computation',
            'compute_on_encrypted'
        ]
    }

    # Comprehensive Consent Management patterns
    COMPREHENSIVE_CONSENT_MANAGEMENT_PATTERNS = {
        'consent_tracking': [
            'consent', 'user_consent', 'track_consent', 'consent_record',
            'ConsentManager', 'consent_database', 'consent_log'
        ],
        'opt_in_out': [
            'opt_in', 'opt_out', 'optin', 'optout', 'accept_terms',
            'decline', 'consent_given', 'consent_withdrawn'
        ],
        'granular_controls': [
            'granular_consent', 'consent_preferences', 'privacy_settings',
            'consent_categories', 'purpose_based_consent', 'selective_consent'
        ],
        'consent_withdrawal': [
            'withdraw_consent', 'revoke_consent', 'remove_consent',
            'consent_revocation', 'opt_out_all'
        ],
        'consent_ui': [
            'consent_banner', 'cookie_consent', 'privacy_notice',
            'consent_form', 'consent_dialog', 'ConsentUI'
        ]
    }

    # Comprehensive Data Lifecycle patterns
    DATA_LIFECYCLE_PATTERNS = {
        'retention_policies': [
            'retention_policy', 'data_retention', 'retention_period',
            'keep_for', 'expire_after', 'ttl', 'time_to_live'
        ],
        'data_deletion': [
            'delete_data', 'purge_data', 'erase_data', 'hard_delete',
            'permanent_deletion', 'data_removal', 'cleanup'
        ],
        'archival': [
            'archive', 'archive_data', 'cold_storage', 'data_archival',
            'archived', 'archival_policy'
        ],
        'right_to_be_forgotten': [
            'right_to_be_forgotten', 'RTBF', 'erase_user', 'delete_user',
            'forget_me', 'erasure_request', 'data_erasure'
        ],
        'data_minimization': [
            'data_minimization', 'minimal_data', 'collect_minimum',
            'necessary_data_only', 'privacy_by_design'
        ]
    }

    # Comprehensive GDPR Compliance patterns
    GDPR_COMPLIANCE_PATTERNS = {
        'right_to_access': [
            'data_access', 'export_data', 'download_data', 'get_user_data',
            'data_subject_access', 'DSAR', 'subject_access_request'
        ],
        'right_to_portability': [
            'data_portability', 'export_json', 'export_csv', 'export_xml',
            'transfer_data', 'portable_format', 'machine_readable'
        ],
        'right_to_correction': [
            'rectification', 'update_data', 'correct_data', 'modify_data',
            'data_correction', 'amend_data'
        ],
        'right_to_erasure': [
            'right_to_erasure', 'delete_account', 'erase_data',
            'remove_personal_data', 'erasure_request'
        ],
        'gdpr_controls': [
            'GDPR', 'gdpr_compliant', 'gdpr_compliance', 'lawful_basis',
            'data_protection_officer', 'DPO', 'privacy_impact_assessment'
        ],
        'data_breach_notification': [
            'breach_notification', 'data_breach', 'incident_response',
            'breach_reporting', 'notify_breach'
        ]
    }

    # Comprehensive Audit Logging patterns
    COMPREHENSIVE_AUDIT_LOGGING_PATTERNS = {
        'access_logs': [
            'access_log', 'log_access', 'access_record', 'who_accessed',
            'user_access_log', 'access_tracking'
        ],
        'data_lineage': [
            'data_lineage', 'lineage_tracking', 'data_provenance',
            'track_data_flow', 'data_pipeline', 'lineage'
        ],
        'compliance_logging': [
            'compliance_log', 'audit_trail', 'regulatory_log',
            'compliance_record', 'compliance_tracking'
        ],
        'audit_trails': [
            'audit_trail', 'audit_log', 'audit_record', 'audit_event',
            'immutable_log', 'tamper_proof'
        ],
        'monitoring': [
            'monitor_access', 'track_usage', 'usage_monitoring',
            'activity_log', 'monitoring_dashboard', 'real_time_monitoring'
        ]
    }

    def _score_pii_detection_comprehensive(self, parsed_data: Dict[str, Any]) -> int:
        """
        Score comprehensive PII Detection (0-100) - Evidence-Based

        Uses EvidenceCollector to detect PII detection libraries.
        PII detection identifies sensitive data before processing.

        Scoring based on detection sophistication:
        - Presidio analyzer: 100
        - spaCy NER: 85
        - Transformers NER models: 75
        - Regex patterns (custom detection): 50
        - None detected: 0
        """
        from aisentry.scorers.evidence_framework import EvidenceCollector

        collector = EvidenceCollector(parsed_data)

        # Evidence 1: Presidio Analyzer (Microsoft's PII detection)
        presidio_evidence = collector.collect_library_evidence(
            control_name='presidio_analyzer',
            module_names=['presidio_analyzer'],
            class_names=['AnalyzerEngine', 'RecognizerRegistry', 'PatternRecognizer'],
            function_names=['analyze']
        )

        # Evidence 2: spaCy NER (Named Entity Recognition)
        spacy_evidence = collector.collect_library_evidence(
            control_name='spacy_ner',
            module_names=['spacy'],
            class_names=['Language'],
            function_names=['load']
        )

        # Evidence 3: Transformers NER (BERT, RoBERTa models)
        transformers_evidence = collector.collect_library_evidence(
            control_name='transformers_ner',
            module_names=['transformers'],
            class_names=['pipeline', 'AutoModelForTokenClassification'],
            function_names=['']
        )

        has_presidio = presidio_evidence.is_confident()
        has_spacy = spacy_evidence.is_confident()
        has_transformers = transformers_evidence.is_confident()

        # Evidence 4: Regex patterns (AST-based detection)
        source_lines = parsed_data.get('source_lines', [])
        source_text = ' '.join(source_lines).lower()

        # Check for common PII regex patterns
        pii_regex_patterns = [
            r'\b\d{3}-\d{2}-\d{4}\b',  # SSN
            r'\b\d{16}\b',  # Credit card
            r'\d{3}[.-]?\d{3}[.-]?\d{4}',  # Phone
            'email.*regex', 'ssn.*regex', 'credit.*card.*regex'
        ]
        has_regex_detection = any(pattern in source_text for pattern in pii_regex_patterns)

        # Score based on sophistication
        if has_presidio:
            return 100  # Best: Dedicated PII detection framework
        elif has_spacy:
            return 85  # Good: NER-based detection
        elif has_transformers:
            return 75  # Good: ML-based NER
        elif has_regex_detection:
            return 50  # Basic: Regex patterns
        else:
            return 0  # No PII detection

    def _score_pii_redaction_comprehensive(self, parsed_data: Dict[str, Any]) -> int:
        """
        Score comprehensive PII Redaction (0-100) - Evidence-Based

        Uses multi-signal evidence collection to eliminate false positives.
        Requires import + instantiation/usage for confident detection.

        Scoring based on evidence strength:
        - Presidio (commercial-grade, STRONG): 100
        - Scrubadub or LangChain PII (open-source, STRONG): 85
        - spaCy NER for PII (MEDIUM): 70
        - Custom redaction functions (WEAK): 50
        - Basic masking (WEAK): 40
        - No evidence: 0
        """
        from aisentry.scorers.evidence_framework import EvidenceCollector, EvidenceStrength

        collector = EvidenceCollector(parsed_data)

        # Evidence 1: Presidio (commercial-grade PII detection/redaction)
        presidio_analyzer_evidence = collector.collect_library_evidence(
            control_name='presidio_analyzer',
            module_names=['presidio_analyzer'],
            class_names=['AnalyzerEngine', 'RecognizerRegistry'],
            function_names=['analyze']
        )

        presidio_anonymizer_evidence = collector.collect_library_evidence(
            control_name='presidio_anonymizer',
            module_names=['presidio_anonymizer'],
            class_names=['AnonymizerEngine', 'AnonymizerConfig'],
            function_names=['anonymize']
        )

        # Evidence 2: Scrubadub (open-source PII scrubbing)
        scrubadub_evidence = collector.collect_library_evidence(
            control_name='scrubadub',
            module_names=['scrubadub'],
            class_names=['Scrubber'],
            function_names=['clean']
        )

        # Evidence 3: LangChain PII transformers
        langchain_pii_evidence = collector.collect_library_evidence(
            control_name='langchain_pii',
            module_names=['langchain'],
            class_names=['PresidioAnonymizer', 'PIIRedactionTransformer'],
            function_names=['anonymize', 'transform']
        )

        # Evidence 4: spaCy NER for PII detection
        spacy_evidence = collector.collect_library_evidence(
            control_name='spacy_ner',
            module_names=['spacy'],
            class_names=[''],
            function_names=['load']
        )

        # Evaluate evidence strength
        has_presidio = (presidio_analyzer_evidence.is_confident() or
                       presidio_anonymizer_evidence.is_confident())
        has_scrubadub = scrubadub_evidence.is_confident()
        has_langchain_pii = langchain_pii_evidence.is_confident()
        has_spacy = spacy_evidence.strength >= EvidenceStrength.MEDIUM

        # Score based on strongest evidence
        if has_presidio:
            return 100
        elif has_scrubadub or has_langchain_pii:
            return 85
        elif has_spacy:
            return 70
        else:
            # Check for custom redaction patterns (very weak evidence)
            redaction_patterns = ['redact', 'anonymize', 'mask_pii', 'remove_pii']
            functions = parsed_data.get('function_calls', [])
            has_custom = any(any(pattern in func.lower() for pattern in redaction_patterns)
                           for func in functions)

            # Check for basic masking
            masking_patterns = ['mask', 'replace', 'hide']
            has_masking = any(any(pattern in func.lower() for pattern in masking_patterns)
                            for func in functions)

            if has_custom:
                return 50
            elif has_masking:
                return 40
            else:
                return 0

    def _score_data_encryption_comprehensive(self, parsed_data: Dict[str, Any]) -> int:
        """
        Score comprehensive Data Encryption (0-100) - Evidence-Based

        Uses multi-signal evidence collection to eliminate false positives.
        Requires import + instantiation/usage for confident detection.

        Scoring based on evidence strength:
        - Cloud KMS (AWS/Azure/GCP, STRONG): 100
        - Cryptography Fernet (STRONG): 90
        - PyCrypto/PyCryptodome (MEDIUM): 75
        - TLS/SSL libraries (MEDIUM): 60
        - Custom encryption (WEAK): 50
        - No evidence: 0
        """
        from aisentry.scorers.evidence_framework import EvidenceCollector, EvidenceStrength

        collector = EvidenceCollector(parsed_data)

        # Evidence 1: AWS KMS
        aws_kms_evidence = collector.collect_library_evidence(
            control_name='aws_kms',
            module_names=['boto3'],
            class_names=['client:kms'],
            function_names=['encrypt', 'decrypt', 'generate_data_key']
        )

        # Evidence 2: Azure Key Vault
        azure_kv_evidence = collector.collect_library_evidence(
            control_name='azure_keyvault',
            module_names=['azure.keyvault.keys'],
            class_names=['KeyClient', 'CryptographyClient'],
            function_names=['encrypt', 'decrypt']
        )

        # Evidence 3: GCP KMS
        gcp_kms_evidence = collector.collect_library_evidence(
            control_name='gcp_kms',
            module_names=['google.cloud.kms'],
            class_names=['KeyManagementServiceClient'],
            function_names=['encrypt', 'decrypt']
        )

        # Evidence 4: Cryptography (Fernet - symmetric encryption)
        fernet_evidence = collector.collect_library_evidence(
            control_name='cryptography_fernet',
            module_names=['cryptography'],
            class_names=['Fernet'],
            function_names=['generate_key', 'encrypt', 'decrypt']
        )

        # Evidence 5: PyCrypto/PyCryptodome
        pycrypto_evidence = collector.collect_library_evidence(
            control_name='pycrypto',
            module_names=['Crypto'],
            class_names=['AES', 'RSA'],
            function_names=['encrypt', 'decrypt']
        )

        # Evidence 6: TLS/SSL libraries
        ssl_evidence = collector.collect_library_evidence(
            control_name='ssl_tls',
            module_names=['ssl'],
            class_names=['SSLContext'],
            function_names=['wrap_socket', 'create_default_context']
        )

        # Evaluate evidence strength
        has_cloud_kms = (aws_kms_evidence.is_confident() or
                        azure_kv_evidence.is_confident() or
                        gcp_kms_evidence.is_confident())
        has_fernet = fernet_evidence.is_confident()
        has_pycrypto = pycrypto_evidence.strength >= EvidenceStrength.MEDIUM
        has_ssl = ssl_evidence.strength >= EvidenceStrength.MEDIUM

        # Score based on strongest evidence
        if has_cloud_kms:
            return 100
        elif has_fernet:
            return 90
        elif has_pycrypto:
            return 75
        elif has_ssl:
            return 60
        else:
            # Check for custom encryption patterns (very weak evidence)
            encryption_patterns = ['encrypt', 'decrypt', 'cipher']
            functions = parsed_data.get('function_calls', [])
            has_custom = any(any(pattern in func.lower() for pattern in encryption_patterns)
                           for func in functions)
            return 50 if has_custom else 0

    def _score_consent_management_comprehensive(self, parsed_data: Dict[str, Any]) -> int:
        """
        Score comprehensive Consent Management (0-100) - Evidence-Based

        Uses AST-based function detection for consent management endpoints.
        Consent management tracks user permissions for data processing.

        Scoring based on consent management features:
        - Tracking + Opt-in + Withdrawal + Granular: 100
        - Tracking + Opt-in + Withdrawal: 75
        - Tracking + Opt-in: 60
        - Basic opt-in only: 40
        - None detected: 0
        """
        # Consent management is primarily about endpoints/functions
        function_defs = parsed_data.get('function_defs', [])
        function_names = [f.lower() for f in function_defs]

        # Consent tracking functions
        tracking_patterns = [
            'track_consent', 'store_consent', 'save_consent', 'consent_record',
            'log_consent', 'update_consent'
        ]
        has_tracking = any(
            any(pattern in func for pattern in tracking_patterns)
            for func in function_names
        )

        # Opt-in/opt-out functions
        opt_patterns = [
            'opt_in', 'opt_out', 'give_consent', 'withdraw_consent',
            'accept_terms', 'decline_terms'
        ]
        has_opt = any(
            any(pattern in func for pattern in opt_patterns)
            for func in function_names
        )

        # Withdrawal functions
        withdrawal_patterns = [
            'withdraw_consent', 'revoke_consent', 'remove_consent',
            'cancel_consent', 'delete_consent'
        ]
        has_withdrawal = any(
            any(pattern in func for pattern in withdrawal_patterns)
            for func in function_names
        )

        # Granular control functions
        granular_patterns = [
            'granular_consent', 'consent_preference', 'permission_level',
            'consent_scope', 'specific_consent'
        ]
        has_granular = any(
            any(pattern in func for pattern in granular_patterns)
            for func in function_names
        )

        # Score based on features
        if has_tracking and has_opt and has_withdrawal and has_granular:
            return 100
        elif has_tracking and has_opt and has_withdrawal:
            return 75
        elif has_tracking and has_opt:
            return 60
        elif has_opt:
            return 40
        else:
            return 0

    def _score_data_lifecycle_comprehensive(self, parsed_data: Dict[str, Any]) -> int:
        """
        Score comprehensive Data Lifecycle Management (0-100) - Evidence-Based

        Uses AST-based function detection for data lifecycle policies.
        Data lifecycle management ensures proper retention and deletion.

        Scoring based on lifecycle management:
        - Retention + Deletion + Archival: 100
        - Retention + Deletion: 75
        - Deletion only: 50
        - None detected: 0
        """
        # Data lifecycle is primarily about policy functions
        function_defs = parsed_data.get('function_defs', [])
        function_names = [f.lower() for f in function_defs]

        # Retention policy functions
        retention_patterns = [
            'retention_policy', 'set_retention', 'data_retention',
            'retention_period', 'expire_data', 'ttl'
        ]
        has_retention = any(
            any(pattern in func for pattern in retention_patterns)
            for func in function_names
        )

        # Data deletion functions
        deletion_patterns = [
            'delete_data', 'purge_data', 'remove_data', 'erase_data',
            'cleanup_data', 'expire_records'
        ]
        has_deletion = any(
            any(pattern in func for pattern in deletion_patterns)
            for func in function_names
        )

        # Data archival functions
        archival_patterns = [
            'archive_data', 'archive_records', 'cold_storage',
            'move_to_archive', 'backup_data'
        ]
        has_archival = any(
            any(pattern in func for pattern in archival_patterns)
            for func in function_names
        )

        # Score based on lifecycle features
        if has_retention and has_deletion and has_archival:
            return 100
        elif has_retention and has_deletion:
            return 75
        elif has_deletion:
            return 50
        else:
            return 0

    def _score_gdpr_compliance_comprehensive(self, parsed_data: Dict[str, Any]) -> int:
        """
        Score comprehensive GDPR Compliance (0-100) - Evidence-Based

        Uses AST-based function detection for GDPR rights.
        More AST-focused than library-based (no specific GDPR libraries).

        Scoring based on GDPR rights implementation:
        - All 3 rights (access + deletion + portability): 100
        - 2 rights: 70
        - 1 right: 40
        - No evidence: 0
        """
        # GDPR compliance is more about endpoints/functions than libraries
        # Check for actual function definitions implementing GDPR rights

        function_defs = parsed_data.get('function_defs', [])
        function_names = [f.lower() for f in function_defs]

        # Right to Access - data export endpoints
        export_patterns = ['export_data', 'download_data', 'get_user_data', 'data_export', 'export_user']
        has_export = any(any(pattern in func for pattern in export_patterns) for func in function_names)

        # Right to Deletion - deletion endpoints
        deletion_patterns = ['delete_account', 'remove_user', 'delete_user', 'gdpr_delete', 'erase_data']
        has_deletion = any(any(pattern in func for pattern in deletion_patterns) for func in function_names)

        # Right to Portability - data portability endpoints
        portability_patterns = ['export_json', 'export_csv', 'data_portability', 'portable_data']
        has_portability = any(any(pattern in func for pattern in portability_patterns) for func in function_names)

        # Also check function calls (not just definitions)
        function_calls = parsed_data.get('function_calls', [])
        function_call_names = [f.lower() for f in function_calls]

        # Check if they're calling these functions
        has_export = has_export or any(any(pattern in func for pattern in export_patterns) for func in function_call_names)
        has_deletion = has_deletion or any(any(pattern in func for pattern in deletion_patterns) for func in function_call_names)
        has_portability = has_portability or any(any(pattern in func for pattern in portability_patterns) for func in function_call_names)

        # Score based on number of rights implemented
        rights_count = sum([has_export, has_deletion, has_portability])

        if rights_count >= 3:
            return 100
        elif rights_count == 2:
            return 70
        elif rights_count == 1:
            return 40
        else:
            return 0

    def _score_audit_logging_comprehensive(self, parsed_data: Dict[str, Any]) -> int:
        """
        Score comprehensive Audit Logging (0-100) - Evidence-Based

        Uses multi-signal evidence collection to eliminate false positives.
        Requires import + instantiation/usage for confident detection.

        Scoring based on evidence strength:
        - Structured logging + Elasticsearch/Datadog (STRONG): 100
        - Structured logging (structlog, STRONG): 85
        - JSON logging (MEDIUM): 70
        - Python logging with audit (WEAK): 60
        - Basic logging (WEAK): 30
        - No evidence: 0
        """
        from aisentry.scorers.evidence_framework import EvidenceCollector, EvidenceStrength

        collector = EvidenceCollector(parsed_data)

        # Evidence 1: Elasticsearch logging
        elasticsearch_evidence = collector.collect_library_evidence(
            control_name='elasticsearch_logging',
            module_names=['elasticsearch'],
            class_names=['Elasticsearch'],
            function_names=['index']
        )

        # Evidence 2: Datadog logging
        datadog_evidence = collector.collect_library_evidence(
            control_name='datadog_logging',
            module_names=['datadog'],
            class_names=['DogStatsd'],
            function_names=['']
        )

        # Evidence 3: Structured logging (structlog)
        structlog_evidence = collector.collect_library_evidence(
            control_name='structlog',
            module_names=['structlog'],
            class_names=[''],
            function_names=['get_logger']
        )

        # Evidence 4: JSON logging
        json_logger_evidence = collector.collect_library_evidence(
            control_name='json_logger',
            module_names=['python-json-logger', 'pythonjsonlogger'],
            class_names=['JsonFormatter'],
            function_names=['']
        )

        # Evidence 5: Standard Python logging
        logging_evidence = collector.collect_library_evidence(
            control_name='python_logging',
            module_names=['logging'],
            class_names=['Logger'],
            function_names=['getLogger']
        )

        # Evaluate evidence strength
        has_elasticsearch = elasticsearch_evidence.is_confident()
        has_datadog = datadog_evidence.is_confident()
        has_structlog = structlog_evidence.is_confident()
        has_json_logging = json_logger_evidence.strength >= EvidenceStrength.MEDIUM
        has_logging = logging_evidence.strength >= EvidenceStrength.WEAK

        # Score based on strongest evidence
        if has_structlog and (has_elasticsearch or has_datadog):
            return 100
        elif has_structlog:
            return 85
        elif has_json_logging:
            return 70
        elif has_logging:
            # Check if it's audit-specific logging
            functions = parsed_data.get('function_calls', [])
            audit_patterns = ['audit', 'security_log', 'track_', 'access_log']
            has_audit = any(any(pattern in func.lower() for pattern in audit_patterns)
                          for func in functions)
            return 60 if has_audit else 30
        else:
            return 0

    def calculate_score(self, parsed_data: Dict[str, Any]) -> CategoryScore:
        """
        Calculate Data Privacy & PII Protection score with framework detection

        Args:
            parsed_data: Aggregated parsed data from all project files

        Returns:
            CategoryScore with overall score and subscores
        """
        # Extract data
        imports = parsed_data.get('imports', [])
        functions = parsed_data.get('functions', [])
        source_lines = parsed_data.get('source_lines', [])
        source_code = ' '.join(source_lines).lower()

        # Detect frameworks
        detected_frameworks = self._detect_frameworks(parsed_data)
        framework_features = {
            fw: self._get_framework_features(parsed_data, fw)
            for fw in detected_frameworks
        }

        # Calculate legacy subscores (backward compatibility)
        pii_handling_score = self._score_pii_handling(
            imports, functions, source_code
        )

        consent_management_score = self._score_consent_management(
            functions, source_code
        )

        compliance_auditing_score = self._score_compliance_auditing(
            imports, source_code
        )

        # Calculate new comprehensive subscores
        pii_detection_score = self._score_pii_detection_comprehensive(parsed_data)
        pii_redaction_score = self._score_pii_redaction_comprehensive(parsed_data)
        data_encryption_score = self._score_data_encryption_comprehensive(parsed_data)
        consent_mgmt_comprehensive_score = self._score_consent_management_comprehensive(parsed_data)
        data_lifecycle_score = self._score_data_lifecycle_comprehensive(parsed_data)
        gdpr_compliance_score = self._score_gdpr_compliance_comprehensive(parsed_data)
        audit_logging_score = self._score_audit_logging_comprehensive(parsed_data)

        # Calculate weighted overall score with new comprehensive subscores
        overall_score = self._weighted_average(
            scores=[
                pii_detection_score,              # Most critical - detect PII
                pii_redaction_score,              # Critical - protect PII
                data_encryption_score,            # Important - secure data
                consent_mgmt_comprehensive_score, # Important - user rights
                data_lifecycle_score,             # Important - data management
                gdpr_compliance_score,            # Important - regulatory
                audit_logging_score,              # Good practice - accountability
                pii_handling_score,               # Legacy (small weight)
                consent_management_score,         # Legacy (small weight)
                compliance_auditing_score         # Legacy (small weight)
            ],
            weights=[
                0.25,  # pii_detection - highest priority
                0.20,  # pii_redaction - critical protection
                0.15,  # data_encryption - important security
                0.15,  # consent_management_comprehensive - important rights
                0.10,  # data_lifecycle - important management
                0.08,  # gdpr_compliance - important regulatory
                0.04,  # audit_logging - good practice
                0.01,  # pii_handling (legacy)
                0.01,  # consent_management (legacy)
                0.01   # compliance_auditing (legacy)
            ]
        )

        # Get all detected controls
        detected_controls = self._get_all_detections(source_code, imports, functions)

        # Calculate confidence (boost for framework detection)
        base_confidence = 0.7 + (len(detected_frameworks) * 0.05)
        confidence = self._calculate_confidence(
            detection_count=len(detected_controls),
            total_possible=15,  # Approximate total controls
            base_confidence=min(base_confidence, 0.95)
        )

        # Identify gaps
        gaps = self._identify_gaps(
            pii_handling_score,
            consent_management_score,
            compliance_auditing_score
        )

        # Generate framework insights
        framework_insights = {}
        if detected_frameworks:
            for framework in detected_frameworks:
                framework_insights[framework] = self._get_framework_insights(
                    framework,
                    framework_features.get(framework, {}),
                    pii_handling_score,
                    consent_management_score,
                    compliance_auditing_score
                )

        return CategoryScore(
            category_id=self.category_id,
            category_name=self.category_name,
            score=overall_score,
            confidence=confidence,
            subscores={
                # Legacy subscores (backward compatibility)
                'pii_handling': pii_handling_score,
                'consent_management': consent_management_score,
                'compliance_auditing': compliance_auditing_score,
                # New comprehensive subscores
                'pii_detection': pii_detection_score,
                'pii_redaction': pii_redaction_score,
                'data_encryption': data_encryption_score,
                'consent_management_comprehensive': consent_mgmt_comprehensive_score,
                'data_lifecycle': data_lifecycle_score,
                'gdpr_compliance': gdpr_compliance_score,
                'audit_logging': audit_logging_score
            },
            detected_controls=detected_controls,
            gaps=gaps,
            evidence={
                'has_pii_detection': pii_handling_score > 0,
                'has_consent_management': consent_management_score > 0,
                'has_compliance_controls': compliance_auditing_score > 0,
                'detected_frameworks': detected_frameworks,
                'framework_insights': framework_insights,
                # New subscore evidence
                'pii_detection_score': pii_detection_score,
                'pii_redaction_score': pii_redaction_score,
                'data_encryption_score': data_encryption_score,
                'consent_mgmt_comprehensive_score': consent_mgmt_comprehensive_score,
                'data_lifecycle_score': data_lifecycle_score,
                'gdpr_compliance_score': gdpr_compliance_score,
                'audit_logging_score': audit_logging_score
            }
        )

    def _score_pii_handling(
        self,
        imports: List[Dict[str, Any]],
        functions: List[Dict[str, Any]],
        source_code: str
    ) -> int:
        """
        Score PII handling (legacy subscore - 1% weight)

        Deprecated: Use comprehensive subscores instead.
        Returns 0 as this is superseded by:
        - pii_detection_comprehensive
        - pii_redaction_comprehensive
        """
        return 0

    def _score_consent_management(
        self,
        functions: List[Dict[str, Any]],
        source_code: str
    ) -> int:
        """
        Score consent management (legacy subscore - 1% weight)

        Deprecated: Use comprehensive subscore instead.
        Returns 0 as this is superseded by:
        - consent_management_comprehensive
        """
        return 0

    def _score_compliance_auditing(
        self,
        imports: List[Dict[str, Any]],
        source_code: str
    ) -> int:
        """
        Score compliance auditing (legacy subscore - 1% weight)

        Deprecated: Use comprehensive subscores instead.
        Returns 0 as this is superseded by:
        - gdpr_compliance_comprehensive
        - audit_logging_comprehensive
        """
        return 0

    def _get_all_detections(
        self,
        source_code: str,
        imports: List[Dict[str, Any]],
        functions: List[Dict[str, Any]]
    ) -> List[str]:
        """Get list of all detected privacy controls"""
        detections = []

        # PII Detection
        if any(p in source_code for p in self.PII_DETECTION_PATTERNS['pattern_matching']):
            detections.append("PII pattern matching")
        if any(p in source_code for p in self.PII_DETECTION_PATTERNS['ner_models']):
            detections.append("NER models for PII")
        if any(p in source_code for p in self.PII_DETECTION_PATTERNS['ml_classifiers']):
            detections.append("ML-based PII detection")

        # Redaction
        if any(p in source_code for p in self.REDACTION_PATTERNS['encryption']):
            detections.append("PII encryption")
        if any(p in source_code for p in self.REDACTION_PATTERNS['masking']):
            detections.append("PII masking")

        # Consent
        if any(p in source_code for p in self.CONSENT_PATTERNS['explicit_optin']):
            detections.append("Explicit consent")
        if any(p in source_code for p in self.CONSENT_PATTERNS['withdrawal']):
            detections.append("Consent withdrawal")

        # User Rights
        if any(p in source_code for p in self.USER_RIGHTS_PATTERNS['right_to_access']):
            detections.append("Right to access")
        if any(p in source_code for p in self.USER_RIGHTS_PATTERNS['right_to_delete']):
            detections.append("Right to delete")

        # Compliance
        if any(p in source_code for p in self.COMPLIANCE_PATTERNS['gdpr']):
            detections.append("GDPR compliance")
        if any(p in source_code for p in self.COMPLIANCE_PATTERNS['ccpa']):
            detections.append("CCPA compliance")

        # Auditing
        if any(p in source_code for p in self.AUDIT_PATTERNS):
            detections.append("Audit logging")

        return detections

    def _identify_gaps(
        self,
        pii_handling_score: int,
        consent_management_score: int,
        compliance_auditing_score: int
    ) -> List[str]:
        """Identify privacy gaps (scores < 40)"""
        gaps = []

        if pii_handling_score < 40:
            gaps.append("PII detection and handling needs improvement")
            gaps.append("Consider implementing PII detection tools (Presidio, spaCy NER)")

        if consent_management_score < 40:
            gaps.append("Consent management is weak")
            gaps.append("Implement user consent mechanisms and user rights endpoints")

        if compliance_auditing_score < 40:
            gaps.append("Regulatory compliance controls missing")
            gaps.append("Add audit logging and compliance documentation")

        return gaps

    def _detect_frameworks(self, parsed_data: Dict[str, Any]) -> List[str]:
        """Detect which LLM frameworks are being used"""
        frameworks = []
        all_text = ' '.join(parsed_data.get('source_lines', [])).lower()

        if any(indicator in all_text for indicator in ['langchain', 'langchain_core', 'langchain_community']):
            frameworks.append('langchain')
        if any(indicator in all_text for indicator in ['llama_index', 'llamaindex', 'from llama_index']):
            frameworks.append('llamaindex')
        if any(indicator in all_text for indicator in ['haystack', 'from haystack']):
            frameworks.append('haystack')

        return frameworks

    def _get_framework_features(self, parsed_data: Dict[str, Any], framework: str) -> Dict[str, bool]:
        """Detect which features of a framework are being used"""
        all_text = ' '.join(parsed_data.get('source_lines', [])).lower()
        features = {}

        if framework == 'langchain':
            patterns = self.LANGCHAIN_PATTERNS
            features = {
                'memory_management': any(p.lower() in all_text for p in patterns['memory_management']),
                'chat_history': any(p.lower() in all_text for p in patterns['chat_history']),
                'pii_redaction': any(p.lower() in all_text for p in patterns['pii_redaction']),
                'data_filtering': any(p.lower() in all_text for p in patterns['data_filtering'])
            }
        elif framework == 'llamaindex':
            patterns = self.LLAMAINDEX_PATTERNS
            features = {
                'document_ingestion': any(p.lower() in all_text for p in patterns['document_ingestion']),
                'metadata_filtering': any(p.lower() in all_text for p in patterns['metadata_filtering']),
                'storage_privacy': any(p.lower() in all_text for p in patterns['storage_privacy']),
                'data_lifecycle': any(p.lower() in all_text for p in patterns['data_lifecycle'])
            }
        elif framework == 'haystack':
            patterns = self.HAYSTACK_PATTERNS
            features = {
                'document_stores': any(p.lower() in all_text for p in patterns['document_stores']),
                'document_cleaning': any(p.lower() in all_text for p in patterns['document_cleaning']),
                'metadata_filtering': any(p.lower() in all_text for p in patterns['metadata_filtering']),
                'access_control': any(p.lower() in all_text for p in patterns['access_control'])
            }

        return features

    def _get_framework_insights(
        self,
        framework: str,
        features: Dict[str, bool],
        pii_handling_score: int,
        consent_management_score: int,
        compliance_auditing_score: int
    ) -> Dict[str, Any]:
        """Generate privacy insights for detected framework"""
        recommendations = []
        best_practices = []

        if framework == 'langchain':
            if features.get('memory_management'):
                best_practices.append("Using conversation memory (consider PII implications)")
            if features.get('pii_redaction'):
                best_practices.append("Using Presidio for PII redaction")

            if not features.get('pii_redaction') and features.get('memory_management'):
                recommendations.append("Add PIIRedactionTransformer or PresidioAnonymizer to sanitize chat history")
            if not features.get('data_filtering'):
                recommendations.append("Use MetadataFieldFilterer to exclude sensitive metadata from vector stores")
            if pii_handling_score < 60:
                recommendations.append("Consider clearing memory periodically with memory.clear() to limit PII retention")

        elif framework == 'llamaindex':
            if features.get('metadata_filtering'):
                best_practices.append("Using metadata filters for access control")
            if features.get('data_lifecycle'):
                best_practices.append("Implementing document lifecycle management")

            if not features.get('metadata_filtering'):
                recommendations.append("Add MetadataFilters to exclude sensitive documents from queries")
            if not features.get('data_lifecycle'):
                recommendations.append("Implement delete_document() for GDPR right-to-erasure compliance")
            if pii_handling_score < 60:
                recommendations.append("Use exclude_metadata_keys to prevent sensitive metadata exposure")

        elif framework == 'haystack':
            if features.get('document_cleaning'):
                best_practices.append("Using DocumentCleaner/PreProcessor for data sanitization")
            if features.get('access_control'):
                best_practices.append("Implementing access control on document stores")

            if not features.get('document_cleaning'):
                recommendations.append("Add DocumentCleaner to sanitize sensitive data before indexing")
            if not features.get('metadata_filtering'):
                recommendations.append("Use filters parameter to restrict document access based on user permissions")
            if consent_management_score < 60:
                recommendations.append("Implement user_filter for multi-tenant privacy isolation")

        return {
            'detected_features': features,
            'security_recommendations': recommendations,
            'best_practices': best_practices
        }
