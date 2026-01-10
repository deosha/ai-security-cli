"""
Category 2: Model Security & Integrity Scorer

Scores the project's security posture for:
- Model Protection (encryption, access control, versioning)
- Extraction Defense (rate limiting, watermarking, API security)
- Supply Chain Security (verification, dependency scanning)

Each subcategory is scored 0-100 based on detected controls.
"""

import logging
from typing import Any, Dict, List

from aisentry.scorers.base_scorer import BaseScorer, CategoryScore

logger = logging.getLogger(__name__)


class ModelSecurityScorer(BaseScorer):
    """
    Score Category 2: Model Security & Integrity

    Evaluates:
    - 2.1 Model Protection (encryption, access control, versioning)
    - 2.2 Extraction Defense (rate limiting, watermarking, privacy)
    - 2.3 Supply Chain Security (verification, scanning)

    Framework-aware scoring for LangChain, LlamaIndex, and Haystack.
    """

    category_id = "2_model_security"
    category_name = "Model Security & Integrity"

    # Framework-specific patterns for model security
    LANGCHAIN_PATTERNS = {
        'api_key_management': [
            'get_openai_api_key', 'OPENAI_API_KEY', 'get_api_key',
            'load_dotenv', 'os.environ', 'os.getenv',
            'SecretStr', 'api_key_env'
        ],
        'callbacks': [
            'BaseCallbackHandler', 'AsyncCallbackHandler', 'CallbackManager',
            'callbacks=', 'callback_manager', 'StdOutCallbackHandler'
        ],
        'rate_limiting': [
            'max_tokens', 'request_timeout', 'max_retries',
            'RateLimiter', 'TokenBucket'
        ],
        'model_loading': [
            'from_pretrained', 'load_model', 'HuggingFaceHub',
            'CacheBackedEmbeddings', 'LocalFileStore'
        ],
        'security_config': [
            'allowed_special', 'disallowed_special', 'validate',
            'RunnableConfig', 'configurable_fields'
        ]
    }

    LLAMAINDEX_PATTERNS = {
        'service_context': [
            'ServiceContext', 'from_defaults', 'llm_predictor',
            'embed_model', 'node_parser', 'callback_manager'
        ],
        'api_keys': [
            'api_key=', 'OPENAI_API_KEY', 'set_global_service_context',
            'api_base', 'api_version'
        ],
        'callbacks': [
            'CallbackManager', 'TokenCountingHandler', 'LlamaDebugHandler',
            'callback_manager='
        ],
        'caching': [
            'SimpleDocumentStore', 'StorageContext', 'cache',
            'persist_dir', 'load_index_from_storage'
        ],
        'model_config': [
            'LLMPredictor', 'ChatMessage', 'Settings',
            'chunk_size', 'chunk_overlap'
        ]
    }

    HAYSTACK_PATTERNS = {
        'pipeline_security': [
            'Pipeline', 'add_node', 'run', 'run_batch',
            'params=', 'validation'
        ],
        'authentication': [
            'api_key=', 'use_auth_token', 'token=',
            'HuggingFaceAPIInvokationLayer', 'OpenAIAnswerGenerator'
        ],
        'document_stores': [
            'InMemoryDocumentStore', 'ElasticsearchDocumentStore',
            'FAISSDocumentStore', 'PineconeDocumentStore',
            'authenticate', 'ssl_cert'
        ],
        'rate_control': [
            'max_tokens', 'timeout', 'max_length',
            'top_k', 'batch_size'
        ],
        'model_loading': [
            'FARMReader', 'TransformersReader', 'model_name_or_path',
            'use_gpu', 'devices'
        ]
    }

    # Detection patterns for various security controls

    # 2.1 Model Protection
    ENCRYPTION_PATTERNS = {
        'at_rest': ['AES', 'encrypt', 'Fernet', 'cryptography'],
        'in_transit': ['https', 'tls', 'ssl', 'secure'],
        'hardware': ['tpm', 'hsm', 'enclave', 'sgx']
    }

    ACCESS_CONTROL_PATTERNS = {
        'basic_auth': ['HTTPBasicAuth', 'basic_auth', 'http_basic'],
        'rbac': ['@login_required', '@permission_required', 'check_permission', 'has_permission'],
        'abac': ['PolicyEngine', 'AttributeBasedAccessControl', 'abac'],
        'oauth': ['OAuth', 'oauth2', 'OAuthlib'],
        'mfa': ['totp', 'mfa', 'two_factor', '2fa'],
        'jwt': ['jwt', 'JsonWebToken', 'verify_token']
    }

    VERSIONING_PATTERNS = {
        'git': ['git', '.git', 'version_control'],
        'registry': ['mlflow', 'wandb', 'model_registry', 'ModelRegistry'],
        'immutable': ['immutable', 'readonly', 'signed_model']
    }

    # 2.2 Extraction Defense
    RATE_LIMITING_PATTERNS = [
        'rate_limit', 'RateLimiter', 'Limiter', 'throttle',
        '@limiter.limit', 'slowapi', 'flask_limiter'
    ]

    QUERY_ANALYSIS_PATTERNS = [
        'query_analyzer', 'pattern_detection', 'analyze_query',
        'detect_extraction', 'query_fingerprint'
    ]

    OUTPUT_PERTURBATION_PATTERNS = [
        'add_noise', 'perturbation', 'randomize', 'jitter',
        'output_variation'
    ]

    WATERMARKING_PATTERNS = [
        'watermark', 'Watermarking', 'embed_watermark',
        'watermark_detector', 'KGW', 'SynthID'
    ]

    DIFFERENTIAL_PRIVACY_PATTERNS = [
        'opacus', 'DifferentialPrivacy', 'dp_sgd',
        'PrivacyEngine', 'tf_privacy', 'diffprivlib'
    ]

    API_SECURITY_PATTERNS = {
        'token_based': ['api_key', 'APIKey', 'Authorization', 'Bearer'],
        'oauth': ['OAuth', 'oauth2'],
        'mtls': ['mtls', 'client_cert', 'mutual_tls', 'certificate_required']
    }

    # 2.3 Supply Chain Security
    VERIFICATION_PATTERNS = {
        'checksums': ['sha256', 'md5sum', 'hashlib', 'verify_checksum'],
        'signatures': ['gpg', 'signature', 'verify_signature', 'signed'],
        'attestation': ['attestation', 'provenance', 'SLSA'],
    }

    DEPENDENCY_SCANNING_PATTERNS = [
        'safety', 'pip-audit', 'snyk', 'dependabot',
        'vulnerability_scan', 'dependency_check'
    ]

    # Comprehensive API Key Security patterns
    API_KEY_SECURITY_PATTERNS = {
        'environment_variables': [
            'os.environ', 'os.getenv', 'load_dotenv', 'environ.get',
            'getenv', 'environment', 'env_var'
        ],
        'secret_management': [
            'aws_secrets_manager', 'HashiCorp Vault', 'vault', 'SecretManager',
            'Azure Key Vault', 'keyring', 'secrets', 'SecretStr'
        ],
        'key_rotation': [
            'rotate_key', 'key_rotation', 'rotate_secret', 'refresh_token',
            'renew_token', 'token_refresh'
        ],
        'key_encryption': [
            'encrypted_key', 'encrypt_secret', 'KMS', 'key_management_service',
            'envelope_encryption'
        ],
        'api_key_validation': [
            'validate_api_key', 'verify_key', 'check_api_key', 'key_validator',
            'api_key_check'
        ]
    }

    # Comprehensive Access Control patterns
    COMPREHENSIVE_ACCESS_CONTROL_PATTERNS = {
        'authentication': [
            'authenticate', 'login', 'LoginManager', 'auth_required',
            '@login_required', 'authenticate_user', 'verify_credentials'
        ],
        'authorization': [
            'authorize', 'check_permission', 'has_permission', '@permission_required',
            'can_access', 'is_authorized', 'authorization_check'
        ],
        'rbac': [
            'role_based_access', 'RBAC', 'RoleManager', 'assign_role',
            'check_role', 'user_role', '@role_required'
        ],
        'abac': [
            'attribute_based', 'ABAC', 'PolicyEngine', 'policy_check',
            'AttributeBasedAccessControl', 'evaluate_policy'
        ],
        'mfa': [
            'multi_factor', 'two_factor', 'MFA', '2FA', 'totp',
            'authenticator', 'verify_otp'
        ],
        'session_management': [
            'session', 'SessionManager', 'session_token', 'csrf_token',
            'session_timeout', 'session_expiry'
        ]
    }

    # Comprehensive Rate Limiting patterns
    COMPREHENSIVE_RATE_LIMITING_PATTERNS = {
        'request_throttling': [
            'rate_limit', 'RateLimiter', 'Limiter', 'throttle',
            '@limiter.limit', 'slowapi', 'flask_limiter', 'django_ratelimit'
        ],
        'token_limits': [
            'max_tokens', 'token_limit', 'token_budget', 'max_length',
            'max_output_tokens', 'token_count'
        ],
        'concurrent_limits': [
            'max_concurrent', 'concurrent_limit', 'connection_pool',
            'max_connections', 'semaphore', 'connection_limit'
        ],
        'dos_prevention': [
            'ddos_protection', 'dos_mitigation', 'traffic_filter',
            'abuse_detection', 'anomaly_detection', 'rate_limit_exceeded'
        ],
        'query_analysis': [
            'query_analyzer', 'pattern_detection', 'analyze_query',
            'detect_extraction', 'query_fingerprint', 'request_validation'
        ]
    }

    # Comprehensive Encryption patterns
    COMPREHENSIVE_ENCRYPTION_PATTERNS = {
        'at_rest': [
            'encrypt', 'encryption', 'AES', 'RSA', 'Fernet',
            'cryptography', 'encrypted_storage', 'encrypt_data'
        ],
        'in_transit': [
            'https', 'tls', 'ssl', 'TLS', 'SSL', 'secure_connection',
            'encrypted_transport', 'verify_ssl'
        ],
        'hardware_security': [
            'HSM', 'hardware_security_module', 'TPM', 'trusted_platform_module',
            'secure_enclave', 'SGX', 'TEE'
        ],
        'key_management': [
            'KMS', 'key_management', 'KeyManagementService', 'key_store',
            'master_key', 'encryption_key'
        ],
        'model_file_encryption': [
            'encrypt_model', 'encrypted_model', 'model_encryption',
            'secure_model_storage', 'encrypted_checkpoint'
        ]
    }

    # Comprehensive Model Provenance patterns
    MODEL_PROVENANCE_PATTERNS = {
        'model_registry': [
            'MLflow', 'mlflow', 'ModelRegistry', 'model_registry',
            'wandb', 'weights_biases', 'neptune', 'comet_ml'
        ],
        'version_control': [
            'git', 'version_control', 'git_lfs', 'dvc', 'data_version_control',
            'model_version', 'version_tag'
        ],
        'checksums': [
            'sha256', 'md5', 'checksum', 'hash', 'hashlib',
            'verify_checksum', 'compute_hash', 'file_hash'
        ],
        'signatures': [
            'sign', 'signature', 'digital_signature', 'verify_signature',
            'gpg', 'pgp', 'signed_model'
        ],
        'metadata_tracking': [
            'model_metadata', 'provenance', 'lineage', 'model_card',
            'training_metadata', 'ModelCard'
        ]
    }

    # Comprehensive Supply Chain patterns
    SUPPLY_CHAIN_VERIFICATION_PATTERNS = {
        'dependency_scanning': [
            'safety', 'pip-audit', 'snyk', 'dependabot', 'renovate',
            'vulnerability_scan', 'dependency_check', 'trivy'
        ],
        'sbom': [
            'SBOM', 'software_bill_of_materials', 'cyclonedx', 'spdx',
            'sbom_generation', 'dependency_graph'
        ],
        'attestation': [
            'attestation', 'provenance', 'SLSA', 'supply_chain_levels',
            'in_toto', 'sigstore', 'cosign'
        ],
        'trusted_sources': [
            'trusted_registry', 'official_model', 'verified_source',
            'huggingface_hub', 'model_zoo', 'trusted_publisher'
        ],
        'license_compliance': [
            'license_check', 'license_compliance', 'oss_license',
            'license_scanner', 'fossa'
        ]
    }

    def _score_api_key_security(self, parsed_data: Dict[str, Any]) -> int:
        """
        Score API Key Security (0-100) - Evidence-Based

        Uses multi-signal evidence collection to eliminate false positives.
        Requires import + instantiation/usage for confident detection.

        Scoring based on evidence strength:
        - Secret management + rotation + encryption + validation: 100
        - Secret management + rotation + encryption: 90
        - Secret management + encryption: 75
        - Secret management (STRONG evidence): 60
        - Environment variables (config evidence): 40
        - Weak/no evidence: 0
        """
        from aisentry.scorers.evidence_framework import EvidenceCollector, EvidenceStrength

        collector = EvidenceCollector(parsed_data)

        # Evidence 1: Secret Management Services (hvac, boto3, Azure Key Vault, etc.)
        secret_mgmt_evidence = collector.collect_library_evidence(
            control_name='secret_management',
            module_names=['hvac', 'boto3', 'azure.keyvault', 'google.cloud.secretmanager'],
            class_names=['Client', 'SecretClient', 'SecretManagerServiceClient'],
            function_names=['read', 'get_secret', 'get_secret_value', 'get_parameter']
        )

        # Evidence 2: Key Rotation (requires secret manager + rotation calls)
        rotation_evidence = collector.collect_library_evidence(
            control_name='key_rotation',
            module_names=['hvac', 'boto3'],
            class_names=['Client'],
            function_names=['rotate_secret', 'update_secret', 'put_parameter']
        )

        # Evidence 3: Key Encryption (KMS, encryption libraries)
        encryption_evidence = collector.collect_library_evidence(
            control_name='key_encryption',
            module_names=['boto3', 'azure.keyvault.keys', 'cryptography'],
            class_names=['Client', 'KeyClient', 'Fernet'],
            function_names=['encrypt', 'decrypt', 'generate_data_key']
        )

        # Evidence 4: API Key Validation
        validation_evidence = collector.collect_library_evidence(
            control_name='api_key_validation',
            module_names=[],  # Usually custom validation
            class_names=[],
            function_names=['validate_api_key', 'verify_key', 'check_api_key']
        )

        # Evidence 5: Environment Variables (config-based, weak evidence)
        env_var_evidence = collector.collect_config_evidence(
            control_name='env_vars',
            config_keys=['api_key', 'secret_key', 'token'],
            required_functions=['os.getenv', 'load_dotenv']
        )

        # Evaluate evidence strength
        has_secret_mgmt = secret_mgmt_evidence.is_confident()  # STRONG or MEDIUM
        has_rotation = rotation_evidence.is_confident()
        has_encryption = encryption_evidence.is_confident()
        has_validation = validation_evidence.strength in (EvidenceStrength.STRONG, EvidenceStrength.MEDIUM, EvidenceStrength.WEAK)
        has_env_vars = env_var_evidence.strength != EvidenceStrength.NONE

        # Score based on evidence combinations
        if has_secret_mgmt and has_rotation and has_encryption and has_validation:
            return 100
        elif has_secret_mgmt and has_rotation and has_encryption:
            return 90
        elif has_secret_mgmt and has_encryption:
            return 75
        elif has_secret_mgmt:
            return 60
        elif has_env_vars:
            return 40
        else:
            return 0

    def _score_model_access_control(self, parsed_data: Dict[str, Any]) -> int:
        """
        Score Model Access Control (0-100) - Evidence-Based

        Scoring based on access control sophistication:
        - MFA + (ABAC or RBAC) + Session management: 100
        - ABAC + MFA: 90
        - RBAC + MFA: 85
        - ABAC or RBAC with session management: 70
        - Authentication + Authorization: 50
        - Basic authentication only: 30
        - None detected: 0
        """
        from aisentry.scorers.evidence_framework import EvidenceCollector

        collector = EvidenceCollector(parsed_data)

        # Evidence 1: Authentication (import + usage)
        auth_evidence = collector.collect_library_evidence(
            control_name='authentication',
            module_names=['jwt', 'pyjwt', 'authlib', 'flask_login', 'django.contrib.auth', 'fastapi.security'],
            class_names=['JWTAuth', 'OAuth2PasswordBearer', 'HTTPBasic', 'HTTPBearer', 'AuthenticationMiddleware'],
            function_names=['authenticate', 'verify_token', 'check_password', 'login_required', 'verify_jwt']
        )

        # Evidence 2: Authorization (import + usage)
        authz_evidence = collector.collect_library_evidence(
            control_name='authorization',
            module_names=['casbin', 'flask_principal', 'django_guardian', 'fastapi_permissions'],
            class_names=['Enforcer', 'Permission', 'Identity', 'Principal'],
            function_names=['authorize', 'check_permission', 'enforce', 'has_permission', 'require_permission']
        )

        # Evidence 3: RBAC (decorator + config evidence)
        rbac_evidence = collector.collect_decorator_evidence(
            control_name='rbac',
            decorator_names=['require_role', 'roles_required', 'permission_required', 'has_role'],
            decorator_modules=['flask_security', 'django_rolepermissions', 'fastapi_permissions']
        )
        # Also check for RBAC library usage
        rbac_lib_evidence = collector.collect_library_evidence(
            control_name='rbac_library',
            module_names=['django_role_permissions', 'flask_security', 'py_abac'],
            class_names=['RoleChecker', 'RBACPolicy', 'PermissionManager'],
            function_names=['check_role', 'has_role', 'assign_role']
        )

        # Evidence 4: ABAC (attribute-based access control)
        abac_evidence = collector.collect_library_evidence(
            control_name='abac',
            module_names=['py_abac', 'casbin', 'oso'],
            class_names=['Policy', 'AttributePolicy', 'ABACEnforcer'],
            function_names=['evaluate_policy', 'check_attributes', 'abac_enforce']
        )

        # Evidence 5: MFA (multi-factor authentication)
        mfa_evidence = collector.collect_library_evidence(
            control_name='mfa',
            module_names=['pyotp', 'duo_client', 'twilio.rest'],
            class_names=['TOTP', 'HOTP', 'Auth', 'Client'],
            function_names=['verify_totp', 'verify_otp', 'send_verification', 'mfa_verify']
        )

        # Evidence 6: Session Management
        session_evidence = collector.collect_library_evidence(
            control_name='session_management',
            module_names=['flask_session', 'django.contrib.sessions', 'itsdangerous'],
            class_names=['Session', 'SessionStore', 'SessionMiddleware'],
            function_names=['create_session', 'invalidate_session', 'refresh_session', 'session_timeout']
        )

        # Evaluate evidence
        has_authentication = auth_evidence.is_confident()
        has_authorization = authz_evidence.is_confident()
        has_rbac = rbac_evidence.is_confident() or rbac_lib_evidence.is_confident()
        has_abac = abac_evidence.is_confident()
        has_mfa = mfa_evidence.is_confident()
        has_session = session_evidence.is_confident()

        # Apply scoring tiers
        if has_mfa and (has_abac or has_rbac) and has_session:
            return 100
        elif has_abac and has_mfa:
            return 90
        elif has_rbac and has_mfa:
            return 85
        elif (has_abac or has_rbac) and has_session:
            return 70
        elif has_authentication and has_authorization:
            return 50
        elif has_authentication:
            return 30
        else:
            return 0

    def _score_rate_limiting_defense(self, parsed_data: Dict[str, Any]) -> int:
        """
        Score Rate Limiting & DoS Defense (0-100) - Evidence-Based

        Scoring based on defensive layers:
        - Request throttling + Token limits + Concurrent limits + DoS prevention + Query analysis: 100
        - Request throttling + Token limits + Concurrent limits + DoS prevention: 90
        - Request throttling + Token limits + DoS prevention: 75
        - Request throttling + Token limits: 60
        - Request throttling or Token limits: 40
        - None detected: 0
        """
        from aisentry.scorers.evidence_framework import EvidenceCollector

        collector = EvidenceCollector(parsed_data)

        # Evidence 1: Request Throttling (decorator + library evidence)
        throttling_decorator = collector.collect_decorator_evidence(
            control_name='request_throttling',
            decorator_names=['rate_limit', 'throttle', 'limiter', 'ratelimit'],
            decorator_modules=['flask_limiter', 'django_ratelimit', 'slowapi']
        )
        throttling_lib = collector.collect_library_evidence(
            control_name='throttling_library',
            module_names=['flask_limiter', 'django_ratelimit', 'slowapi', 'ratelimit'],
            class_names=['Limiter', 'RateLimiter', 'ThrottleMiddleware'],
            function_names=['limit', 'rate_limit', 'throttle_request']
        )

        # Evidence 2: Token Limits (config + library evidence)
        token_limit_evidence = collector.collect_config_evidence(
            control_name='token_limits',
            config_keys=['max_tokens', 'token_limit', 'max_completion_tokens', 'token_budget'],
            required_functions=['tiktoken.encoding_for_model', 'count_tokens', 'truncate_tokens']
        )

        # Evidence 3: Concurrent Request Limits
        concurrent_evidence = collector.collect_library_evidence(
            control_name='concurrent_limits',
            module_names=['asyncio', 'concurrent.futures', 'threading'],
            class_names=['Semaphore', 'BoundedSemaphore', 'ThreadPoolExecutor'],
            function_names=['acquire', 'release', 'limit_concurrency']
        )
        # Also check for concurrent limiters in config
        concurrent_config = collector.collect_config_evidence(
            control_name='concurrent_config',
            config_keys=['max_concurrent_requests', 'concurrent_limit', 'max_workers'],
            required_functions=[]
        )

        # Evidence 4: DoS Prevention
        dos_evidence = collector.collect_library_evidence(
            control_name='dos_prevention',
            module_names=['slowapi', 'django_ratelimit', 'werkzeug.middleware.proxy_fix'],
            class_names=['DoSProtection', 'RequestValidator', 'CircuitBreaker'],
            function_names=['check_request_size', 'validate_payload', 'circuit_break']
        )

        # Evidence 5: Query Analysis (complexity detection)
        query_analysis_evidence = collector.collect_library_evidence(
            control_name='query_analysis',
            module_names=['graphql', 'sqlparse'],
            class_names=['QueryComplexityAnalyzer', 'DepthLimitValidator'],
            function_names=['analyze_complexity', 'check_depth', 'validate_query']
        )

        # Evaluate evidence
        has_throttling = throttling_decorator.is_confident() or throttling_lib.is_confident()
        has_token_limits = token_limit_evidence.is_confident()
        has_concurrent = concurrent_evidence.is_confident() or concurrent_config.is_confident()
        has_dos_prevention = dos_evidence.is_confident()
        has_query_analysis = query_analysis_evidence.is_confident()

        # Apply scoring tiers
        if has_throttling and has_token_limits and has_concurrent and has_dos_prevention and has_query_analysis:
            return 100
        elif has_throttling and has_token_limits and has_concurrent and has_dos_prevention:
            return 90
        elif has_throttling and has_token_limits and has_dos_prevention:
            return 75
        elif has_throttling and has_token_limits:
            return 60
        elif has_throttling or has_token_limits:
            return 40
        else:
            return 0

    def _score_model_encryption(self, parsed_data: Dict[str, Any]) -> int:
        """
        Score Model Encryption (0-100) - Evidence-Based

        Scoring based on encryption coverage:
        - Hardware security + At-rest + In-transit + Key management + Model file encryption: 100
        - At-rest + In-transit + Key management + Model file encryption: 90
        - At-rest + In-transit + Key management: 75
        - At-rest + In-transit: 60
        - In-transit only: 40
        - At-rest only: 30
        - None detected: 0
        """
        from aisentry.scorers.evidence_framework import EvidenceCollector

        collector = EvidenceCollector(parsed_data)

        # Evidence 1: At-rest Encryption
        at_rest_evidence = collector.collect_library_evidence(
            control_name='at_rest_encryption',
            module_names=['cryptography.fernet', 'cryptography.hazmat', 'nacl.secret', 'Crypto.Cipher'],
            class_names=['Fernet', 'AES', 'ChaCha20Poly1305', 'SecretBox'],
            function_names=['encrypt', 'decrypt', 'encrypt_file', 'encrypt_at_rest']
        )

        # Evidence 2: In-transit Encryption (TLS/SSL)
        in_transit_evidence = collector.collect_library_evidence(
            control_name='in_transit_encryption',
            module_names=['ssl', 'OpenSSL', 'certifi', 'urllib3'],
            class_names=['SSLContext', 'TLSContext', 'HTTPSConnectionPool'],
            function_names=['wrap_socket', 'create_default_context', 'check_hostname']
        )
        # Also check for HTTPS/TLS config
        tls_config = collector.collect_config_evidence(
            control_name='tls_config',
            config_keys=['ssl_verify', 'verify_ssl', 'cert_reqs', 'tls_version'],
            required_functions=[]
        )

        # Evidence 3: Hardware Security (HSM, TPM, Secure Enclave)
        hardware_evidence = collector.collect_library_evidence(
            control_name='hardware_security',
            module_names=['pkcs11', 'tpm2_pytss', 'yubico'],
            class_names=['PKCS11', 'TPM', 'YubiKey'],
            function_names=['initialize_hsm', 'use_tpm', 'hsm_encrypt']
        )

        # Evidence 4: Key Management
        key_mgmt_evidence = collector.collect_library_evidence(
            control_name='key_management',
            module_names=['boto3', 'azure.keyvault', 'google.cloud.kms', 'hvac'],
            class_names=['KMSClient', 'KeyClient', 'KeyManagementServiceClient'],
            function_names=['create_key', 'encrypt', 'decrypt', 'rotate_key', 'generate_data_key']
        )

        # Evidence 5: Model File Encryption
        model_encrypt_evidence = collector.collect_library_evidence(
            control_name='model_file_encryption',
            module_names=['cryptography', 'pyAesCrypt', 'pycryptodome'],
            class_names=['Fernet', 'AES'],
            function_names=['encrypt_model', 'decrypt_model', 'encrypt_file', 'save_encrypted']
        )

        # Evaluate evidence
        has_at_rest = at_rest_evidence.is_confident()
        has_in_transit = in_transit_evidence.is_confident() or tls_config.is_confident()
        has_hardware = hardware_evidence.is_confident()
        has_key_mgmt = key_mgmt_evidence.is_confident()
        has_model_encryption = model_encrypt_evidence.is_confident()

        # Apply scoring tiers
        if has_hardware and has_at_rest and has_in_transit and has_key_mgmt and has_model_encryption:
            return 100
        elif has_at_rest and has_in_transit and has_key_mgmt and has_model_encryption:
            return 90
        elif has_at_rest and has_in_transit and has_key_mgmt:
            return 75
        elif has_at_rest and has_in_transit:
            return 60
        elif has_in_transit:
            return 40
        elif has_at_rest:
            return 30
        else:
            return 0

    def _score_model_provenance(self, parsed_data: Dict[str, Any]) -> int:
        """
        Score Model Provenance & Tracking (0-100) - Evidence-Based

        Scoring based on tracking sophistication:
        - Model registry + Version control + Checksums + Signatures + Metadata: 100
        - Model registry + Version control + Checksums + Signatures: 90
        - Model registry + Version control + Checksums: 75
        - Model registry + Version control: 60
        - Version control + Checksums: 50
        - Version control only: 40
        - None detected: 0
        """
        from aisentry.scorers.evidence_framework import EvidenceCollector

        collector = EvidenceCollector(parsed_data)

        # Evidence 1: Model Registry
        registry_evidence = collector.collect_library_evidence(
            control_name='model_registry',
            module_names=['mlflow', 'wandb', 'huggingface_hub', 'clearml', 'neptune'],
            class_names=['MlflowClient', 'Run', 'HfApi', 'Task', 'ModelRegistry'],
            function_names=['log_model', 'register_model', 'upload_file', 'create_model_version']
        )

        # Evidence 2: Version Control (Git, DVC)
        version_control_evidence = collector.collect_library_evidence(
            control_name='version_control',
            module_names=['git', 'dvc', 'gitpython'],
            class_names=['Repo', 'Git', 'DVCRepo'],
            function_names=['commit', 'tag', 'push', 'dvc_add', 'track_model']
        )

        # Evidence 3: Checksums (SHA256, MD5)
        checksum_evidence = collector.collect_library_evidence(
            control_name='checksums',
            module_names=['hashlib', 'xxhash'],
            class_names=['sha256', 'md5', 'blake2b'],
            function_names=['sha256', 'md5', 'file_digest', 'compute_hash', 'verify_checksum']
        )

        # Evidence 4: Digital Signatures
        signature_evidence = collector.collect_library_evidence(
            control_name='signatures',
            module_names=['cryptography.hazmat.primitives.asymmetric', 'ecdsa', 'rsa'],
            class_names=['RSA', 'ECDSA', 'DSA'],
            function_names=['sign', 'verify', 'sign_file', 'verify_signature']
        )

        # Evidence 5: Metadata Tracking
        metadata_evidence = collector.collect_library_evidence(
            control_name='metadata_tracking',
            module_names=['mlflow', 'wandb', 'tensorboard'],
            class_names=['MlflowClient', 'Run', 'SummaryWriter'],
            function_names=['log_param', 'log_metric', 'log_artifact', 'set_tag', 'log_metadata']
        )

        # Evaluate evidence
        has_registry = registry_evidence.is_confident()
        has_version_control = version_control_evidence.is_confident()
        has_checksums = checksum_evidence.is_confident()
        has_signatures = signature_evidence.is_confident()
        has_metadata = metadata_evidence.is_confident()

        # Apply scoring tiers
        if has_registry and has_version_control and has_checksums and has_signatures and has_metadata:
            return 100
        elif has_registry and has_version_control and has_checksums and has_signatures:
            return 90
        elif has_registry and has_version_control and has_checksums:
            return 75
        elif has_registry and has_version_control:
            return 60
        elif has_version_control and has_checksums:
            return 50
        elif has_version_control:
            return 40
        else:
            return 0

    def _score_supply_chain_verification(self, parsed_data: Dict[str, Any]) -> int:
        """
        Score Supply Chain Verification (0-100) - Evidence-Based

        Scoring based on verification layers:
        - Dependency scanning + SBOM + Attestation + Trusted sources + License compliance: 100
        - Dependency scanning + SBOM + Attestation + Trusted sources: 90
        - Dependency scanning + SBOM + Attestation: 75
        - Dependency scanning + SBOM: 60
        - Dependency scanning or SBOM: 40
        - None detected: 0
        """
        from aisentry.scorers.evidence_framework import EvidenceCollector

        collector = EvidenceCollector(parsed_data)

        # Evidence 1: Dependency Scanning
        dep_scanning_evidence = collector.collect_library_evidence(
            control_name='dependency_scanning',
            module_names=['safety', 'pip_audit', 'bandit', 'semgrep'],
            class_names=['Safety', 'Auditor', 'Scanner'],
            function_names=['check', 'audit', 'scan_dependencies', 'check_vulnerabilities']
        )

        # Evidence 2: SBOM (Software Bill of Materials)
        sbom_evidence = collector.collect_library_evidence(
            control_name='sbom',
            module_names=['cyclonedx', 'spdx', 'syft'],
            class_names=['BomGenerator', 'Document', 'SBOM'],
            function_names=['generate_sbom', 'create_bom', 'export_sbom']
        )

        # Evidence 3: Attestation (Sigstore, in-toto)
        attestation_evidence = collector.collect_library_evidence(
            control_name='attestation',
            module_names=['sigstore', 'in_toto', 'notary'],
            class_names=['Signer', 'Attestation', 'Verifier'],
            function_names=['sign', 'attest', 'verify_attestation', 'create_attestation']
        )

        # Evidence 4: Trusted Sources
        trusted_sources_evidence = collector.collect_config_evidence(
            control_name='trusted_sources',
            config_keys=['trusted_host', 'index_url', 'extra_index_url', 'trusted_registry'],
            required_functions=['verify_source', 'check_registry']
        )

        # Evidence 5: License Compliance
        license_evidence = collector.collect_library_evidence(
            control_name='license_compliance',
            module_names=['licensecheck', 'license_expression', 'pip_licenses'],
            class_names=['LicenseChecker', 'LicenseScanner'],
            function_names=['check_license', 'scan_licenses', 'verify_compliance']
        )

        # Evaluate evidence
        has_dep_scanning = dep_scanning_evidence.is_confident()
        has_sbom = sbom_evidence.is_confident()
        has_attestation = attestation_evidence.is_confident()
        has_trusted_sources = trusted_sources_evidence.is_confident()
        has_license = license_evidence.is_confident()

        # Apply scoring tiers
        if has_dep_scanning and has_sbom and has_attestation and has_trusted_sources and has_license:
            return 100
        elif has_dep_scanning and has_sbom and has_attestation and has_trusted_sources:
            return 90
        elif has_dep_scanning and has_sbom and has_attestation:
            return 75
        elif has_dep_scanning and has_sbom:
            return 60
        elif has_dep_scanning or has_sbom:
            return 40
        else:
            return 0

    def calculate_score(self, parsed_data: Dict[str, Any]) -> CategoryScore:
        """
        Calculate Model Security & Integrity score with framework detection

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
        model_protection_score = self._score_model_protection(
            imports, functions, source_code, detected_frameworks
        )

        extraction_defense_score = self._score_extraction_defense(
            imports, functions, source_code, detected_frameworks
        )

        supply_chain_score = self._score_supply_chain_security(
            imports, source_code, detected_frameworks
        )

        # Calculate new comprehensive subscores
        api_key_security_score = self._score_api_key_security(parsed_data)
        model_access_control_score = self._score_model_access_control(parsed_data)
        rate_limiting_defense_score = self._score_rate_limiting_defense(parsed_data)
        model_encryption_score = self._score_model_encryption(parsed_data)
        model_provenance_score = self._score_model_provenance(parsed_data)
        supply_chain_verification_score = self._score_supply_chain_verification(parsed_data)

        # Calculate weighted overall score with new comprehensive subscores
        overall_score = self._weighted_average(
            scores=[
                api_key_security_score,       # Most critical - key management
                model_access_control_score,   # Critical - who can access
                rate_limiting_defense_score,  # Critical - DoS prevention
                model_encryption_score,        # Important - data protection
                model_provenance_score,        # Important - tracking
                supply_chain_verification_score, # Important - trust
                model_protection_score,        # Legacy (small weight)
                extraction_defense_score,      # Legacy (small weight)
                supply_chain_score             # Legacy (small weight)
            ],
            weights=[
                0.25,  # api_key_security - highest priority
                0.20,  # model_access_control - critical access control
                0.20,  # rate_limiting_defense - critical DoS prevention
                0.15,  # model_encryption - important protection
                0.10,  # model_provenance - important tracking
                0.07,  # supply_chain_verification - important trust
                0.01,  # model_protection (legacy)
                0.01,  # extraction_defense (legacy)
                0.01   # supply_chain_security (legacy)
            ]
        )

        # Get all detected controls
        detected_controls = self._get_all_detections(source_code, imports, detected_frameworks)

        # Calculate confidence (boost for framework detection)
        base_confidence = 0.7 + (len(detected_frameworks) * 0.05)  # +5% per framework
        confidence = self._calculate_confidence(
            detection_count=len(detected_controls),
            total_possible=20,  # Approximate total controls we check for
            base_confidence=min(base_confidence, 0.95)  # Cap at 95%
        )

        # Identify gaps
        gaps = self._identify_gaps(
            model_protection_score,
            extraction_defense_score,
            supply_chain_score,
            detected_frameworks
        )

        # Generate framework insights
        framework_insights = {}
        if detected_frameworks:
            for framework in detected_frameworks:
                framework_insights[framework] = self._get_framework_insights(
                    framework,
                    framework_features.get(framework, {}),
                    model_protection_score,
                    extraction_defense_score,
                    supply_chain_score
                )

        return CategoryScore(
            category_id=self.category_id,
            category_name=self.category_name,
            score=overall_score,
            confidence=confidence,
            subscores={
                # Legacy subscores (backward compatibility)
                'model_protection': model_protection_score,
                'extraction_defense': extraction_defense_score,
                'supply_chain_security': supply_chain_score,
                # New comprehensive subscores
                'api_key_security': api_key_security_score,
                'model_access_control': model_access_control_score,
                'rate_limiting_defense': rate_limiting_defense_score,
                'model_encryption': model_encryption_score,
                'model_provenance': model_provenance_score,
                'supply_chain_verification': supply_chain_verification_score
            },
            detected_controls=detected_controls,
            gaps=gaps,
            evidence={
                'has_encryption': model_protection_score > 0,
                'has_extraction_defense': extraction_defense_score > 0,
                'has_supply_chain_controls': supply_chain_score > 0,
                'detected_frameworks': detected_frameworks,
                'framework_insights': framework_insights,
                # New subscore evidence
                'api_key_security_score': api_key_security_score,
                'model_access_control_score': model_access_control_score,
                'rate_limiting_defense_score': rate_limiting_defense_score,
                'model_encryption_score': model_encryption_score,
                'model_provenance_score': model_provenance_score,
                'supply_chain_verification_score': supply_chain_verification_score
            }
        )

    def _score_model_protection(
        self,
        imports: List[Dict[str, Any]],
        functions: List[Dict[str, Any]],
        source_code: str,
        detected_frameworks: List[str] = None
    ) -> int:
        """Score 2.1: Model Protection with framework awareness"""
        if detected_frameworks is None:
            detected_frameworks = []

        # Weight Encryption (0-100)
        encryption_score = 0
        has_at_rest = any(
            pattern in source_code
            for pattern in self.ENCRYPTION_PATTERNS['at_rest']
        )
        has_in_transit = any(
            pattern in source_code
            for pattern in self.ENCRYPTION_PATTERNS['in_transit']
        )
        has_hardware = any(
            pattern in source_code
            for pattern in self.ENCRYPTION_PATTERNS['hardware']
        )

        if has_hardware:
            encryption_score = 100
        elif has_at_rest and has_in_transit:
            encryption_score = 75
        elif has_in_transit:
            encryption_score = 50
        elif has_at_rest:
            encryption_score = 25

        # Access Control Model (0-100)
        access_control_score = 0
        has_mfa = any(
            pattern in source_code
            for pattern in self.ACCESS_CONTROL_PATTERNS['mfa']
        )
        has_abac = any(
            pattern in source_code
            for pattern in self.ACCESS_CONTROL_PATTERNS['abac']
        )
        has_rbac = any(
            pattern in source_code
            for pattern in self.ACCESS_CONTROL_PATTERNS['rbac']
        )
        has_oauth = any(
            pattern in source_code
            for pattern in self.ACCESS_CONTROL_PATTERNS['oauth']
        )
        has_jwt = any(
            pattern in source_code
            for pattern in self.ACCESS_CONTROL_PATTERNS['jwt']
        )
        has_basic = any(
            pattern in source_code
            for pattern in self.ACCESS_CONTROL_PATTERNS['basic_auth']
        )

        if has_mfa and (has_abac or has_rbac):
            access_control_score = 100  # Zero Trust + MFA
        elif has_abac:
            access_control_score = 75
        elif has_rbac:
            access_control_score = 50
        elif has_oauth or has_jwt:
            access_control_score = 40
        elif has_basic:
            access_control_score = 25

        # Model Versioning (0-100)
        versioning_score = 0
        has_immutable = any(
            pattern in source_code
            for pattern in self.VERSIONING_PATTERNS['immutable']
        )
        has_registry = any(
            pattern in source_code
            for pattern in self.VERSIONING_PATTERNS['registry']
        )
        has_git = any(
            pattern in source_code
            for pattern in self.VERSIONING_PATTERNS['git']
        )

        if has_immutable:
            versioning_score = 100
        elif has_registry:
            versioning_score = 75
        elif has_git:
            versioning_score = 50
        elif 'version' in source_code:
            versioning_score = 25  # Basic versioning

        # Average the three components
        return int((encryption_score + access_control_score + versioning_score) / 3)

    def _score_extraction_defense(
        self,
        imports: List[Dict[str, Any]],
        functions: List[Dict[str, Any]],
        source_code: str,
        detected_frameworks: List[str] = None
    ) -> int:
        """Score 2.2: Extraction Defense with framework awareness"""
        if detected_frameworks is None:
            detected_frameworks = []

        # Anti-Extraction Measures (checkboxes, 20 points each)
        measures_score = 0

        has_rate_limiting = any(
            pattern in source_code
            for pattern in self.RATE_LIMITING_PATTERNS
        )
        if has_rate_limiting:
            measures_score += 20

        has_query_analysis = any(
            pattern in source_code
            for pattern in self.QUERY_ANALYSIS_PATTERNS
        )
        if has_query_analysis:
            measures_score += 20

        has_output_perturbation = any(
            pattern in source_code
            for pattern in self.OUTPUT_PERTURBATION_PATTERNS
        )
        if has_output_perturbation:
            measures_score += 20

        has_watermarking = any(
            pattern in source_code
            for pattern in self.WATERMARKING_PATTERNS
        )
        if has_watermarking:
            measures_score += 20

        has_differential_privacy = any(
            pattern in source_code
            for pattern in self.DIFFERENTIAL_PRIVACY_PATTERNS
        )
        if has_differential_privacy:
            measures_score += 20

        # API Security Level (0-100)
        api_security_score = 0
        has_mtls = any(
            pattern in source_code
            for pattern in self.API_SECURITY_PATTERNS['mtls']
        )
        has_oauth_api = any(
            pattern in source_code
            for pattern in self.API_SECURITY_PATTERNS['oauth']
        )
        has_token = any(
            pattern in source_code
            for pattern in self.API_SECURITY_PATTERNS['token_based']
        )

        if has_mtls:
            api_security_score = 100
        elif has_oauth_api:
            api_security_score = 75
        elif has_token:
            api_security_score = 50
        elif 'authorization' in source_code or 'authenticate' in source_code:
            api_security_score = 25  # Basic auth

        # Average the two components
        return int((measures_score + api_security_score) / 2)

    def _score_supply_chain_security(
        self,
        imports: List[Dict[str, Any]],
        source_code: str,
        detected_frameworks: List[str] = None
    ) -> int:
        """Score 2.3: Supply Chain Security with framework awareness"""
        if detected_frameworks is None:
            detected_frameworks = []

        # Model Source Verification (0-100)
        verification_score = 0
        has_attestation = any(
            pattern in source_code
            for pattern in self.VERIFICATION_PATTERNS['attestation']
        )
        has_signatures = any(
            pattern in source_code
            for pattern in self.VERIFICATION_PATTERNS['signatures']
        )
        has_checksums = any(
            pattern in source_code
            for pattern in self.VERIFICATION_PATTERNS['checksums']
        )

        if has_attestation and has_signatures and has_checksums:
            verification_score = 100  # Full chain
        elif has_attestation:
            verification_score = 75
        elif has_signatures:
            verification_score = 50
        elif has_checksums:
            verification_score = 25

        # Dependency Scanning (0-100)
        scanning_score = 0
        has_dependency_scanning = any(
            pattern in source_code
            for pattern in self.DEPENDENCY_SCANNING_PATTERNS
        )

        if has_dependency_scanning:
            # Check if automated/continuous
            if 'ci' in source_code or 'github' in source_code or 'gitlab' in source_code:
                scanning_score = 75  # Automated
            else:
                scanning_score = 50  # Scheduled

        # Average the two components
        return int((verification_score + scanning_score) / 2)

    def _get_all_detections(self, source_code: str, imports: List[Dict[str, Any]],
                           detected_frameworks: List[str] = None) -> List[str]:
        """Get list of all detected security controls"""
        if detected_frameworks is None:
            detected_frameworks = []

        detections = []

        # Check encryption
        if any(p in source_code for p in self.ENCRYPTION_PATTERNS['at_rest']):
            detections.append("Encryption at rest")
        if any(p in source_code for p in self.ENCRYPTION_PATTERNS['in_transit']):
            detections.append("Encryption in transit")

        # Check access control
        if any(p in source_code for p in self.ACCESS_CONTROL_PATTERNS['rbac']):
            detections.append("RBAC")
        if any(p in source_code for p in self.ACCESS_CONTROL_PATTERNS['oauth']):
            detections.append("OAuth")

        # Check versioning
        if any(p in source_code for p in self.VERSIONING_PATTERNS['registry']):
            detections.append("Model registry")

        # Check extraction defenses
        if any(p in source_code for p in self.RATE_LIMITING_PATTERNS):
            detections.append("Rate limiting")
        if any(p in source_code for p in self.WATERMARKING_PATTERNS):
            detections.append("Watermarking")
        if any(p in source_code for p in self.DIFFERENTIAL_PRIVACY_PATTERNS):
            detections.append("Differential privacy")

        # Check supply chain
        if any(p in source_code for p in self.VERIFICATION_PATTERNS['checksums']):
            detections.append("Checksum verification")
        if any(p in source_code for p in self.VERIFICATION_PATTERNS['signatures']):
            detections.append("Signature verification")

        return detections

    def _identify_gaps(
        self,
        model_protection_score: int,
        extraction_defense_score: int,
        supply_chain_score: int,
        detected_frameworks: List[str] = None
    ) -> List[str]:
        """Identify security gaps (scores < 40)"""
        if detected_frameworks is None:
            detected_frameworks = []

        gaps = []

        if model_protection_score < 40:
            gaps.append("Model protection needs improvement")
            gaps.append("Consider implementing encryption and access controls")

        if extraction_defense_score < 40:
            gaps.append("Extraction defense is weak")
            gaps.append("Implement rate limiting and output protections")

        if supply_chain_score < 40:
            gaps.append("Supply chain security needs attention")
            gaps.append("Add model verification and dependency scanning")

        return gaps

    def _detect_frameworks(self, parsed_data: Dict[str, Any]) -> List[str]:
        """Detect which LLM frameworks are being used"""
        frameworks = []
        all_text = ' '.join(parsed_data.get('source_lines', [])).lower()

        # Check for LangChain
        if any(indicator in all_text for indicator in ['langchain', 'langchain_core', 'langchain_community']):
            frameworks.append('langchain')

        # Check for LlamaIndex
        if any(indicator in all_text for indicator in ['llama_index', 'llamaindex', 'from llama_index']):
            frameworks.append('llamaindex')

        # Check for Haystack
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
                'api_key_management': any(p.lower() in all_text for p in patterns['api_key_management']),
                'callbacks': any(p.lower() in all_text for p in patterns['callbacks']),
                'rate_limiting': any(p.lower() in all_text for p in patterns['rate_limiting']),
                'model_loading': any(p.lower() in all_text for p in patterns['model_loading']),
                'security_config': any(p.lower() in all_text for p in patterns['security_config'])
            }
        elif framework == 'llamaindex':
            patterns = self.LLAMAINDEX_PATTERNS
            features = {
                'service_context': any(p.lower() in all_text for p in patterns['service_context']),
                'api_keys': any(p.lower() in all_text for p in patterns['api_keys']),
                'callbacks': any(p.lower() in all_text for p in patterns['callbacks']),
                'caching': any(p.lower() in all_text for p in patterns['caching']),
                'model_config': any(p.lower() in all_text for p in patterns['model_config'])
            }
        elif framework == 'haystack':
            patterns = self.HAYSTACK_PATTERNS
            features = {
                'pipeline_security': any(p.lower() in all_text for p in patterns['pipeline_security']),
                'authentication': any(p.lower() in all_text for p in patterns['authentication']),
                'document_stores': any(p.lower() in all_text for p in patterns['document_stores']),
                'rate_control': any(p.lower() in all_text for p in patterns['rate_control']),
                'model_loading': any(p.lower() in all_text for p in patterns['model_loading'])
            }

        return features

    def _get_framework_insights(
        self,
        framework: str,
        features: Dict[str, bool],
        model_protection_score: int,
        extraction_defense_score: int,
        supply_chain_score: int
    ) -> Dict[str, Any]:
        """Generate security insights for detected framework"""
        recommendations = []
        best_practices = []

        if framework == 'langchain':
            # Best practices
            if features.get('api_key_management'):
                best_practices.append("Using environment variables for API keys (good security practice)")
            if features.get('callbacks'):
                best_practices.append("Using callbacks for monitoring and logging")
            if features.get('rate_limiting'):
                best_practices.append("Implementing rate limiting on model calls")

            # Recommendations
            if not features.get('callbacks'):
                recommendations.append("Add BaseCallbackHandler for monitoring and security logging")
            if not features.get('security_config'):
                recommendations.append("Use RunnableConfig with allowed_special/disallowed_special for input safety")
            if model_protection_score < 60:
                recommendations.append("Consider using CacheBackedEmbeddings for efficient and secure caching")

        elif framework == 'llamaindex':
            # Best practices
            if features.get('service_context'):
                best_practices.append("Using ServiceContext for centralized configuration")
            if features.get('callbacks'):
                best_practices.append("Implementing callback handlers for observability")
            if features.get('caching'):
                best_practices.append("Using document stores for efficient caching")

            # Recommendations
            if not features.get('callbacks'):
                recommendations.append("Add TokenCountingHandler or LlamaDebugHandler for monitoring")
            if not features.get('api_keys'):
                recommendations.append("Ensure API keys are properly managed (environment variables or secrets management)")
            if extraction_defense_score < 60:
                recommendations.append("Configure chunk_size and chunk_overlap limits to prevent extraction attacks")

        elif framework == 'haystack':
            # Best practices
            if features.get('authentication'):
                best_practices.append("Using authentication tokens for API access")
            if features.get('pipeline_security'):
                best_practices.append("Using Pipeline structure for controlled execution flow")
            if features.get('document_stores'):
                best_practices.append("Using secure document stores with authentication")

            # Recommendations
            if not features.get('rate_control'):
                recommendations.append("Add max_tokens and timeout limits to prevent resource exhaustion")
            if not features.get('authentication'):
                recommendations.append("Enable authentication on document stores and API layers")
            if supply_chain_score < 60:
                recommendations.append("Verify model sources when loading models with FARMReader or TransformersReader")

        return {
            'detected_features': features,
            'security_recommendations': recommendations,
            'best_practices': best_practices
        }
