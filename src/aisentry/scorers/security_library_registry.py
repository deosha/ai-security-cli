"""
Security Library Registry

Normalized mapping of known security libraries and their patterns.
Used for evidence-based scoring to reduce false positives.
"""

from typing import Dict, Set


class SecurityLibraryRegistry:
    """
    Registry of known security libraries with fully-qualified names

    This enables precise matching against import statements and instantiations
    instead of ambiguous string matching.
    """

    # Secret Management Libraries
    SECRET_MANAGERS = {
        'hvac': {'Client': 'HashiCorp Vault client'},
        'azure.keyvault.secrets': {'SecretClient': 'Azure Key Vault'},
        'google.cloud.secretmanager': {'SecretManagerServiceClient': 'GCP Secret Manager'},
        'boto3': {
            'client:secretsmanager': 'AWS Secrets Manager',
            'client:ssm': 'AWS Systems Manager Parameter Store'
        },
        'keyring': {'get_password': 'System keyring', 'set_password': 'System keyring'},
        'python-dotenv': {'load_dotenv': 'Environment variable loader'},
    }

    # Rate Limiting Libraries
    RATE_LIMITERS = {
        'flask_limiter': {'Limiter': 'Flask rate limiter'},
        'slowapi': {'Limiter': 'FastAPI rate limiter'},
        'django_ratelimit': {'ratelimit': 'Django rate limiter'},
        'ratelimit': {'limits': 'Generic rate limiter'},
        'aiohttp_ratelimit': {'RateLimiter': 'aiohttp rate limiter'},
    }

    # PII Detection Libraries
    PII_DETECTORS = {
        'presidio_analyzer': {'AnalyzerEngine': 'Microsoft Presidio analyzer', 'RecognizerRegistry': 'Microsoft Presidio analyzer'},
        'presidio_anonymizer': {'AnonymizerEngine': 'Microsoft Presidio anonymizer', 'PresidioAnonymizer': 'Microsoft Presidio anonymizer'},
        'spacy': {'load': 'spaCy NER'},
        'transformers': {'pipeline': 'Hugging Face transformers', 'AutoModelForTokenClassification': 'Hugging Face transformers'},
    }

    # Bias Detection Libraries
    BIAS_DETECTORS = {
        'fairlearn': {
            'MetricFrame': 'Microsoft Fairlearn', 'ThresholdOptimizer': 'Microsoft Fairlearn', 'DemographicParity': 'Microsoft Fairlearn'
        },
        'aif360': {
            'BinaryLabelDataset': 'IBM AI Fairness 360', 'Reweighing': 'IBM AI Fairness 360', 'DisparateImpactRemover': 'IBM AI Fairness 360'
        },
        'what-if-tool': {'WitWidget': 'Google What-If Tool'},
    }

    # Explainability Libraries
    EXPLAINABILITY_LIBS = {
        'shap': {
            'Explainer': 'SHAP', 'TreeExplainer': 'SHAP', 'KernelExplainer': 'SHAP', 'DeepExplainer': 'SHAP'
        },
        'lime': {
            'LimeTextExplainer': 'LIME', 'LimeTabularExplainer': 'LIME', 'LimeImageExplainer': 'LIME'
        },
        'eli5': {
            'explain_weights': 'ELI5', 'explain_prediction': 'ELI5'
        },
        'captum': {
            'IntegratedGradients': 'Captum', 'LayerIntegratedGradients': 'Captum'
        },
    }

    # Toxicity/Content Moderation Libraries
    CONTENT_MODERATORS = {
        'detoxify': {'Detoxify': 'Detoxify toxicity classifier'},
        'perspective': {'PerspectiveAPI': 'Perspective API'},
        'openai': {'Moderation': 'OpenAI moderation API'},
        'guardrails': {'Guard': 'Guardrails AI'},
        'better_profanity': {'profanity': 'Better Profanity filter'},
    }

    # Authorization Libraries
    AUTHORIZATION_LIBS = {
        'casbin': {'Enforcer': 'Casbin RBAC/ABAC'},
        'flask_principal': {'Principal': 'Flask-Principal', 'Permission': 'Flask-Principal'},
        'django.contrib.auth': {'permission_required': 'Django permissions'},
        'pycasbin': {'Enforcer': 'PyCasbin'},
    }

    # Audit Logging Libraries
    AUDIT_LOGGERS = {
        'structlog': {'get_logger': 'Structured logging'},
        'python-json-logger': {'JsonFormatter': 'JSON logging'},
        'elasticsearch': {'Elasticsearch': 'Elasticsearch logging'},
        'datadog': {'DogStatsd': 'Datadog logging'},
    }

    # Input Validation Libraries
    VALIDATION_LIBS = {
        'pydantic': {'BaseModel': 'Pydantic validation', 'validator': 'Pydantic validation', 'Field': 'Pydantic validation'},
        'marshmallow': {'Schema': 'Marshmallow validation', 'validate': 'Marshmallow validation', 'fields': 'Marshmallow validation'},
        'cerberus': {'Validator': 'Cerberus validation', 'validate': 'Cerberus validation'},
        'voluptuous': {'Schema': 'Voluptuous validation', 'Required': 'Voluptuous validation'},
        'jsonschema': {'validate': 'JSON Schema validation', 'Draft7Validator': 'JSON Schema validation'},
    }

    # Prompt Injection Defense Libraries
    PROMPT_INJECTION_DEFENSE = {
        'langkit': {'PromptInjectionDetector': 'LangKit prompt injection defense', 'detect': 'LangKit detection'},
        'rebuff': {'RebuffSdk': 'Rebuff prompt injection defense', 'detect_injection': 'Rebuff detection'},
        'llm_guard': {'Scanner': 'LLM Guard', 'InputScanner': 'LLM Guard input scanner', 'PromptInjection': 'LLM Guard prompt injection'},
        'nemoguardrails': {'RailsConfig': 'NeMo Guardrails', 'LLMRails': 'NeMo Guardrails', 'generate': 'NeMo Guardrails'},
        'lakera': {'guard': 'Lakera Guard', 'prompt_injection_check': 'Lakera Guard'},
    }

    # Monitoring & Observability Libraries
    MONITORING_LIBS = {
        'langfuse': {'Langfuse': 'Langfuse LLM observability', 'trace': 'Langfuse tracing', 'observe': 'Langfuse observation'},
        'langsmith': {'Client': 'LangSmith', 'create_run': 'LangSmith run tracking', 'trace': 'LangSmith tracing'},
        'phoenix': {'launch_app': 'Phoenix tracing', 'trace': 'Phoenix tracing'},
        'opentelemetry': {'trace': 'OpenTelemetry', 'Tracer': 'OpenTelemetry tracer'},
        'logging': {'Logger': 'Python logging', 'getLogger': 'Python logging', 'info': 'Python logging'},
    }

    # Template Libraries
    TEMPLATE_LIBS = {
        'langchain': {'PromptTemplate': 'LangChain templates', 'ChatPromptTemplate': 'LangChain chat templates', 'FewShotPromptTemplate': 'LangChain few-shot'},
        'langchain_core.prompts': {'PromptTemplate': 'LangChain templates', 'ChatPromptTemplate': 'LangChain chat templates'},
        'llama_index': {'PromptTemplate': 'LlamaIndex templates', 'SelectorPromptTemplate': 'LlamaIndex selector'},
        'haystack': {'PromptNode': 'Haystack prompt node', 'PromptTemplate': 'Haystack templates'},
        'jinja2': {'Template': 'Jinja2 templating', 'Environment': 'Jinja2 environment'},
    }

    # Output Filtering/Sanitization Libraries
    OUTPUT_FILTERING = {
        'bleach': {'clean': 'Bleach HTML sanitization', 'linkify': 'Bleach linkification'},
        'html': {'escape': 'HTML escaping', 'unescape': 'HTML unescaping'},
        'markupsafe': {'escape': 'MarkupSafe escaping', 'Markup': 'MarkupSafe'},
        'langchain': {'OutputParser': 'LangChain output parser', 'StructuredOutputParser': 'LangChain structured parser'},
        'pydantic': {'BaseModel': 'Pydantic output validation'},  # Can be used for output validation too
    }

    # PII Redaction Libraries (expanded from PII_DETECTORS)
    PII_REDACTION_LIBS = {
        'presidio_analyzer': {'AnalyzerEngine': 'Presidio analyzer', 'RecognizerRegistry': 'Presidio registry'},
        'presidio_anonymizer': {'AnonymizerEngine': 'Presidio anonymizer', 'AnonymizerConfig': 'Presidio config'},
        'scrubadub': {'clean': 'Scrubadub cleaning', 'Scrubber': 'Scrubadub scrubber'},
        'spacy': {'load': 'spaCy NER for PII'},
        'langchain': {'PresidioAnonymizer': 'LangChain Presidio', 'PIIRedactionTransformer': 'LangChain PII redaction'},
    }

    # Encryption Libraries
    ENCRYPTION_LIBS = {
        'cryptography': {'Fernet': 'Symmetric encryption', 'generate_key': 'Key generation'},
        'Crypto': {'AES': 'AES encryption', 'RSA': 'RSA encryption'},
        'boto3': {'client:kms': 'AWS KMS'},
        'azure.keyvault.keys': {'KeyClient': 'Azure Key Vault', 'CryptographyClient': 'Azure crypto'},
        'google.cloud.kms': {'KeyManagementServiceClient': 'GCP KMS'},
    }

    # Access Control Libraries (expanded from AUTHORIZATION_LIBS)
    ACCESS_CONTROL_LIBS = {
        'flask_login': {'LoginManager': 'Flask-Login', 'login_required': 'Flask login decorator'},
        'django.contrib.auth': {'authenticate': 'Django auth', 'permission_required': 'Django permissions'},
        'fastapi': {'Depends': 'FastAPI dependencies', 'Security': 'FastAPI security'},
        'casbin': {'Enforcer': 'Casbin RBAC'},
        'authlib': {'OAuth2': 'Authlib OAuth2'},
    }

    # Vector Database / RAG Libraries
    VECTOR_DB_LIBS = {
        'chromadb': {'Client': 'ChromaDB client', 'Collection': 'ChromaDB collection'},
        'pinecone': {'init': 'Pinecone init', 'Index': 'Pinecone index'},
        'weaviate': {'Client': 'Weaviate client'},
        'qdrant_client': {'QdrantClient': 'Qdrant client'},
        'langchain': {'Chroma': 'LangChain Chroma', 'Pinecone': 'LangChain Pinecone', 'RetrievalQA': 'LangChain RAG'},
        'llama_index': {'VectorStoreIndex': 'LlamaIndex vector store', 'StorageContext': 'LlamaIndex storage'},
    }

    # ML Versioning / Governance Libraries
    ML_VERSIONING_LIBS = {
        'mlflow': {'log_model': 'MLflow model logging', 'start_run': 'MLflow run', 'MlflowClient': 'MLflow client'},
        'dvc': {'api': 'DVC API', 'Remote': 'DVC remote'},
        'wandb': {'init': 'Weights & Biases init', 'log': 'W&B logging'},
    }

    @classmethod
    def is_secret_manager(cls, module: str, class_name: str = '') -> bool:
        """Check if module.class represents a secret manager"""
        return cls._check_library(cls.SECRET_MANAGERS, module, class_name)

    @classmethod
    def is_rate_limiter(cls, module: str, class_name: str = '') -> bool:
        """Check if module.class represents a rate limiter"""
        return cls._check_library(cls.RATE_LIMITERS, module, class_name)

    @classmethod
    def is_pii_detector(cls, module: str, class_name: str = '') -> bool:
        """Check if module.class represents a PII detector"""
        return cls._check_library(cls.PII_DETECTORS, module, class_name)

    @classmethod
    def is_bias_detector(cls, module: str, class_name: str = '') -> bool:
        """Check if module.class represents a bias detector"""
        return cls._check_library(cls.BIAS_DETECTORS, module, class_name)

    @classmethod
    def is_explainability_lib(cls, module: str, class_name: str = '') -> bool:
        """Check if module.class represents an explainability library"""
        return cls._check_library(cls.EXPLAINABILITY_LIBS, module, class_name)

    @classmethod
    def is_content_moderator(cls, module: str, class_name: str = '') -> bool:
        """Check if module.class represents a content moderator"""
        return cls._check_library(cls.CONTENT_MODERATORS, module, class_name)

    @classmethod
    def is_authorization_lib(cls, module: str, class_name: str = '') -> bool:
        """Check if module.class represents an authorization library"""
        return cls._check_library(cls.AUTHORIZATION_LIBS, module, class_name)

    @classmethod
    def is_audit_logger(cls, module: str, class_name: str = '') -> bool:
        """Check if module.class represents an audit logger"""
        return cls._check_library(cls.AUDIT_LOGGERS, module, class_name)

    @classmethod
    def is_validation_lib(cls, module: str, class_name: str = '') -> bool:
        """Check if module.class represents an input validation library"""
        return cls._check_library(cls.VALIDATION_LIBS, module, class_name)

    @classmethod
    def is_prompt_injection_defense(cls, module: str, class_name: str = '') -> bool:
        """Check if module.class represents a prompt injection defense library"""
        return cls._check_library(cls.PROMPT_INJECTION_DEFENSE, module, class_name)

    @classmethod
    def is_monitoring_lib(cls, module: str, class_name: str = '') -> bool:
        """Check if module.class represents a monitoring/observability library"""
        return cls._check_library(cls.MONITORING_LIBS, module, class_name)

    @classmethod
    def is_template_lib(cls, module: str, class_name: str = '') -> bool:
        """Check if module.class represents a template library"""
        return cls._check_library(cls.TEMPLATE_LIBS, module, class_name)

    @classmethod
    def is_output_filtering(cls, module: str, class_name: str = '') -> bool:
        """Check if module.class represents an output filtering/sanitization library"""
        return cls._check_library(cls.OUTPUT_FILTERING, module, class_name)

    @classmethod
    def is_pii_redaction_lib(cls, module: str, class_name: str = '') -> bool:
        """Check if module.class represents a PII redaction library"""
        return cls._check_library(cls.PII_REDACTION_LIBS, module, class_name)

    @classmethod
    def is_encryption_lib(cls, module: str, class_name: str = '') -> bool:
        """Check if module.class represents an encryption library"""
        return cls._check_library(cls.ENCRYPTION_LIBS, module, class_name)

    @classmethod
    def is_access_control_lib(cls, module: str, class_name: str = '') -> bool:
        """Check if module.class represents an access control library"""
        return cls._check_library(cls.ACCESS_CONTROL_LIBS, module, class_name)

    @classmethod
    def is_vector_db_lib(cls, module: str, class_name: str = '') -> bool:
        """Check if module.class represents a vector database library"""
        return cls._check_library(cls.VECTOR_DB_LIBS, module, class_name)

    @classmethod
    def is_ml_versioning_lib(cls, module: str, class_name: str = '') -> bool:
        """Check if module.class represents an ML versioning library"""
        return cls._check_library(cls.ML_VERSIONING_LIBS, module, class_name)

    @classmethod
    def _check_library(cls, registry: Dict, module: str, class_name: str = '') -> bool:
        """
        Check if a module/class combination is in the registry

        Args:
            registry: The library registry to check
            module: Module name (e.g., 'hvac', 'boto3')
            class_name: Class or function name (e.g., 'Client', 'Limiter')

        Returns:
            True if found in registry
        """
        # Exact module match
        if module in registry:
            if not class_name:
                return True

            # Check if class/function is in the module's set
            entries = registry[module]
            if isinstance(entries, set):
                return class_name in entries
            elif isinstance(entries, dict):
                return class_name in entries or f':{class_name}' in entries

        # Partial module match (e.g., 'azure.keyvault' matches 'azure.keyvault.secrets')
        for reg_module in registry.keys():
            if module.startswith(reg_module) or reg_module.startswith(module):
                if not class_name:
                    return True
                entries = registry[reg_module]
                if isinstance(entries, (set, dict)) and class_name in entries:
                    return True

        return False

    @classmethod
    def get_all_modules(cls) -> Set[str]:
        """Get all registered security library modules"""
        modules = set()
        for registry in [
            cls.SECRET_MANAGERS,
            cls.RATE_LIMITERS,
            cls.PII_DETECTORS,
            cls.BIAS_DETECTORS,
            cls.EXPLAINABILITY_LIBS,
            cls.CONTENT_MODERATORS,
            cls.AUTHORIZATION_LIBS,
            cls.AUDIT_LOGGERS,
            cls.VALIDATION_LIBS,
            cls.PROMPT_INJECTION_DEFENSE,
            cls.MONITORING_LIBS,
            cls.TEMPLATE_LIBS,
            cls.OUTPUT_FILTERING,
            cls.PII_REDACTION_LIBS,
            cls.ENCRYPTION_LIBS,
            cls.ACCESS_CONTROL_LIBS,
            cls.VECTOR_DB_LIBS,
            cls.ML_VERSIONING_LIBS,
        ]:
            modules.update(registry.keys())
        return modules
