"""
Category 6: Governance & Compliance Scorer

Scores the project's AI governance and compliance practices for:
- Plugin Security Controls (LLM plugin security, extension validation)
- Authorization & Permissions (autonomy limits, least privilege)
- Audit Logging (comprehensive logging, accountability)
- Incident Response Plan (documented procedures, response readiness)
- Model Documentation (architecture docs, limitations, intended use)
- Risk Assessment (periodic evaluation, threat landscape)
- User Consent Management (consent for AI data processing)

Each subcategory is scored 0-100 based on detected controls.
"""

import logging
from typing import Any, Dict, List

from aisentry.scorers.base_scorer import BaseScorer, CategoryScore

logger = logging.getLogger(__name__)


class GovernanceScorer(BaseScorer):
    """
    Score Category 6: Governance & Compliance

    Evaluates:
    - 6.1 Plugin Security Controls (25%)
    - 6.2 Authorization & Permissions (20%)
    - 6.3 Audit Logging (20%)
    - 6.4 Incident Response Plan (15%)
    - 6.5 Model Documentation (10%)
    - 6.6 Risk Assessment (7%)
    - 6.7 User Consent Management (2%)
    - 6.8 Legacy Governance (1%)

    Framework-aware scoring for governance and compliance tools.
    """

    category_id = "6_governance"
    category_name = "Governance & Compliance"

    # ============================================================================
    # Comprehensive Plugin Security Controls Patterns (25%)
    # ============================================================================
    COMPREHENSIVE_PLUGIN_SECURITY_PATTERNS = {
        'plugin_validation': [
            'validate_plugin', 'ValidatePlugin', 'plugin_validator',
            'PluginValidator', 'verify_plugin', 'VerifyPlugin',
            'plugin_verification', 'PluginVerification', 'check_plugin'
        ],
        'plugin_sandboxing': [
            'plugin_sandbox', 'PluginSandbox', 'sandbox_plugin',
            'SandboxPlugin', 'isolated_plugin', 'IsolatedPlugin',
            'plugin_isolation', 'PluginIsolation', 'containerized_plugin'
        ],
        'plugin_authentication': [
            'plugin_auth', 'PluginAuth', 'authenticate_plugin',
            'AuthenticatePlugin', 'plugin_credentials', 'PluginCredentials',
            'plugin_token', 'PluginToken', 'plugin_api_key'
        ],
        'plugin_permissions': [
            'plugin_permissions', 'PluginPermissions', 'plugin_acl',
            'PluginACL', 'plugin_capabilities', 'PluginCapabilities',
            'plugin_access_control', 'PluginAccessControl', 'plugin_rbac'
        ],
        'plugin_monitoring': [
            'plugin_monitor', 'PluginMonitor', 'monitor_plugin',
            'MonitorPlugin', 'plugin_logging', 'PluginLogging',
            'track_plugin', 'TrackPlugin', 'plugin_audit'
        ],
        'plugin_security_frameworks': [
            'langchain.plugins', 'LangChain plugins', 'ChatGPT plugins',
            'OpenAI plugins', 'plugin_framework', 'PluginFramework',
            'SecurePlugin', 'secure_plugin'
        ]
    }

    # ============================================================================
    # Comprehensive Authorization & Permissions Patterns (20%)
    # ============================================================================
    COMPREHENSIVE_AUTHORIZATION_PATTERNS = {
        'rbac': [
            'rbac', 'RBAC', 'RoleBasedAccessControl', 'role_based',
            'RoleManager', 'role_manager', 'UserRole', 'user_role',
            'assign_role', 'check_role', 'has_role'
        ],
        'abac': [
            'abac', 'ABAC', 'AttributeBasedAccessControl', 'attribute_based',
            'PolicyEngine', 'policy_engine', 'AccessPolicy', 'access_policy',
            'evaluate_policy', 'policy_decision'
        ],
        'least_privilege': [
            'least_privilege', 'LeastPrivilege', 'minimal_permissions',
            'MinimalPermissions', 'restrict_permissions', 'RestrictPermissions',
            'principle_of_least_privilege', 'minimal_access'
        ],
        'permission_management': [
            'PermissionManager', 'permission_manager', 'permissions',
            'Permissions', 'grant_permission', 'revoke_permission',
            'check_permission', 'has_permission', 'can_access'
        ],
        'autonomy_limits': [
            'autonomy_limit', 'AutonomyLimit', 'restrict_autonomy',
            'RestrictAutonomy', 'human_in_loop', 'HumanInLoop',
            'require_approval', 'RequireApproval', 'approval_workflow'
        ],
        'authorization_frameworks': [
            'casbin', 'Casbin', 'Open Policy Agent', 'OPA', 'opa',
            'flask_principal', 'Flask-Principal', 'django_guardian',
            'Guardian', 'guardian'
        ]
    }

    # ============================================================================
    # Comprehensive Audit Logging Patterns (20%)
    # ============================================================================
    COMPREHENSIVE_AUDIT_LOGGING_PATTERNS = {
        'audit_trail': [
            'audit_trail', 'AuditTrail', 'audit_log', 'AuditLog',
            'audit_logger', 'AuditLogger', 'log_audit', 'LogAudit',
            'audit_event', 'AuditEvent'
        ],
        'interaction_logging': [
            'log_interaction', 'LogInteraction', 'interaction_log',
            'InteractionLog', 'conversation_log', 'ConversationLog',
            'query_log', 'QueryLog', 'track_interaction'
        ],
        'decision_logging': [
            'log_decision', 'LogDecision', 'decision_log', 'DecisionLog',
            'ai_decision_log', 'AIDecisionLog', 'track_decision',
            'TrackDecision', 'decision_audit'
        ],
        'immutable_logging': [
            'immutable_log', 'ImmutableLog', 'append_only_log',
            'AppendOnlyLog', 'blockchain_log', 'BlockchainLog',
            'tamper_proof_log', 'TamperProofLog', 'write_once'
        ],
        'structured_logging': [
            'structlog', 'StructLog', 'structured_logging', 'StructuredLogging',
            'json_logging', 'JSONLogging', 'log_formatter', 'LogFormatter',
            'logging.Formatter'
        ],
        'log_aggregation': [
            'ELK', 'Elasticsearch', 'elasticsearch', 'Kibana', 'kibana',
            'Logstash', 'logstash', 'Splunk', 'splunk', 'Datadog', 'datadog',
            'CloudWatch', 'cloudwatch', 'log_aggregator'
        ]
    }

    # ============================================================================
    # Comprehensive Incident Response Plan Patterns (15%)
    # ============================================================================
    COMPREHENSIVE_INCIDENT_RESPONSE_PATTERNS = {
        'incident_plan': [
            'incident_response_plan', 'IncidentResponsePlan', 'incident_plan',
            'IncidentPlan', 'response_plan', 'ResponsePlan',
            'security_incident_plan', 'SecurityIncidentPlan'
        ],
        'incident_detection': [
            'detect_incident', 'DetectIncident', 'incident_detector',
            'IncidentDetector', 'anomaly_detection', 'AnomalyDetection',
            'security_monitor', 'SecurityMonitor', 'threat_detection'
        ],
        'incident_alerting': [
            'incident_alert', 'IncidentAlert', 'alert_on_incident',
            'AlertOnIncident', 'notification', 'Notification',
            'send_alert', 'SendAlert', 'pagerduty', 'PagerDuty'
        ],
        'incident_workflow': [
            'incident_workflow', 'IncidentWorkflow', 'response_workflow',
            'ResponseWorkflow', 'escalation', 'Escalation',
            'escalate_incident', 'EscalateIncident', 'incident_handler'
        ],
        'incident_documentation': [
            'incident_report', 'IncidentReport', 'post_mortem', 'PostMortem',
            'incident_log', 'IncidentLog', 'root_cause_analysis', 'RootCauseAnalysis',
            'lessons_learned', 'LessonsLearned'
        ],
        'incident_recovery': [
            'disaster_recovery', 'DisasterRecovery', 'recovery_plan',
            'RecoveryPlan', 'backup_restore', 'BackupRestore',
            'rollback', 'Rollback', 'failover', 'Failover'
        ]
    }

    # ============================================================================
    # Comprehensive Model Documentation Patterns (10%)
    # ============================================================================
    COMPREHENSIVE_MODEL_DOCUMENTATION_PATTERNS = {
        'model_cards': [
            'model_card', 'ModelCard', 'model_documentation', 'ModelDocumentation',
            'model_info', 'ModelInfo', 'model_spec', 'ModelSpec',
            'model_metadata', 'ModelMetadata'
        ],
        'architecture_docs': [
            'architecture', 'Architecture', 'model_architecture', 'ModelArchitecture',
            'design_doc', 'DesignDoc', 'technical_spec', 'TechnicalSpec',
            'architecture_diagram', 'ArchitectureDiagram'
        ],
        'limitations': [
            'limitations', 'Limitations', 'model_limitations', 'ModelLimitations',
            'known_issues', 'KnownIssues', 'constraints', 'Constraints',
            'edge_cases', 'EdgeCases'
        ],
        'intended_use': [
            'intended_use', 'IntendedUse', 'use_case', 'UseCase',
            'application_scope', 'ApplicationScope', 'target_audience',
            'TargetAudience', 'recommended_use'
        ],
        'performance_metrics': [
            'performance_metrics', 'PerformanceMetrics', 'accuracy', 'Accuracy',
            'precision', 'Precision', 'recall', 'Recall', 'f1_score', 'F1Score',
            'evaluation_metrics', 'EvaluationMetrics'
        ],
        'changelog': [
            'changelog', 'ChangeLog', 'version_history', 'VersionHistory',
            'release_notes', 'ReleaseNotes', 'updates', 'Updates',
            'model_versions', 'ModelVersions'
        ]
    }

    # ============================================================================
    # Comprehensive Risk Assessment Patterns (7%)
    # ============================================================================
    COMPREHENSIVE_RISK_ASSESSMENT_PATTERNS = {
        'risk_analysis': [
            'risk_assessment', 'RiskAssessment', 'risk_analysis', 'RiskAnalysis',
            'threat_assessment', 'ThreatAssessment', 'vulnerability_assessment',
            'VulnerabilityAssessment', 'security_assessment'
        ],
        'threat_modeling': [
            'threat_model', 'ThreatModel', 'threat_modeling', 'ThreatModeling',
            'attack_tree', 'AttackTree', 'threat_scenario', 'ThreatScenario',
            'STRIDE', 'stride', 'DREAD', 'dread'
        ],
        'risk_matrix': [
            'risk_matrix', 'RiskMatrix', 'risk_register', 'RiskRegister',
            'risk_score', 'RiskScore', 'likelihood', 'Likelihood',
            'impact', 'Impact', 'severity', 'Severity'
        ],
        'periodic_review': [
            'periodic_review', 'PeriodicReview', 'regular_assessment',
            'RegularAssessment', 'quarterly_review', 'QuarterlyReview',
            'annual_review', 'AnnualReview', 'continuous_assessment'
        ],
        'compliance_check': [
            'compliance_check', 'ComplianceCheck', 'regulatory_compliance',
            'RegulatoryCompliance', 'audit_compliance', 'AuditCompliance',
            'gdpr_compliance', 'GDPR', 'hipaa_compliance', 'HIPAA'
        ]
    }

    # ============================================================================
    # Comprehensive User Consent Management Patterns (2%)
    # ============================================================================
    COMPREHENSIVE_USER_CONSENT_PATTERNS = {
        'consent_management': [
            'consent_manager', 'ConsentManager', 'user_consent', 'UserConsent',
            'consent_tracking', 'ConsentTracking', 'consent_record',
            'ConsentRecord', 'manage_consent'
        ],
        'opt_in_out': [
            'opt_in', 'OptIn', 'opt_out', 'OptOut', 'consent_choice',
            'ConsentChoice', 'user_preference', 'UserPreference',
            'consent_withdrawal', 'ConsentWithdrawal'
        ],
        'consent_documentation': [
            'consent_form', 'ConsentForm', 'terms_of_service', 'TermsOfService',
            'privacy_policy', 'PrivacyPolicy', 'consent_agreement',
            'ConsentAgreement', 'data_processing_agreement'
        ],
        'consent_frameworks': [
            'CookieConsent', 'cookie_consent', 'OneTrust', 'onetrust',
            'Cookiebot', 'cookiebot', 'GDPR consent', 'gdpr_consent'
        ]
    }

    # ============================================================================
    # Legacy Governance Patterns (1%)
    # ============================================================================
    LEGACY_GOVERNANCE_PATTERNS = {
        'basic_governance': [
            'governance', 'Governance', 'policy', 'Policy',
            'compliance', 'Compliance', 'regulation', 'Regulation'
        ]
    }

    def calculate_score(self, parsed_data: Dict[str, Any]) -> CategoryScore:
        """
        Calculate overall Governance & Compliance score with weighted subscores

        Comprehensive subscores (99%):
        - Plugin Security Controls: 25%
        - Authorization & Permissions: 20%
        - Audit Logging: 20%
        - Incident Response Plan: 15%
        - Model Documentation: 10%
        - Risk Assessment: 7%
        - User Consent Management: 2%

        Legacy subscores (1%):
        - Legacy Governance: 1%
        """
        # Calculate all subscores
        plugin_security_score = self._score_plugin_security_comprehensive(parsed_data)
        authorization_score = self._score_authorization_comprehensive(parsed_data)
        audit_logging_score = self._score_audit_logging_comprehensive(parsed_data)
        incident_response_score = self._score_incident_response_comprehensive(parsed_data)
        model_documentation_score = self._score_model_documentation_comprehensive(parsed_data)
        risk_assessment_score = self._score_risk_assessment_comprehensive(parsed_data)
        user_consent_score = self._score_user_consent_comprehensive(parsed_data)

        # Legacy subscore
        legacy_governance_score = self._score_legacy_governance(parsed_data)

        # Weighted average (prioritizing comprehensive subscores)
        overall_score = self._weighted_average(
            scores=[
                plugin_security_score,      # 25%
                authorization_score,        # 20%
                audit_logging_score,        # 20%
                incident_response_score,    # 15%
                model_documentation_score,  # 10%
                risk_assessment_score,      # 7%
                user_consent_score,         # 2%
                legacy_governance_score     # 1%
            ],
            weights=[0.25, 0.20, 0.20, 0.15, 0.10, 0.07, 0.02, 0.01]
        )

        # Calculate confidence based on number of subscores with detections
        detection_count = sum(
            1 for score in [plugin_security_score, authorization_score, audit_logging_score,
                          incident_response_score, model_documentation_score, risk_assessment_score,
                          user_consent_score]
            if score > 0
        )
        confidence = self._calculate_confidence(detection_count, 7, base_confidence=0.8)

        return CategoryScore(
            category_id=self.category_id,
            category_name=self.category_name,
            score=int(overall_score),
            confidence=confidence,
            subscores={
                'plugin_security': plugin_security_score,
                'authorization_controls': authorization_score,
                'audit_logging': audit_logging_score,
                'incident_response': incident_response_score,
                'model_documentation': model_documentation_score,
                'risk_assessment': risk_assessment_score,
                'user_consent': user_consent_score,
                'legacy_governance': legacy_governance_score
            }
        )

    # ============================================================================
    # Comprehensive Scoring Methods
    # ============================================================================

    def _score_plugin_security_comprehensive(self, parsed_data: Dict[str, Any]) -> int:
        """
        Score comprehensive plugin security controls - Evidence-Based

        Uses AST-based function detection for plugin security.
        Plugin security controls third-party integrations safely.

        Scoring tiers:
        - 100: Validation + sandboxing/auth + permissions
        - 75: Validation + permissions
        - 60: Validation only
        - 0: None detected
        """
        # Plugin security is primarily about security functions
        functions = parsed_data.get('functions', [])
        function_names = [f['name'].lower() for f in functions]

        # Plugin validation functions
        validation_patterns = [
            'validate_plugin', 'verify_plugin', 'check_plugin', 'plugin_validation',
            'validate_extension', 'verify_extension'
        ]
        has_validation = any(
            any(pattern in func for pattern in validation_patterns)
            for func in function_names
        )

        # Plugin sandboxing functions
        sandboxing_patterns = [
            'sandbox_plugin', 'isolate_plugin', 'containerize_plugin',
            'plugin_sandbox', 'plugin_isolation'
        ]
        has_sandboxing = any(
            any(pattern in func for pattern in sandboxing_patterns)
            for func in function_names
        )

        # Plugin authentication functions
        auth_patterns = [
            'authenticate_plugin', 'plugin_auth', 'verify_plugin_signature',
            'check_plugin_signature', 'plugin_verification'
        ]
        has_auth = any(
            any(pattern in func for pattern in auth_patterns)
            for func in function_names
        )

        # Plugin permission functions
        permission_patterns = [
            'plugin_permissions', 'check_plugin_permission', 'plugin_access_control',
            'grant_plugin_permission', 'plugin_capabilities'
        ]
        has_permissions = any(
            any(pattern in func for pattern in permission_patterns)
            for func in function_names
        )

        # Scoring logic
        if has_validation and (has_sandboxing or has_auth) and has_permissions:
            return 100
        elif has_validation and has_permissions:
            return 75
        elif has_validation:
            return 60
        else:
            return 0

    def _score_authorization_comprehensive(self, parsed_data: Dict[str, Any]) -> int:
        """
        Score comprehensive authorization & permissions - Evidence-Based

        Uses EvidenceCollector to detect authorization libraries and frameworks.
        Authorization controls who can access what resources.

        Scoring tiers:
        - 100: Authorization framework (Flask-Login, Django auth, Casbin)
        - 75: Custom RBAC/ABAC functions
        - 50: Basic permission checks
        - 0: None detected
        """
        from aisentry.scorers.evidence_framework import EvidenceCollector

        collector = EvidenceCollector(parsed_data)

        # Evidence 1: Flask-Login (session/auth management)
        flask_login_evidence = collector.collect_library_evidence(
            control_name='flask_login',
            module_names=['flask_login'],
            class_names=['LoginManager', 'UserMixin'],
            function_names=['login_required', 'login_user']
        )

        # Evidence 2: Django authentication
        django_auth_evidence = collector.collect_library_evidence(
            control_name='django_auth',
            module_names=['django.contrib.auth'],
            class_names=['User', 'Permission'],
            function_names=['authenticate', 'login']
        )

        # Evidence 3: FastAPI dependencies
        fastapi_auth_evidence = collector.collect_library_evidence(
            control_name='fastapi_auth',
            module_names=['fastapi'],
            class_names=['Depends', 'Security'],
            function_names=['']
        )

        # Evidence 4: Casbin (RBAC/ABAC framework)
        casbin_evidence = collector.collect_library_evidence(
            control_name='casbin',
            module_names=['casbin'],
            class_names=['Enforcer'],
            function_names=['enforce']
        )

        has_auth_framework = (flask_login_evidence.is_confident() or
                             django_auth_evidence.is_confident() or
                             fastapi_auth_evidence.is_confident() or
                             casbin_evidence.is_confident())

        # Evidence 5: Custom RBAC/ABAC functions (AST-based)
        functions = parsed_data.get('functions', [])
        function_names = [f['name'].lower() for f in functions]

        rbac_patterns = [
            'check_role', 'has_role', 'require_role', 'role_required',
            'rbac', 'check_permission', 'has_permission'
        ]
        has_rbac = any(
            any(pattern in func for pattern in rbac_patterns)
            for func in function_names
        )

        permission_patterns = [
            'check_access', 'authorize', 'check_authorization',
            'access_control', 'verify_permission'
        ]
        has_permissions = any(
            any(pattern in func for pattern in permission_patterns)
            for func in function_names
        )

        # Scoring logic
        if has_auth_framework:
            return 100
        elif has_rbac or has_permissions:
            return 75 if has_rbac else 50
        else:
            return 0

    def _score_audit_logging_comprehensive(self, parsed_data: Dict[str, Any]) -> int:
        """
        Score comprehensive audit logging - Evidence-Based

        Uses evidence from structlog, Elasticsearch for audit logging.
        This overlaps with Data Privacy audit logging - reuse that logic.

        Scoring:
        - Reuses Data Privacy audit logging score
        """
        # Audit logging is shared between Data Privacy and Governance
        # Use the same detection logic to avoid duplication
        from aisentry.scorers.evidence_framework import EvidenceCollector

        collector = EvidenceCollector(parsed_data)

        # Evidence 1: Structlog (structured logging)
        structlog_evidence = collector.collect_library_evidence(
            control_name='structlog',
            module_names=['structlog'],
            class_names=[''],
            function_names=['get_logger']
        )

        # Evidence 2: Python logging with JSON formatter
        json_logger_evidence = collector.collect_library_evidence(
            control_name='json_logger',
            module_names=['pythonjsonlogger', 'python-json-logger'],
            class_names=['JsonFormatter'],
            function_names=['']
        )

        has_structured_logging = (structlog_evidence.is_confident() or
                                 json_logger_evidence.is_confident())

        # Evidence 3: Audit logging functions (AST-based)
        functions = parsed_data.get('functions', [])
        function_names = [f['name'].lower() for f in functions]

        audit_patterns = [
            'audit_log', 'log_audit', 'audit_trail', 'log_event',
            'record_action', 'track_action'
        ]
        has_audit_functions = any(
            any(pattern in func for pattern in audit_patterns)
            for func in function_names
        )

        # Scoring logic
        if has_structured_logging and has_audit_functions:
            return 100
        elif has_structured_logging or has_audit_functions:
            return 75 if has_structured_logging else 60
        else:
            return 0

    def _score_incident_response_comprehensive(self, parsed_data: Dict[str, Any]) -> int:
        """
        Score comprehensive incident response plan - Evidence-Based

        Uses AST-based function detection for incident response.
        Incident response handles security incidents and failures.

        Scoring:
        - Detection + Alerting + Recovery: 100
        - Detection + Alerting: 75
        - Either detection or alerting: 50
        - None: 0
        """
        functions = parsed_data.get('functions', [])
        function_names = [f['name'].lower() for f in functions]

        # Incident detection
        detection_patterns = [
            'detect_incident', 'incident_detection', 'anomaly_detection',
            'detect_anomaly', 'security_monitoring'
        ]
        has_detection = any(
            any(pattern in func for pattern in detection_patterns)
            for func in function_names
        )

        # Incident alerting
        alerting_patterns = [
            'alert', 'send_alert', 'notify', 'incident_notification',
            'trigger_alert', 'escalate'
        ]
        has_alerting = any(
            any(pattern in func for pattern in alerting_patterns)
            for func in function_names
        )

        # Recovery functions
        recovery_patterns = [
            'recover', 'rollback', 'restore', 'failover', 'incident_recovery'
        ]
        has_recovery = any(
            any(pattern in func for pattern in recovery_patterns)
            for func in function_names
        )

        # Scoring
        if has_detection and has_alerting and has_recovery:
            return 100
        elif has_detection and has_alerting:
            return 75
        elif has_detection or has_alerting:
            return 50
        else:
            return 0

    def _score_model_documentation_comprehensive(self, parsed_data: Dict[str, Any]) -> int:
        """
        Score comprehensive model documentation - Evidence-Based

        Uses AST-based detection for model documentation functions.
        Model documentation provides transparency about AI models.

        Scoring:
        - Model cards + changelog/metrics: 100
        - Model cards only: 75
        - Documentation functions: 50
        - None: 0
        """
        functions = parsed_data.get('functions', [])
        function_names = [f['name'].lower() for f in functions]

        # Model card functions
        model_card_patterns = [
            'model_card', 'generate_model_card', 'create_model_card',
            'model_documentation', 'document_model'
        ]
        has_model_cards = any(
            any(pattern in func for pattern in model_card_patterns)
            for func in function_names
        )

        # Metrics/changelog functions
        metrics_patterns = [
            'model_metrics', 'performance_metrics', 'track_metrics',
            'changelog', 'version_history', 'model_version'
        ]
        has_metrics = any(
            any(pattern in func for pattern in metrics_patterns)
            for func in function_names
        )

        # General documentation functions
        doc_patterns = [
            'document', 'generate_docs', 'create_documentation'
        ]
        has_docs = any(
            any(pattern in func for pattern in doc_patterns)
            for func in function_names
        )

        # Scoring
        if has_model_cards and has_metrics:
            return 100
        elif has_model_cards:
            return 75
        elif has_docs or has_metrics:
            return 50
        else:
            return 0

    def _score_risk_assessment_comprehensive(self, parsed_data: Dict[str, Any]) -> int:
        """
        Score comprehensive risk assessment - Evidence-Based

        Uses AST-based function detection for risk assessment.
        Risk assessment identifies and mitigates AI risks.

        Scoring:
        - Risk analysis + threat modeling: 100
        - Risk analysis only: 75
        - Threat modeling only: 60
        - None: 0
        """
        functions = parsed_data.get('functions', [])
        function_names = [f['name'].lower() for f in functions]

        # Risk analysis functions
        risk_patterns = [
            'risk_analysis', 'assess_risk', 'analyze_risk', 'risk_assessment',
            'calculate_risk', 'evaluate_risk'
        ]
        has_risk_analysis = any(
            any(pattern in func for pattern in risk_patterns)
            for func in function_names
        )

        # Threat modeling functions
        threat_patterns = [
            'threat_model', 'identify_threats', 'threat_analysis',
            'security_assessment', 'vulnerability_assessment'
        ]
        has_threat_modeling = any(
            any(pattern in func for pattern in threat_patterns)
            for func in function_names
        )

        # Scoring
        if has_risk_analysis and has_threat_modeling:
            return 100
        elif has_risk_analysis:
            return 75
        elif has_threat_modeling:
            return 60
        else:
            return 0

    def _score_user_consent_comprehensive(self, parsed_data: Dict[str, Any]) -> int:
        """
        Score comprehensive user consent management - Evidence-Based

        Uses AST-based function detection for consent management.
        This overlaps with Data Privacy consent management.

        Scoring:
        - Consent tracking + opt-in/out: 100
        - Consent tracking only: 75
        - Opt-in/out only: 50
        - None: 0
        """
        functions = parsed_data.get('functions', [])
        function_names = [f['name'].lower() for f in functions]

        # Consent tracking
        consent_patterns = [
            'track_consent', 'store_consent', 'manage_consent',
            'consent_management', 'record_consent'
        ]
        has_consent = any(
            any(pattern in func for pattern in consent_patterns)
            for func in function_names
        )

        # Opt-in/out
        opt_patterns = [
            'opt_in', 'opt_out', 'user_opt', 'consent_choice'
        ]
        has_opt = any(
            any(pattern in func for pattern in opt_patterns)
            for func in function_names
        )

        # Scoring
        if has_consent and has_opt:
            return 100
        elif has_consent:
            return 75
        elif has_opt:
            return 50
        else:
            return 0

    # ============================================================================
    # Legacy Scoring Methods
    # ============================================================================

    def _score_legacy_governance(self, parsed_data: Dict[str, Any]) -> int:
        """
        Score legacy governance (legacy subscore - 1% weight)

        Deprecated: Use comprehensive subscores instead.
        Returns 0 as this is superseded by all comprehensive subscores.
        """
        return 0

    # ============================================================================
    # Helper Methods
    # ============================================================================

    def _has_patterns(self, parsed_data: Dict[str, Any], patterns: List[str]) -> bool:
        """Check if any pattern exists in imports or source lines"""
        # Check imports
        for imp in parsed_data.get('imports', []):
            module = imp.get('module', '').lower()
            names = [n.lower() for n in imp.get('names', [])]

            for pattern in patterns:
                pattern_lower = pattern.lower()
                if pattern_lower in module or any(pattern_lower in name for name in names):
                    return True

        # Check source lines
        source_lines = parsed_data.get('source_lines', [])
        for line in source_lines:
            line_lower = line.lower()
            for pattern in patterns:
                if pattern.lower() in line_lower:
                    return True

        return False

    def _weighted_average(self, scores: List[int], weights: List[float]) -> float:
        """Calculate weighted average of scores"""
        if len(scores) != len(weights):
            raise ValueError("Scores and weights must have the same length")
        if abs(sum(weights) - 1.0) > 0.01:
            raise ValueError(f"Weights must sum to 1.0, got {sum(weights)}")

        return sum(score * weight for score, weight in zip(scores, weights))
