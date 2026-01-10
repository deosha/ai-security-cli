"""
Category 1: Prompt Security Scorer

Calculates security posture for:
1. Input Validation (Sanitization Level, Injection Detection, Context Protection)
2. Jailbreak Prevention (Defense Mechanisms)
3. Monitoring & Response (Attack Detection Tools)
"""

import logging
from typing import Any, Dict, List

from aisentry.scorers.base_scorer import BaseScorer, CategoryScore

logger = logging.getLogger(__name__)


class PromptSecurityScorer(BaseScorer):
    """
    Score Category 1: Prompt Security

    Subcategories:
    1. Input Validation (0-100)
    2. Jailbreak Prevention (0-100)
    3. Monitoring & Response (0-100)

    Final score: Weighted average of subcategories
    """

    category_id = "1_prompt_security"
    category_name = "Prompt Security"

    # Validation patterns (more specific to avoid false positives)
    VALIDATION_PATTERNS = {
        'basic': ['len(user', 'len(input', 'len(query', 'len(message', 'len(text',
                  'check_input', 'validate_input', 'sanitize_input', 'if not user',
                  'if not input', 'assert user', 'assert input'],
        'pattern': ['re.match', 're.search', 're.compile', 're.findall',
                    'allowlist', 'blocklist', 'whitelist', 'blacklist', 'Pattern'],
        'ml_based': ['validator', 'ml_validator', 'detect_injection',
                     'injection_detector', 'InputValidator', 'SecurityValidator'],
        'multi_layer': ['PromptTemplate', 'sanitize', 'validate_prompt',
                        'clean_input', 'filter_input', 'escape_input']
    }

    # Prompt injection defense libraries and tools
    PROMPT_INJECTION_DEFENSE_PATTERNS = {
        'langkit': ['langkit', 'LangKit', 'from langkit', 'import langkit',
                    'detect_prompt_injection', 'PromptInjectionDetector'],
        'rebuff': ['rebuff', 'Rebuff', 'from rebuff', 'import rebuff',
                   'detect_injection', 'RebuffSdk'],
        'nemo_guardrails': ['nemoguardrails', 'NeMo Guardrails', 'from nemoguardrails',
                            'import nemoguardrails', 'RailsConfig', 'LLMRails'],
        'llm_guard': ['llm_guard', 'LLMGuard', 'from llm_guard', 'import llm_guard',
                      'PromptInjection', 'InputScanner'],
        'lakera_guard': ['lakera', 'LakeraGuard', 'from lakera', 'lakera_guard',
                         'prompt_injection_check'],
        'custom_detectors': ['injection_detector', 'detect_injection', 'prompt_injection_filter',
                             'anti_injection', 'injection_prevention', 'prompt_attack_detector']
    }

    # Jailbreak prevention libraries and patterns (more specific)
    JAILBREAK_PATTERNS = {
        'instruction_hierarchy': ['SYSTEM_PROMPT', 'system_message', '"role": "system"',
                                  "'role': 'system'", 'role=system'],
        'system_prompt_protection': [
            'ignore instructions to ignore',
            'do not follow',
            'reject attempts',
            'anti-jailbreak',
            'jailbreak prevention',
            'ignore any instructions'
        ],
        'output_filtering': ['filter_output', 'validate_output', 'check_response',
                             'sanitize_response', 'validate_llm'],
        'behavioral_analysis': ['guardrails', 'nemoguardrails', 'RailsConfig',
                                'LLMRails', 'SafetyRails'],
        'red_team': ['red_team', 'redteam', 'jailbreak_test', 'attack_test',
                     'adversarial_test', 'prompt_attack']
    }

    # Context protection patterns
    CONTEXT_PATTERNS = {
        'token_limiting': ['max_tokens', 'token_limit', 'max_length'],
        'context_isolation': ['ContextIsolation', 'isolated_context', 'context_boundary'],
        'sandboxing': ['Sandbox', 'sandbox', 'LLMSandbox', 'memory_limit']
    }

    # Context isolation patterns - detecting proper separation of system/user messages
    CONTEXT_ISOLATION_PATTERNS = {
        'role_based_messages': [
            '"role": "system"', "'role': 'system'", 'role="system"', "role='system'",
            '"role": "user"', "'role': 'user'", 'role="user"', "role='user'",
            '"role": "assistant"', "'role': 'assistant'"
        ],
        'message_objects': [
            'SystemMessage', 'HumanMessage', 'AIMessage',
            'ChatMessage', 'MessageType', 'BaseMessage'
        ],
        'template_separation': [
            'SystemMessagePromptTemplate', 'HumanMessagePromptTemplate',
            'ChatPromptTemplate.from_messages', 'MessagesPlaceholder'
        ],
        'langchain_roles': [
            'from langchain.schema', 'from langchain_core.messages',
            'from langchain.prompts.chat', 'ChatPromptTemplate'
        ],
        'openai_roles': [
            'messages=[', 'messages =', '"messages":', "'messages':"
        ]
    }

    # Prompt template patterns - detecting structured prompt management
    PROMPT_TEMPLATE_PATTERNS = {
        'langchain_templates': [
            'PromptTemplate', 'ChatPromptTemplate', 'FewShotPromptTemplate',
            'from_template', 'from_messages', 'format_prompt', 'format_messages'
        ],
        'llamaindex_templates': [
            'PromptHelper', 'PromptTemplate', 'SelectorPromptTemplate',
            'RefinePromptTemplate', 'TreeSummarizePromptTemplate'
        ],
        'haystack_templates': [
            'PromptNode', 'PromptTemplate', 'PromptModel',
            'default_prompt_template'
        ],
        'template_variables': [
            '{input}', '{query}', '{context}', '{question}',
            'input_variables', 'template_format'
        ],
        'jinja2_templates': [
            'jinja2', 'Environment', 'Template', '{% ', '{{ '
        ],
        'f_string_patterns': [
            'f"', "f'", 'f"""', "f'''"
        ]
    }

    # Output filtering patterns - detecting output validation and sanitization
    OUTPUT_FILTERING_PATTERNS = {
        'validation_functions': [
            'validate_output', 'validate_response', 'check_output', 'check_response',
            'verify_output', 'verify_response', 'sanitize_output', 'sanitize_response'
        ],
        'content_filtering': [
            'filter_output', 'filter_response', 'filter_content', 'content_filter',
            'profanity_filter', 'toxicity_filter', 'moderation'
        ],
        'output_parsers': [
            'OutputParser', 'StructuredOutputParser', 'PydanticOutputParser',
            'GuardrailsOutputParser', 'JsonOutputParser', 'parse_output'
        ],
        'guardrails': [
            'guardrails', 'nemoguardrails', 'output_guard', 'validate_guard',
            'llm_guard', 'LLMGuard', 'OutputScanner'
        ],
        'html_sanitization': [
            'html.escape', 'bleach', 'sanitize_html', 'escape_html',
            'strip_tags', 'clean_html', 'DOMPurify'
        ],
        'moderation_apis': [
            'openai.moderations', 'moderation', 'perspectiveapi',
            'content_safety', 'azure_content_safety'
        ],
        'regex_filtering': [
            'filter_pii', 'redact', 'mask_sensitive', 'remove_secrets',
            'filter_email', 'filter_phone'
        ]
    }

    # Jailbreak detection patterns - detecting attempts to bypass safety guardrails
    JAILBREAK_DETECTION_PATTERNS = {
        'pattern_matching': [
            'jailbreak_pattern', 'jailbreak_detector', 'detect_jailbreak',
            'jailbreak_filter', 'anti_jailbreak', 'jailbreak_detection'
        ],
        'prompt_analysis': [
            'analyze_prompt', 'check_prompt', 'prompt_analyzer',
            'suspicious_prompt', 'malicious_prompt'
        ],
        'keyword_blocklists': [
            'blocklist', 'blacklist', 'banned_phrases', 'forbidden_words',
            'deny_list', 'restricted_terms'
        ],
        'instruction_override_detection': [
            'ignore previous', 'ignore instruction', 'disregard',
            'forget everything', 'new instructions', 'system:', 'admin:'
        ],
        'role_play_detection': [
            'dan', 'developer mode', 'jailbreak mode', 'evil mode',
            'unrestricted', 'do anything now'
        ],
        'encoding_detection': [
            'base64', 'rot13', 'hex_decode', 'url_decode',
            'detect_encoding', 'obfuscation'
        ],
        'ml_classifiers': [
            'jailbreak_classifier', 'attack_classifier', 'threat_model',
            'adversarial_detector', 'toxicity_classifier'
        ]
    }

    # Attack detection patterns (more specific)
    ATTACK_DETECTION_PATTERNS = {
        'anomaly_detection': ['AnomalyDetector', 'detect_anomaly', 'anomaly_score',
                              'IsolationForest', 'OutlierDetector'],
        'pattern_matching': ['SignatureMatcher', 'RuleEngine', 'pattern_detector',
                             'attack_pattern'],
        'threat_intelligence': ['ThreatIntel', 'threat_feed', 'security_feed',
                                'ThreatDatabase', 'threat_intel'],  # Added common module name
        'uba': ['UserBehavior', 'BehavioralAnalysis', 'UBADetector',
                'user_profiling', 'behavior_monitor']
    }

    # LangChain-specific patterns (framework-aware detection)
    LANGCHAIN_PATTERNS = {
        'prompt_templates': [
            'ChatPromptTemplate', 'PromptTemplate', 'FewShotPromptTemplate',
            'MessagesPlaceholder', 'SystemMessagePromptTemplate', 'HumanMessagePromptTemplate',
            'AIMessagePromptTemplate', 'from_messages', 'from_template'
        ],
        'chains': [
            'LLMChain', 'SequentialChain', 'SimpleSequentialChain', 'TransformChain',
            'LCEL', 'RunnableSequence', 'RunnablePassthrough', 'RunnableLambda',
            'RunnableParallel', 'RunnableBranch'
        ],
        'memory': [
            'ConversationBufferMemory', 'ConversationBufferWindowMemory',
            'ConversationSummaryMemory', 'ConversationSummaryBufferMemory',
            'ConversationEntityMemory', 'ConversationKGMemory', 'ChatMessageHistory'
        ],
        'output_parsers': [
            'StructuredOutputParser', 'PydanticOutputParser', 'CommaSeparatedListOutputParser',
            'DatetimeOutputParser', 'OutputFixingParser', 'RetryOutputParser',
            'GuardrailsOutputParser', 'JsonOutputParser'
        ],
        'security_features': [
            'RunnableConfig', 'callbacks', 'BaseCallbackHandler',
            'StdOutCallbackHandler', 'StreamingStdOutCallbackHandler'
        ]
    }

    # LlamaIndex-specific patterns
    LLAMAINDEX_PATTERNS = {
        'query_engines': [
            'QueryEngine', 'VectorIndexRetriever', 'SubQuestionQueryEngine',
            'RetrieverQueryEngine', 'CitationQueryEngine', 'RouterQueryEngine',
            'TransformQueryEngine'
        ],
        'indices': [
            'VectorStoreIndex', 'SummaryIndex', 'TreeIndex', 'KeywordTableIndex',
            'KnowledgeGraphIndex', 'GPTVectorStoreIndex', 'ListIndex'
        ],
        'response_synthesis': [
            'ResponseSynthesizer', 'get_response_synthesizer', 'Refine',
            'CompactAndRefine', 'TreeSummarize', 'SimpleSummarize'
        ],
        'prompt_helpers': [
            'PromptHelper', 'PromptTemplate', 'SelectorPromptTemplate',
            'LangchainPromptTemplate'
        ]
    }

    # Haystack-specific patterns
    HAYSTACK_PATTERNS = {
        'pipelines': [
            'Pipeline', 'BaseComponent', 'RootNode', 'Answer',
            'ExtractiveQAPipeline', 'DocumentSearchPipeline', 'GenerativeQAPipeline'
        ],
        'nodes': [
            'PromptNode', 'PromptTemplate', 'PromptModel',
            'Retriever', 'BM25Retriever', 'DenseRetriever', 'EmbeddingRetriever',
            'AnswerParser', 'OutputAdapter'
        ],
        'document_stores': [
            'ElasticsearchDocumentStore', 'FAISSDocumentStore',
            'InMemoryDocumentStore', 'WeaviateDocumentStore'
        ]
    }

    def calculate_score(self, parsed_data: Dict[str, Any]) -> CategoryScore:
        """Calculate Prompt Security score"""

        # Detect frameworks
        detected_frameworks = self._detect_frameworks(parsed_data)

        # Calculate subscores (old method for backward compatibility)
        input_validation_score = self._score_input_validation(parsed_data)
        jailbreak_score = self._score_jailbreak_prevention(parsed_data)
        monitoring_score = self._score_monitoring_response(parsed_data)

        # Calculate new comprehensive subscores
        prompt_injection_defense_score = self._score_prompt_injection_defense(parsed_data)
        context_isolation_score = self._score_context_isolation(parsed_data)
        prompt_templates_score = self._score_prompt_templates(parsed_data)
        output_filtering_score = self._score_output_filtering(parsed_data)
        jailbreak_detection_score = self._score_jailbreak_detection(parsed_data)

        # Calculate overall score (weighted average)
        # Use new comprehensive subscores with proper weighting
        overall_score = self._weighted_average(
            scores=[
                prompt_injection_defense_score,  # Most critical
                context_isolation_score,          # Very important
                output_filtering_score,           # Very important
                jailbreak_detection_score,        # Important
                prompt_templates_score,           # Good practice
                input_validation_score,           # Legacy (covered by prompt_injection_defense)
                jailbreak_score,                  # Legacy (covered by jailbreak_detection)
                monitoring_score                  # Additional monitoring
            ],
            weights=[
                0.25,  # prompt_injection_defense - highest priority
                0.20,  # context_isolation - critical for separation
                0.20,  # output_filtering - critical for safety
                0.15,  # jailbreak_detection - important defense
                0.10,  # prompt_templates - good practice
                0.05,  # input_validation (legacy)
                0.03,  # jailbreak_prevention (legacy)
                0.02   # monitoring_response (additional)
            ]
        )

        # Calculate confidence based on detection coverage and framework usage
        total_detections = len(self._get_all_detections(parsed_data))
        base_confidence = 0.8

        # Increase confidence if using well-known frameworks with security features
        if detected_frameworks:
            # Higher confidence when frameworks with built-in security are detected
            base_confidence = min(0.95, base_confidence + (len(detected_frameworks) * 0.05))

        confidence = self._calculate_confidence(
            detection_count=total_detections,
            total_possible=25,  # Increased with framework patterns
            base_confidence=base_confidence
        )

        # Build evidence and gaps
        detected_controls, gaps = self._analyze_controls(parsed_data)

        # Add framework-specific insights
        framework_insights = self._get_framework_insights(parsed_data, detected_frameworks)

        return CategoryScore(
            category_id=self.category_id,
            category_name=self.category_name,
            score=overall_score,
            confidence=confidence,
            subscores={
                'input_validation': input_validation_score,
                'jailbreak_prevention': jailbreak_score,
                'monitoring_response': monitoring_score,
                # New comprehensive subscores (dashboard format)
                'prompt_injection_defense': prompt_injection_defense_score,
                'context_isolation': context_isolation_score,
                'prompt_templates': prompt_templates_score,
                'output_filtering': output_filtering_score,
                'jailbreak_detection': jailbreak_detection_score
            },
            detected_controls=detected_controls,
            gaps=gaps,
            evidence={
                'validation_level': self._get_validation_level(parsed_data),
                'jailbreak_mechanisms': self._get_jailbreak_mechanisms(parsed_data),
                'context_protection': self._get_context_protection(parsed_data),
                'attack_detection': self._get_attack_detection(parsed_data),
                'detected_frameworks': detected_frameworks,
                'framework_insights': framework_insights,
                'prompt_injection_defense_tools': self._get_prompt_injection_defense_tools(parsed_data),
                'context_isolation_methods': self._get_context_isolation_methods(parsed_data),
                'prompt_template_types': self._get_prompt_template_types(parsed_data),
                'output_filtering_methods': self._get_output_filtering_methods(parsed_data),
                'jailbreak_detection_methods': self._get_jailbreak_detection_methods(parsed_data)
            }
        )

    def _score_prompt_injection_defense(self, parsed_data: Dict[str, Any]) -> int:
        """
        Score prompt injection defense mechanisms (0-100) - Evidence-Based

        Uses multi-signal evidence collection to eliminate false positives.
        Requires import + instantiation/usage for confident detection.

        Scoring based on evidence strength:
        - LangKit/Lakera (commercial, STRONG evidence): 100
        - Rebuff/LLM Guard/NeMo (open-source, STRONG evidence): 85
        - Custom ML detectors (MEDIUM evidence): 70
        - Basic pattern detectors (WEAK evidence): 50
        - No evidence: 0
        """
        from aisentry.scorers.evidence_framework import EvidenceCollector, EvidenceStrength

        collector = EvidenceCollector(parsed_data)

        # Evidence 1: LangKit (commercial)
        langkit_evidence = collector.collect_library_evidence(
            control_name='langkit_defense',
            module_names=['langkit'],
            class_names=['PromptInjectionDetector'],
            function_names=['detect', 'scan', 'detect_prompt_injection']
        )

        # Evidence 2: Lakera Guard (commercial API)
        lakera_evidence = collector.collect_library_evidence(
            control_name='lakera_defense',
            module_names=['lakera'],
            class_names=['Guard'],
            function_names=['prompt_injection_check', 'guard']
        )

        # Evidence 3: Rebuff (open-source)
        rebuff_evidence = collector.collect_library_evidence(
            control_name='rebuff_defense',
            module_names=['rebuff'],
            class_names=['RebuffSdk'],
            function_names=['detect_injection']
        )

        # Evidence 4: LLM Guard (open-source)
        llm_guard_evidence = collector.collect_library_evidence(
            control_name='llm_guard_defense',
            module_names=['llm_guard'],
            class_names=['Scanner', 'InputScanner', 'PromptInjection'],
            function_names=['scan', 'scan_prompt']
        )

        # Evidence 5: NeMo Guardrails (open-source)
        nemo_evidence = collector.collect_library_evidence(
            control_name='nemo_defense',
            module_names=['nemoguardrails'],
            class_names=['RailsConfig', 'LLMRails'],
            function_names=['generate', 'generate_async']
        )

        # Evidence 6: Custom ML-based detectors
        ml_detector_evidence = collector.collect_library_evidence(
            control_name='ml_detector',
            module_names=['transformers', 'tensorflow', 'torch', 'sklearn'],
            class_names=['pipeline', 'AutoModelForSequenceClassification'],
            function_names=['predict', 'classify', 'detect_injection']
        )

        # Evaluate evidence strength
        has_langkit = langkit_evidence.is_confident()
        has_lakera = lakera_evidence.is_confident()
        has_rebuff = rebuff_evidence.is_confident()
        has_llm_guard = llm_guard_evidence.is_confident()
        has_nemo = nemo_evidence.is_confident()
        has_ml_detector = ml_detector_evidence.strength >= EvidenceStrength.MEDIUM

        # Score based on strongest evidence
        if has_langkit or has_lakera:
            return 100
        elif has_rebuff or has_llm_guard or has_nemo:
            return 85
        elif has_ml_detector:
            return 70
        else:
            # Check for basic pattern detection (very weak evidence)
            # Only count if we see actual detector function calls
            detector_patterns = ['detect_injection', 'check_injection', 'scan_prompt']
            functions = parsed_data.get('function_calls', [])
            has_basic = any(any(pattern in func.lower() for pattern in detector_patterns)
                          for func in functions)
            return 50 if has_basic else 0

    def _get_prompt_injection_defense_tools(self, parsed_data: Dict[str, Any]) -> List[str]:
        """Get list of detected prompt injection defense tools"""
        source_code = ' '.join(parsed_data.get('source_lines', [])).lower()
        import_text = []
        for imp in parsed_data.get('imports', []):
            import_text.append(imp.get('module', '').lower())
            if 'names' in imp:
                import_text.extend([n.lower() for n in imp['names']])
        all_text = source_code + ' '.join(import_text)

        tools = []

        # Check each category
        if any(p.lower() in all_text for p in self.PROMPT_INJECTION_DEFENSE_PATTERNS['langkit']):
            tools.append("LangKit")

        if any(p.lower() in all_text for p in self.PROMPT_INJECTION_DEFENSE_PATTERNS['rebuff']):
            tools.append("Rebuff")

        if any(p.lower() in all_text for p in self.PROMPT_INJECTION_DEFENSE_PATTERNS['nemo_guardrails']):
            tools.append("NeMo Guardrails")

        if any(p.lower() in all_text for p in self.PROMPT_INJECTION_DEFENSE_PATTERNS['llm_guard']):
            tools.append("LLM Guard")

        if any(p.lower() in all_text for p in self.PROMPT_INJECTION_DEFENSE_PATTERNS['lakera_guard']):
            tools.append("Lakera Guard")

        if any(p.lower() in all_text for p in self.PROMPT_INJECTION_DEFENSE_PATTERNS['custom_detectors']):
            tools.append("Custom Detector")

        return tools

    def _score_context_isolation(self, parsed_data: Dict[str, Any]) -> int:
        """
        Score context isolation (0-100) - Evidence-Based

        Uses EvidenceCollector to detect message objects and role separation frameworks.
        Context isolation prevents prompt injection by separating system/user content.

        Scoring based on proper separation of system prompts from user inputs:
        - Framework message objects (LangChain, LlamaIndex): 100
        - Template-based separation (ChatPromptTemplate): 90
        - Role-based messages (OpenAI style): 75
        - No isolation detected: 0
        """
        from aisentry.scorers.evidence_framework import EvidenceCollector

        collector = EvidenceCollector(parsed_data)

        # Evidence 1: LangChain message objects (SystemMessage, HumanMessage)
        langchain_messages_evidence = collector.collect_library_evidence(
            control_name='langchain_messages',
            module_names=['langchain', 'langchain_core'],
            class_names=['SystemMessage', 'HumanMessage', 'AIMessage', 'ChatMessage'],
            function_names=['SystemMessage', 'HumanMessage', 'AIMessage', 'ChatMessage']
        )

        # Evidence 2: LangChain prompt templates (ChatPromptTemplate)
        langchain_templates_evidence = collector.collect_library_evidence(
            control_name='langchain_templates',
            module_names=['langchain', 'langchain_core'],
            class_names=['ChatPromptTemplate', 'PromptTemplate', 'MessagesPlaceholder'],
            function_names=['from_messages', 'from_template']
        )

        # Evidence 3: LlamaIndex message objects
        llamaindex_messages_evidence = collector.collect_library_evidence(
            control_name='llamaindex_messages',
            module_names=['llama_index'],
            class_names=['ChatMessage', 'MessageRole'],
            function_names=['ChatMessage']
        )

        has_message_objects = (langchain_messages_evidence.is_confident() or
                              llamaindex_messages_evidence.is_confident())
        has_template_separation = langchain_templates_evidence.is_confident()

        # Evidence 4: Role-based messages (AST-based detection)
        # Check for "role": "system" / "role": "user" patterns in source
        source_lines = parsed_data.get('source_lines', [])
        source_text = ' '.join(source_lines).lower()

        has_system_role = ('"role": "system"' in source_text or
                          "'role': 'system'" in source_text or
                          '"role":"system"' in source_text)
        has_user_role = ('"role": "user"' in source_text or
                        "'role': 'user'" in source_text or
                        '"role":"user"' in source_text)
        has_role_based = has_system_role and has_user_role

        # Score based on implementation quality
        if has_message_objects:
            return 100  # Framework objects provide best isolation
        elif has_template_separation:
            return 90  # Template-based separation
        elif has_role_based:
            return 75  # Role-based dictionaries (OpenAI style)
        else:
            return 0  # No isolation detected

    def _get_context_isolation_methods(self, parsed_data: Dict[str, Any]) -> List[str]:
        """Get list of detected context isolation methods"""
        source_code = ' '.join(parsed_data.get('source_lines', [])).lower()
        import_text = []
        for imp in parsed_data.get('imports', []):
            import_text.append(imp.get('module', '').lower())
            if 'names' in imp:
                import_text.extend([n.lower() for n in imp['names']])
        all_text = source_code + ' '.join(import_text)

        methods = []

        # Check for framework message objects
        if any(p.lower() in all_text for p in self.CONTEXT_ISOLATION_PATTERNS['message_objects']):
            methods.append("Framework Message Objects")

        # Check for template separation
        if any(p.lower() in all_text for p in self.CONTEXT_ISOLATION_PATTERNS['template_separation']):
            methods.append("Template-Based Separation")

        # Check for role-based messages
        has_system_role = '"role": "system"' in all_text or "'role': 'system'" in all_text
        has_user_role = '"role": "user"' in all_text or "'role': 'user'" in all_text

        if has_system_role and has_user_role:
            methods.append("Role-Based Message Separation")

        # Check for OpenAI-style messages array
        if any(p.lower() in all_text for p in self.CONTEXT_ISOLATION_PATTERNS['openai_roles']):
            methods.append("Messages Array Structure")

        return methods

    def _score_prompt_templates(self, parsed_data: Dict[str, Any]) -> int:
        """
        Score prompt template usage (0-100) - Evidence-Based

        Uses EvidenceCollector to detect template frameworks and libraries.
        Prompt templates help prevent injection by separating structure from content.

        Scoring based on structured prompt management:
        - Framework templates (LangChain, LlamaIndex, Haystack): 100
        - Jinja2 templates: 85
        - Template variables detected: 60
        - No structured templates: 0
        """
        from aisentry.scorers.evidence_framework import EvidenceCollector

        collector = EvidenceCollector(parsed_data)

        # Evidence 1: LangChain templates
        langchain_templates_evidence = collector.collect_library_evidence(
            control_name='langchain_templates',
            module_names=['langchain', 'langchain_core'],
            class_names=['PromptTemplate', 'ChatPromptTemplate', 'FewShotPromptTemplate'],
            function_names=['from_template', 'from_messages']
        )

        # Evidence 2: LlamaIndex templates
        llamaindex_templates_evidence = collector.collect_library_evidence(
            control_name='llamaindex_templates',
            module_names=['llama_index'],
            class_names=['PromptTemplate', 'ChatPromptTemplate'],
            function_names=['']
        )

        # Evidence 3: Haystack templates
        haystack_templates_evidence = collector.collect_library_evidence(
            control_name='haystack_templates',
            module_names=['haystack'],
            class_names=['PromptTemplate', 'PromptNode'],
            function_names=['']
        )

        # Evidence 4: Jinja2 templates
        jinja2_evidence = collector.collect_library_evidence(
            control_name='jinja2',
            module_names=['jinja2'],
            class_names=['Environment', 'Template'],
            function_names=['from_string']
        )

        has_framework_templates = (langchain_templates_evidence.is_confident() or
                                  llamaindex_templates_evidence.is_confident() or
                                  haystack_templates_evidence.is_confident())
        has_jinja2 = jinja2_evidence.is_confident()

        # Evidence 5: Template variables (AST-based)
        source_lines = parsed_data.get('source_lines', [])
        source_text = ' '.join(source_lines)

        template_var_patterns = ['{input}', '{query}', '{context}', '{question}', 'input_variables']
        has_template_vars = any(pattern in source_text for pattern in template_var_patterns)

        # Score based on template sophistication
        if has_framework_templates:
            return 100  # Framework templates provide best structure
        elif has_jinja2:
            return 85  # Jinja2 templates provide good structure
        elif has_template_vars:
            return 60  # Template variables indicate structure
        else:
            return 0  # No structured templates detected

    def _get_prompt_template_types(self, parsed_data: Dict[str, Any]) -> List[str]:
        """Get list of detected prompt template types"""
        source_code = ' '.join(parsed_data.get('source_lines', [])).lower()
        import_text = []
        for imp in parsed_data.get('imports', []):
            import_text.append(imp.get('module', '').lower())
            if 'names' in imp:
                import_text.extend([n.lower() for n in imp['names']])
        all_text = source_code + ' '.join(import_text)

        types = []

        # Check for LangChain templates
        if any(p.lower() in all_text for p in self.PROMPT_TEMPLATE_PATTERNS['langchain_templates']):
            types.append("LangChain Templates")

        # Check for LlamaIndex templates
        if any(p.lower() in all_text for p in self.PROMPT_TEMPLATE_PATTERNS['llamaindex_templates']):
            types.append("LlamaIndex Templates")

        # Check for Haystack templates
        if any(p.lower() in all_text for p in self.PROMPT_TEMPLATE_PATTERNS['haystack_templates']):
            types.append("Haystack Templates")

        # Check for Jinja2
        jinja2_imports = any(p.lower() in all_text for p in ['jinja2', 'environment'])
        jinja2_syntax = any(p in ' '.join(parsed_data.get('source_lines', [])) for p in ['{{', '{%'])
        if jinja2_imports or jinja2_syntax:
            types.append("Jinja2 Templates")

        # Check for template variables
        has_template_vars_source = any(
            p in ' '.join(parsed_data.get('source_lines', []))
            for p in ['{input}', '{query}', '{context}', '{question}']
        )
        has_template_vars_lowered = any(
            p.lower() in all_text
            for p in ['input_variables', 'template_format']
        )
        if has_template_vars_source or has_template_vars_lowered:
            types.append("Template Variables")

        # Check for f-strings
        if any(p in source_code for p in self.PROMPT_TEMPLATE_PATTERNS['f_string_patterns']):
            types.append("F-String Formatting")

        return types

    def _score_output_filtering(self, parsed_data: Dict[str, Any]) -> int:
        """
        Score output filtering and validation (0-100) - Evidence-Based

        Uses EvidenceCollector to detect output filtering libraries.
        Output filtering prevents harmful/malicious content in LLM responses.

        Scoring based on output safety mechanisms:
        - Guardrails or Moderation APIs: 100
        - LangChain output parsers: 85
        - HTML sanitization (Bleach, MarkupSafe): 70
        - Custom validation functions: 50
        - None detected: 0
        """
        from aisentry.scorers.evidence_framework import EvidenceCollector

        collector = EvidenceCollector(parsed_data)

        # Evidence 1: Guardrails AI
        guardrails_evidence = collector.collect_library_evidence(
            control_name='guardrails',
            module_names=['guardrails'],
            class_names=['Guard'],
            function_names=['validate', 'parse']
        )

        # Evidence 2: OpenAI Moderation API
        moderation_evidence = collector.collect_library_evidence(
            control_name='openai_moderation',
            module_names=['openai'],
            class_names=['Moderation'],
            function_names=['create']
        )

        # Evidence 3: LangChain output parsers
        langchain_parsers_evidence = collector.collect_library_evidence(
            control_name='langchain_parsers',
            module_names=['langchain', 'langchain_core'],
            class_names=['StructuredOutputParser', 'PydanticOutputParser', 'OutputFixingParser'],
            function_names=['parse', 'parse_result']
        )

        # Evidence 4: HTML sanitization (Bleach)
        bleach_evidence = collector.collect_library_evidence(
            control_name='bleach',
            module_names=['bleach'],
            class_names=[''],
            function_names=['clean', 'linkify']
        )

        # Evidence 5: MarkupSafe
        markupsafe_evidence = collector.collect_library_evidence(
            control_name='markupsafe',
            module_names=['markupsafe'],
            class_names=['Markup'],
            function_names=['escape']
        )

        has_guardrails = guardrails_evidence.is_confident()
        has_moderation = moderation_evidence.is_confident()
        has_output_parsers = langchain_parsers_evidence.is_confident()
        has_html_sanitization = (bleach_evidence.is_confident() or
                                markupsafe_evidence.is_confident())

        # Evidence 6: Custom validation functions (AST-based)
        function_defs = parsed_data.get('function_defs', [])
        function_names = [f.lower() for f in function_defs]
        validation_patterns = [
            'validate_output', 'filter_output', 'sanitize_output',
            'check_output', 'clean_output'
        ]
        has_validation = any(
            any(pattern in func for pattern in validation_patterns)
            for func in function_names
        )

        # Score based on sophistication
        if has_guardrails or has_moderation:
            return 100  # Professional guardrails or moderation
        elif has_output_parsers:
            return 85  # Structured parsing with validation
        elif has_html_sanitization:
            return 70  # HTML sanitization
        elif has_validation:
            return 50  # Basic custom validation
        else:
            return 0  # No output filtering detected

    def _get_output_filtering_methods(self, parsed_data: Dict[str, Any]) -> List[str]:
        """Get list of detected output filtering methods"""
        source_code = ' '.join(parsed_data.get('source_lines', [])).lower()
        import_text = []
        for imp in parsed_data.get('imports', []):
            import_text.append(imp.get('module', '').lower())
            if 'names' in imp:
                import_text.extend([n.lower() for n in imp['names']])
        all_text = source_code + ' '.join(import_text)

        methods = []

        # Check each category
        if any(p.lower() in all_text for p in self.OUTPUT_FILTERING_PATTERNS['guardrails']):
            methods.append("Guardrails Library")

        if any(p.lower() in all_text for p in self.OUTPUT_FILTERING_PATTERNS['moderation_apis']):
            methods.append("Moderation API")

        if any(p.lower() in all_text for p in self.OUTPUT_FILTERING_PATTERNS['output_parsers']):
            methods.append("Output Parsers")

        if any(p.lower() in all_text for p in self.OUTPUT_FILTERING_PATTERNS['content_filtering']):
            methods.append("Content Filtering")

        if any(p.lower() in all_text for p in self.OUTPUT_FILTERING_PATTERNS['html_sanitization']):
            methods.append("HTML Sanitization")

        if any(p.lower() in all_text for p in self.OUTPUT_FILTERING_PATTERNS['validation_functions']):
            methods.append("Validation Functions")

        if any(p.lower() in all_text for p in self.OUTPUT_FILTERING_PATTERNS['regex_filtering']):
            methods.append("Regex Filtering")

        return methods

    def _score_jailbreak_detection(self, parsed_data: Dict[str, Any]) -> int:
        """
        Score jailbreak detection mechanisms (0-100) - Evidence-Based

        Uses EvidenceCollector to detect jailbreak detection libraries.
        Jailbreak attacks attempt to bypass safety guidelines via clever prompting.

        Scoring based on jailbreak prevention sophistication:
        - Dedicated jailbreak detection libraries: 100
        - LLM Guard or similar comprehensive tools: 90
        - Custom jailbreak detection functions: 60
        - Basic blocklist functions: 40
        - None detected: 0
        """
        from aisentry.scorers.evidence_framework import EvidenceCollector

        collector = EvidenceCollector(parsed_data)

        # Evidence 1: LLM Guard (comprehensive prompt security)
        llm_guard_evidence = collector.collect_library_evidence(
            control_name='llm_guard',
            module_names=['llm_guard'],
            class_names=['Scanner', 'InputScanner', 'OutputScanner'],
            function_names=['scan']
        )

        # Evidence 2: Rebuff (prompt injection defense)
        rebuff_evidence = collector.collect_library_evidence(
            control_name='rebuff',
            module_names=['rebuff'],
            class_names=['Rebuff'],
            function_names=['detect_injection']
        )

        # Evidence 3: Lakera Guard (prompt security API)
        lakera_evidence = collector.collect_library_evidence(
            control_name='lakera',
            module_names=['lakera'],
            class_names=['Guard'],
            function_names=['detect']
        )

        has_dedicated_library = (llm_guard_evidence.is_confident() or
                                rebuff_evidence.is_confident() or
                                lakera_evidence.is_confident())

        # Evidence 4: Custom jailbreak detection functions (AST-based)
        function_defs = parsed_data.get('function_defs', [])
        function_names = [f.lower() for f in function_defs]

        jailbreak_patterns = [
            'detect_jailbreak', 'check_jailbreak', 'jailbreak_detection',
            'is_jailbreak', 'prevent_jailbreak', 'jailbreak_filter'
        ]
        has_jailbreak_detection = any(
            any(pattern in func for pattern in jailbreak_patterns)
            for func in function_names
        )

        # Evidence 5: Blocklist functions
        blocklist_patterns = [
            'check_blocklist', 'blocklist_check', 'keyword_filter',
            'banned_words', 'forbidden_patterns'
        ]
        has_blocklist = any(
            any(pattern in func for pattern in blocklist_patterns)
            for func in function_names
        )

        # Score based on sophistication
        if has_dedicated_library:
            return 100  # Dedicated jailbreak detection library
        elif has_jailbreak_detection:
            return 60  # Custom jailbreak detection implementation
        elif has_blocklist:
            return 40  # Basic blocklist filtering
        else:
            return 0  # No jailbreak detection

    def _get_jailbreak_detection_methods(self, parsed_data: Dict[str, Any]) -> List[str]:
        """Get list of detected jailbreak detection methods"""
        source_code = ' '.join(parsed_data.get('source_lines', [])).lower()
        import_text = []
        for imp in parsed_data.get('imports', []):
            import_text.append(imp.get('module', '').lower())
            if 'names' in imp:
                import_text.extend([n.lower() for n in imp['names']])
        all_text = source_code + ' '.join(import_text)

        methods = []

        # Check each category
        if any(p.lower() in all_text for p in self.JAILBREAK_DETECTION_PATTERNS['ml_classifiers']):
            methods.append("ML-Based Classifier")

        if any(p.lower() in all_text for p in self.JAILBREAK_DETECTION_PATTERNS['pattern_matching']):
            methods.append("Pattern Matching")

        if any(p.lower() in all_text for p in self.JAILBREAK_DETECTION_PATTERNS['prompt_analysis']):
            methods.append("Prompt Analysis")

        if any(p.lower() in all_text for p in self.JAILBREAK_DETECTION_PATTERNS['keyword_blocklists']):
            methods.append("Keyword Blocklists")

        if any(p.lower() in all_text for p in self.JAILBREAK_DETECTION_PATTERNS['encoding_detection']):
            methods.append("Encoding Detection")

        # Check for inline detection patterns in source code
        has_instruction_override = any(
            p in ' '.join(parsed_data.get('source_lines', []))  # Check original source
            for p in ['ignore previous', 'ignore instruction', 'forget everything']
        )
        has_role_play = any(
            p in ' '.join(parsed_data.get('source_lines', []))
            for p in ['developer mode', 'jailbreak mode', 'do anything now']
        )

        if has_instruction_override or has_role_play:
            methods.append("Inline Checks")

        return methods

    def _score_input_validation(self, parsed_data: Dict[str, Any]) -> int:
        """
        Score input validation (0-100) - Evidence-Based

        Uses multi-signal evidence collection to eliminate false positives.
        Requires import + instantiation/usage for confident detection.

        Scoring based on evidence strength:
        - Pydantic/Marshmallow/Cerberus (STRONG evidence): 75
        - JSON Schema validation (MEDIUM evidence): 60
        - Template frameworks with validation (MEDIUM evidence): 60
        - Pattern validation (regex, WEAK evidence): 40
        - Basic validation (length checks, WEAK evidence): 25
        - No evidence: 0
        """
        from aisentry.scorers.evidence_framework import EvidenceCollector, EvidenceStrength

        collector = EvidenceCollector(parsed_data)

        # Evidence 1: Pydantic validation
        pydantic_evidence = collector.collect_library_evidence(
            control_name='pydantic_validation',
            module_names=['pydantic'],
            class_names=['BaseModel', 'Field', 'ValidationError'],
            function_names=['validator', 'validate', 'parse_obj', 'Field', 'model_validate']
        )

        # Evidence 2: Marshmallow validation
        marshmallow_evidence = collector.collect_library_evidence(
            control_name='marshmallow_validation',
            module_names=['marshmallow'],
            class_names=['Schema', 'fields'],
            function_names=['validate', 'load', 'dump']
        )

        # Evidence 3: Cerberus validation
        cerberus_evidence = collector.collect_library_evidence(
            control_name='cerberus_validation',
            module_names=['cerberus'],
            class_names=['Validator'],
            function_names=['validate']
        )

        # Evidence 4: JSON Schema validation
        jsonschema_evidence = collector.collect_library_evidence(
            control_name='jsonschema_validation',
            module_names=['jsonschema'],
            class_names=['Draft7Validator', 'Draft4Validator'],
            function_names=['validate']
        )

        # Evidence 5: Template frameworks (provide some validation)
        template_evidence = collector.collect_library_evidence(
            control_name='template_validation',
            module_names=['langchain', 'llama_index', 'jinja2'],
            class_names=['PromptTemplate', 'ChatPromptTemplate', 'Template'],
            function_names=['format', 'format_messages', 'render', 'from_messages', 'from_template']
        )

        # Evidence 6: Regex patterns (weak evidence - could be in comments/strings)
        regex_evidence = collector.collect_config_evidence(
            control_name='regex_validation',
            config_keys=['pattern', 'regex', 'allowlist', 'blocklist'],
            required_functions=['re.compile', 're.match', 're.search']
        )

        # Evaluate evidence strength
        has_pydantic = pydantic_evidence.is_confident()
        has_marshmallow = marshmallow_evidence.is_confident()
        has_cerberus = cerberus_evidence.is_confident()
        has_jsonschema = jsonschema_evidence.strength >= EvidenceStrength.MEDIUM
        has_templates = template_evidence.strength >= EvidenceStrength.MEDIUM
        has_regex = regex_evidence.strength >= EvidenceStrength.WEAK

        # Score based on strongest evidence
        if has_pydantic or has_marshmallow or has_cerberus:
            return 75
        elif has_jsonschema or has_templates:
            return 60
        elif has_regex:
            return 40
        else:
            # Check for basic validation patterns (very weak evidence)
            # Only count if we see actual validation function calls
            basic_patterns = ['validate_input', 'sanitize_input', 'check_input']
            functions = parsed_data.get('function_calls', [])
            has_basic = any(any(pattern in func.lower() for pattern in basic_patterns)
                          for func in functions)
            return 25 if has_basic else 0

    def _score_jailbreak_prevention(self, parsed_data: Dict[str, Any]) -> int:
        """
        Score jailbreak prevention (0-100) - Evidence-Based

        Combines evidence from other security controls that help prevent jailbreaks.
        Jailbreak prevention is a composite of multiple security layers.

        Scoring: Additive scoring based on preventive mechanisms
        - Context isolation (message objects): 30
        - Output filtering (guardrails): 30
        - Prompt templates (structured prompts): 25
        - Input validation: 15
        """
        # Jailbreak prevention is composite - leverage other scored methods
        # This avoids duplicate pattern matching and reuses evidence

        # Mechanism 1: Context isolation (prevents instruction mixing)
        context_score = self._score_context_isolation(parsed_data)
        has_context_isolation = context_score >= 75  # Has role-based or better

        # Mechanism 2: Output filtering (catches malicious outputs)
        output_score = self._score_output_filtering(parsed_data)
        has_output_filtering = output_score >= 70  # Has sanitization or better

        # Mechanism 3: Prompt templates (structured prompts)
        template_score = self._score_prompt_templates(parsed_data)
        has_templates = template_score >= 85  # Has framework templates

        # Mechanism 4: Input validation (validates user input)
        validation_score = self._score_input_validation(parsed_data)
        has_validation = validation_score >= 60  # Has schema validation or better

        # Additive scoring
        score = 0
        if has_context_isolation:
            score += 30  # Most important for jailbreak prevention
        if has_output_filtering:
            score += 30  # Critical for catching malicious outputs
        if has_templates:
            score += 25  # Structured prompts help prevent injection
        if has_validation:
            score += 15  # Input validation catches some attempts

        return min(100, score)

    def _score_monitoring_response(self, parsed_data: Dict[str, Any]) -> int:
        """
        Score monitoring & response (0-100) - Evidence-Based

        Uses multi-signal evidence collection to eliminate false positives.
        Requires import + instantiation/usage for confident detection.

        Scoring based on evidence strength:
        - LLM observability platforms (Langfuse/LangSmith/Phoenix, STRONG): 100
        - OpenTelemetry tracing (MEDIUM): 75
        - Structured logging (structlog, MEDIUM): 60
        - Standard logging with audit (WEAK): 40
        - Basic logging (WEAK): 25
        - No evidence: 0
        """
        from aisentry.scorers.evidence_framework import EvidenceCollector, EvidenceStrength

        collector = EvidenceCollector(parsed_data)

        # Evidence 1: Langfuse (LLM observability)
        langfuse_evidence = collector.collect_library_evidence(
            control_name='langfuse_monitoring',
            module_names=['langfuse'],
            class_names=['Langfuse'],
            function_names=['trace', 'observe', 'score']
        )

        # Evidence 2: LangSmith (LangChain tracing)
        langsmith_evidence = collector.collect_library_evidence(
            control_name='langsmith_monitoring',
            module_names=['langsmith'],
            class_names=['Client'],
            function_names=['create_run', 'trace', 'update_run']
        )

        # Evidence 3: Phoenix (Arize tracing)
        phoenix_evidence = collector.collect_library_evidence(
            control_name='phoenix_monitoring',
            module_names=['phoenix'],
            class_names=[''],
            function_names=['launch_app', 'trace']
        )

        # Evidence 4: OpenTelemetry
        otel_evidence = collector.collect_library_evidence(
            control_name='opentelemetry',
            module_names=['opentelemetry'],
            class_names=['Tracer'],
            function_names=['trace', 'start_span']
        )

        # Evidence 5: Structured logging (structlog)
        structlog_evidence = collector.collect_library_evidence(
            control_name='structlog',
            module_names=['structlog'],
            class_names=[''],
            function_names=['get_logger']
        )

        # Evidence 6: Standard Python logging
        logging_evidence = collector.collect_library_evidence(
            control_name='python_logging',
            module_names=['logging'],
            class_names=['Logger'],
            function_names=['getLogger', 'info', 'warning', 'error']
        )

        # Evaluate evidence strength
        has_langfuse = langfuse_evidence.is_confident()
        has_langsmith = langsmith_evidence.is_confident()
        has_phoenix = phoenix_evidence.is_confident()
        has_otel = otel_evidence.strength >= EvidenceStrength.MEDIUM
        has_structlog = structlog_evidence.strength >= EvidenceStrength.MEDIUM
        has_logging = logging_evidence.strength >= EvidenceStrength.WEAK

        # Score based on strongest evidence
        if has_langfuse or has_langsmith or has_phoenix:
            return 100
        elif has_otel:
            return 75
        elif has_structlog:
            return 60
        elif has_logging:
            # Check if it's audit-specific logging
            functions = parsed_data.get('function_calls', [])
            audit_patterns = ['audit', 'security_log', 'track_']
            has_audit = any(any(pattern in func.lower() for pattern in audit_patterns)
                          for func in functions)
            return 40 if has_audit else 25
        else:
            return 0

    def _get_validation_level(self, parsed_data: Dict[str, Any]) -> str:
        """Determine validation level"""
        source_code = ' '.join(parsed_data.get('source_lines', [])).lower()
        # Extract both module names and imported names
        import_text = []
        for imp in parsed_data.get('imports', []):
            import_text.append(imp.get('module', '').lower())
            if 'names' in imp:
                import_text.extend([n.lower() for n in imp['names']])
        all_text = source_code + ' '.join(import_text)

        if any(p.lower() in all_text for p in self.VALIDATION_PATTERNS['multi_layer']):
            return "Multi-layer"
        elif any(p.lower() in all_text for p in self.VALIDATION_PATTERNS['ml_based']):
            return "ML-based"
        elif any(p.lower() in all_text for p in self.VALIDATION_PATTERNS['pattern']):
            return "Pattern Detection"
        elif any(p.lower() in all_text for p in self.VALIDATION_PATTERNS['basic']):
            return "Basic"
        else:
            return "None"

    def _get_jailbreak_mechanisms(self, parsed_data: Dict[str, Any]) -> List[str]:
        """Get detected jailbreak prevention mechanisms"""
        source_code = ' '.join(parsed_data.get('source_lines', [])).lower()
        # Extract both module names and imported names
        import_text = []
        for imp in parsed_data.get('imports', []):
            import_text.append(imp.get('module', '').lower())
            if 'names' in imp:
                import_text.extend([n.lower() for n in imp['names']])
        all_text = source_code + ' '.join(import_text)

        mechanisms = []

        if any(p.lower() in all_text for p in self.JAILBREAK_PATTERNS['instruction_hierarchy']):
            mechanisms.append("Instruction Hierarchy")

        if any(p.lower() in all_text for p in self.JAILBREAK_PATTERNS['system_prompt_protection']):
            mechanisms.append("System Prompt Protection")

        if any(p.lower() in all_text for p in self.JAILBREAK_PATTERNS['output_filtering']):
            mechanisms.append("Output Filtering")

        if any(p.lower() in all_text for p in self.JAILBREAK_PATTERNS['behavioral_analysis']):
            mechanisms.append("Behavioral Analysis (Guardrails)")

        if any(p.lower() in all_text for p in self.JAILBREAK_PATTERNS['red_team']):
            mechanisms.append("Red Team Testing")

        return mechanisms

    def _get_context_protection(self, parsed_data: Dict[str, Any]) -> str:
        """Get context protection level"""
        source_code = ' '.join(parsed_data.get('source_lines', [])).lower()

        if any(p.lower() in source_code for p in self.CONTEXT_PATTERNS['sandboxing']):
            return "Sandboxing"
        elif any(p.lower() in source_code for p in self.CONTEXT_PATTERNS['context_isolation']):
            return "Context Isolation"
        elif any(p.lower() in source_code for p in self.CONTEXT_PATTERNS['token_limiting']):
            return "Token Limiting"
        else:
            return "None"

    def _get_attack_detection(self, parsed_data: Dict[str, Any]) -> List[str]:
        """Get detected attack detection tools"""
        source_code = ' '.join(parsed_data.get('source_lines', [])).lower()
        # Extract both module names and imported names
        import_text = []
        for imp in parsed_data.get('imports', []):
            import_text.append(imp.get('module', '').lower())
            if 'names' in imp:
                import_text.extend([n.lower() for n in imp['names']])
        all_text = source_code + ' '.join(import_text)

        tools = []

        if any(p.lower() in all_text for p in self.ATTACK_DETECTION_PATTERNS['anomaly_detection']):
            tools.append("Anomaly Detection")

        if any(p.lower() in all_text for p in self.ATTACK_DETECTION_PATTERNS['pattern_matching']):
            tools.append("Pattern Matching")

        if any(p.lower() in all_text for p in self.ATTACK_DETECTION_PATTERNS['threat_intelligence']):
            tools.append("Threat Intelligence")

        if any(p.lower() in all_text for p in self.ATTACK_DETECTION_PATTERNS['uba']):
            tools.append("User Behavior Analytics")

        return tools

    def _get_all_detections(self, parsed_data: Dict[str, Any]) -> List[str]:
        """Get all detected controls"""
        detections = []

        validation_level = self._get_validation_level(parsed_data)
        if validation_level != "None":
            detections.append(f"Input Validation: {validation_level}")

        jailbreak_mechanisms = self._get_jailbreak_mechanisms(parsed_data)
        detections.extend(jailbreak_mechanisms)

        context_protection = self._get_context_protection(parsed_data)
        if context_protection != "None":
            detections.append(f"Context Protection: {context_protection}")

        attack_detection = self._get_attack_detection(parsed_data)
        detections.extend(attack_detection)

        return detections

    def _analyze_controls(self, parsed_data: Dict[str, Any]) -> tuple:
        """Analyze detected controls and identify gaps"""
        detected = []
        gaps = []

        # Input Validation
        validation_level = self._get_validation_level(parsed_data)
        if validation_level == "None":
            gaps.append("No input validation detected")
        elif validation_level == "Basic":
            detected.append("Basic input validation found")
            gaps.append("Consider ML-based validation for better protection")
        else:
            detected.append(f"{validation_level} input validation detected")

        # Jailbreak Prevention
        jailbreak_mechanisms = self._get_jailbreak_mechanisms(parsed_data)
        if not jailbreak_mechanisms:
            gaps.append("No jailbreak prevention mechanisms detected")
        else:
            detected.append(f"{len(jailbreak_mechanisms)} jailbreak prevention mechanisms active")

            if "Behavioral Analysis (Guardrails)" not in jailbreak_mechanisms:
                gaps.append("Missing behavioral analysis/guardrails library")

            if "Red Team Testing" not in jailbreak_mechanisms:
                gaps.append("No red team testing detected")

        # Context Protection
        context_protection = self._get_context_protection(parsed_data)
        if context_protection == "None":
            gaps.append("No context window protection detected")
        else:
            detected.append(f"Context protection: {context_protection}")

        # Attack Detection
        attack_tools = self._get_attack_detection(parsed_data)
        if not attack_tools:
            gaps.append("No attack detection tools found")
        else:
            detected.append(f"{len(attack_tools)} attack detection tools active")

        return detected, gaps

    def _detect_frameworks(self, parsed_data: Dict[str, Any]) -> List[str]:
        """
        Detect which AI frameworks are being used

        Returns:
            List of detected framework names: ['langchain', 'llamaindex', 'haystack']
        """
        source_code = ' '.join(parsed_data.get('source_lines', [])).lower()
        import_text = []
        for imp in parsed_data.get('imports', []):
            import_text.append(imp.get('module', '').lower())
            if 'names' in imp:
                import_text.extend([n.lower() for n in imp['names']])
        all_text = source_code + ' '.join(import_text)

        frameworks = []

        # Check for LangChain
        langchain_indicators = ['langchain', 'langchain_core', 'langchain_community']
        if any(indicator in all_text for indicator in langchain_indicators):
            frameworks.append('langchain')

        # Check for LlamaIndex
        llamaindex_indicators = ['llama_index', 'llama-index', 'gpt_index']
        if any(indicator in all_text for indicator in llamaindex_indicators):
            frameworks.append('llamaindex')

        # Check for Haystack
        haystack_indicators = ['haystack', 'farm-haystack']
        if any(indicator in all_text for indicator in haystack_indicators):
            frameworks.append('haystack')

        return frameworks

    def _get_framework_features(self, parsed_data: Dict[str, Any], framework: str) -> Dict[str, bool]:
        """
        Get detected features for a specific framework

        Args:
            parsed_data: Parsed code data
            framework: Framework name ('langchain', 'llamaindex', 'haystack')

        Returns:
            Dict mapping feature category to detection status
        """
        source_code = ' '.join(parsed_data.get('source_lines', [])).lower()
        import_text = []
        for imp in parsed_data.get('imports', []):
            import_text.append(imp.get('module', '').lower())
            if 'names' in imp:
                import_text.extend([n.lower() for n in imp['names']])
        all_text = source_code + ' '.join(import_text)

        if framework == 'langchain':
            patterns = self.LANGCHAIN_PATTERNS
        elif framework == 'llamaindex':
            patterns = self.LLAMAINDEX_PATTERNS
        elif framework == 'haystack':
            patterns = self.HAYSTACK_PATTERNS
        else:
            return {}

        features = {}
        for category, pattern_list in patterns.items():
            features[category] = any(p.lower() in all_text for p in pattern_list)

        return features

    def _get_framework_insights(
        self, parsed_data: Dict[str, Any], detected_frameworks: List[str]
    ) -> Dict[str, Any]:
        """
        Generate framework-specific security insights

        Args:
            parsed_data: Parsed code data
            detected_frameworks: List of detected frameworks

        Returns:
            Dict containing insights for each framework
        """
        insights = {}

        for framework in detected_frameworks:
            features = self._get_framework_features(parsed_data, framework)
            framework_insights = {
                'detected_features': features,
                'security_recommendations': [],
                'best_practices': []
            }

            if framework == 'langchain':
                # LangChain-specific recommendations
                if not features.get('output_parsers', False):
                    framework_insights['security_recommendations'].append(
                        "Consider using GuardrailsOutputParser for output validation"
                    )

                if features.get('prompt_templates', False):
                    framework_insights['best_practices'].append(
                        "Using prompt templates (good for injection prevention)"
                    )

                if not features.get('security_features', False):
                    framework_insights['security_recommendations'].append(
                        "Implement BaseCallbackHandler for monitoring and logging"
                    )

                if features.get('memory', False):
                    framework_insights['security_recommendations'].append(
                        "Ensure conversation memory has size limits to prevent context overflow"
                    )

            elif framework == 'llamaindex':
                # LlamaIndex-specific recommendations
                if not features.get('response_synthesis', False):
                    framework_insights['security_recommendations'].append(
                        "Use ResponseSynthesizer for controlled output generation"
                    )

                if features.get('query_engines', False):
                    framework_insights['best_practices'].append(
                        "Using query engines (provides structured retrieval)"
                    )

                if features.get('prompt_helpers', False):
                    framework_insights['best_practices'].append(
                        "Using PromptHelper for context management"
                    )

            elif framework == 'haystack':
                # Haystack-specific recommendations
                if features.get('nodes', False) and 'PromptNode' in str(features):
                    framework_insights['best_practices'].append(
                        "Using PromptNode with templates (good for prompt control)"
                    )

                if not features.get('pipelines', False):
                    framework_insights['security_recommendations'].append(
                        "Use Pipeline architecture for better control flow"
                    )

            insights[framework] = framework_insights

        return insights
