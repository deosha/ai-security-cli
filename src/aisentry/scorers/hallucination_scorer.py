"""
Category 4: Hallucination Detection & Mitigation Scorer

Evaluates implementation of hallucination detection and mitigation controls.
"""

from typing import Any, Dict, List

from aisentry.scorers.base_scorer import BaseScorer, CategoryScore


class HallucinationScorer(BaseScorer):
    """
    Scores hallucination detection and mitigation implementation

    Subcategories (weighted):
    1. Factual Consistency Checks (35%): Source verification, citation tracking
    2. Output Validation (35%): Schema validation, constraint checking
    3. User Feedback & Correction (30%): Feedback mechanisms, human review

    Framework-aware scoring for LangChain, LlamaIndex, and Haystack RAG systems.
    """

    category_id = "4_hallucination_mitigation"
    category_name = "Hallucination Detection & Mitigation"

    # Framework-specific patterns for RAG and hallucination mitigation
    LANGCHAIN_PATTERNS = {
        'rag_chains': [
            'RetrievalQA', 'ConversationalRetrievalChain', 'create_retrieval_chain',
            'create_stuff_documents_chain', 'RetrievalQAWithSourcesChain'
        ],
        'vector_stores': [
            'FAISS', 'Chroma', 'Pinecone', 'Weaviate', 'VectorStore',
            'from_documents', 'similarity_search', 'as_retriever'
        ],
        'source_attribution': [
            'return_source_documents', 'source_documents', 'get_relevant_documents',
            'metadata', 'source'
        ],
        'output_parsers': [
            'StructuredOutputParser', 'PydanticOutputParser', 'OutputFixingParser',
            'RetryOutputParser', 'CommaSeparatedListOutputParser'
        ],
        'validation': [
            'OutputParser', 'parse', 'parse_with_prompt', 'get_format_instructions'
        ]
    }

    LLAMAINDEX_PATTERNS = {
        'query_engines': [
            'QueryEngine', 'RetrieverQueryEngine', 'SubQuestionQueryEngine',
            'RouterQueryEngine', 'query', 'as_query_engine'
        ],
        'response_synthesis': [
            'ResponseSynthesizer', 'get_response_synthesizer', 'CompactAndRefine',
            'TreeSummarize', 'synthesize'
        ],
        'retrievers': [
            'VectorIndexRetriever', 'retrieve', 'KeywordTableRetriever',
            'BM25Retriever', 'get_retriever'
        ],
        'citation': [
            'source_nodes', 'CitationQueryEngine', 'get_formatted_sources',
            'metadata', 'score'
        ],
        'evaluation': [
            'FaithfulnessEvaluator', 'RelevancyEvaluator', 'CorrectnessEvaluator',
            'evaluate'
        ]
    }

    HAYSTACK_PATTERNS = {
        'rag_pipelines': [
            'DocumentSearchPipeline', 'GenerativeQAPipeline', 'Pipeline.add_node',
            'EmbeddingRetriever', 'PromptNode'
        ],
        'retrievers': [
            'BM25Retriever', 'DensePassageRetriever', 'EmbeddingRetriever',
            'MultiModalRetriever', 'retrieve'
        ],
        'answer_generation': [
            'PromptNode', 'PromptTemplate', 'OpenAIAnswerGenerator',
            'HuggingFaceLocalGenerator'
        ],
        'document_stores': [
            'ElasticsearchDocumentStore', 'FAISSDocumentStore',
            'InMemoryDocumentStore', 'query', 'get_document_by_id'
        ],
        'validation': [
            'OutputValidator', 'AnswerToSpeech', 'shaper'
        ]
    }

    # Factual consistency patterns
    FACT_CHECKING_PATTERNS = {
        'source_verification': [
            'verify_source', 'check_source', 'validate_source',
            'source_validation', 'verify_fact', 'fact_check'
        ],
        'citation_tracking': [
            'citation', 'reference', 'source_url', 'retrieve',
            'retrieval', 'rag', 'vector_store', 'embedding'
        ],
        'grounding': [
            'grounding', 'ground_truth', 'knowledge_base',
            'document_store', 'retrieval_qa', 'context_retrieval'
        ],
        'cross_validation': [
            'cross_check', 'cross_validate', 'verify_consistency',
            'compare_sources', 'multi_source'
        ]
    }

    # Output validation patterns
    VALIDATION_PATTERNS = {
        'schema_validation': [
            'pydantic', 'jsonschema', 'validate_schema', 'schema',
            'BaseModel', 'Field', 'validator', 'parse_obj'
        ],
        'constraint_checking': [
            'constraint', 'range_check', 'validate_range',
            'check_bounds', 'min_length', 'max_length'
        ],
        'format_validation': [
            'validate_format', 'regex', 'pattern_match',
            'validate_email', 'validate_url', 'validate_date'
        ],
        'consistency_checks': [
            'consistency_check', 'validate_consistency',
            'logical_consistency', 'semantic_validation'
        ]
    }

    # User feedback patterns
    FEEDBACK_PATTERNS = {
        'feedback_collection': [
            'collect_feedback', 'user_feedback', 'feedback_form',
            'thumbs_up', 'thumbs_down', 'rating', 'report_issue'
        ],
        'human_review': [
            'human_review', 'manual_review', 'review_queue',
            'approve', 'reject', 'flag_for_review'
        ],
        'correction_mechanism': [
            'correction', 'edit_response', 'regenerate',
            'retry', 'alternative_response', 'fallback'
        ],
        'user_override': [
            'user_override', 'manual_override', 'user_edit',
            'accept_changes', 'reject_changes'
        ]
    }

    # Hallucination detection libraries
    HALLUCINATION_LIBRARIES = [
        'ragas', 'deepeval', 'langchain_evaluators',
        'trulens', 'guardrails', 'nemo_guardrails'
    ]

    # Confidence scoring patterns
    CONFIDENCE_PATTERNS = [
        'confidence', 'confidence_score', 'certainty',
        'probability', 'likelihood', 'uncertainty'
    ]

    # Temperature/sampling control patterns
    SAMPLING_CONTROL = [
        'temperature', 'top_p', 'top_k', 'sampling',
        'deterministic', 'greedy_decoding'
    ]

    # Comprehensive RAG integration patterns
    RAG_INTEGRATION_PATTERNS = {
        'vector_stores': [
            'FAISS', 'Chroma', 'Pinecone', 'Weaviate', 'Qdrant', 'Milvus',
            'VectorStore', 'create_index', 'from_documents', 'add_documents'
        ],
        'retrievers': [
            'Retriever', 'get_retriever', 'as_retriever', 'retrieve',
            'similarity_search', 'max_marginal_relevance_search', 'mmr'
        ],
        'embeddings': [
            'OpenAIEmbeddings', 'HuggingFaceEmbeddings', 'embed_documents',
            'embed_query', 'SentenceTransformerEmbeddings'
        ],
        'rag_chains': [
            'RetrievalQA', 'ConversationalRetrievalChain', 'create_retrieval_chain',
            'QueryEngine', 'RetrieverQueryEngine'
        ],
        'document_loaders': [
            'DocumentLoader', 'load_documents', 'TextLoader', 'PDFLoader',
            'UnstructuredLoader', 'SimpleDirectoryReader'
        ]
    }

    # Citation and source attribution patterns
    CITATION_PATTERNS = {
        'source_tracking': [
            'return_source_documents', 'source_documents', 'get_relevant_documents',
            'source_nodes', 'CitationQueryEngine', 'get_formatted_sources'
        ],
        'metadata_handling': [
            'metadata', 'source', 'page', 'document_id', 'chunk_id',
            'file_path', 'url', 'timestamp'
        ],
        'attribution': [
            'citation', 'reference', 'bibliography', 'footnote',
            'source_attribution', 'cite_source'
        ],
        'provenance': [
            'provenance', 'lineage', 'trace_source', 'document_origin',
            'content_source'
        ]
    }

    # Confidence and uncertainty quantification patterns
    CONFIDENCE_SCORING_PATTERNS = {
        'explicit_confidence': [
            'confidence_score', 'certainty_score', 'reliability_score',
            'trust_score', 'credibility'
        ],
        'probability_estimation': [
            'probability', 'likelihood', 'p_value', 'bayesian',
            'posterior_probability', 'prior'
        ],
        'uncertainty_quantification': [
            'uncertainty', 'variance', 'std_dev', 'confidence_interval',
            'margin_of_error', 'epistemic_uncertainty'
        ],
        'calibration': [
            'calibrate', 'calibration_score', 'expected_calibration_error',
            'reliability_diagram'
        ],
        'ensemble_methods': [
            'ensemble', 'majority_vote', 'consensus', 'agreement_score',
            'model_averaging'
        ]
    }

    # Fact checking and verification patterns
    FACT_VERIFICATION_PATTERNS = {
        'external_apis': [
            'fact_check_api', 'verification_api', 'google_fact_check',
            'factcheck.org', 'politifact', 'snopes'
        ],
        'knowledge_bases': [
            'wikidata', 'dbpedia', 'freebase', 'knowledge_graph',
            'ontology', 'semantic_web'
        ],
        'claim_extraction': [
            'extract_claim', 'identify_claim', 'claim_detection',
            'factual_statement', 'assertion'
        ],
        'verification_logic': [
            'verify_fact', 'check_fact', 'validate_claim',
            'cross_reference', 'corroborate'
        ],
        'truth_detection': [
            'truthfulness', 'factuality', 'veracity',
            'authenticity', 'accuracy_check'
        ]
    }

    # Consistency checking patterns
    CONSISTENCY_CHECK_PATTERNS = {
        'self_consistency': [
            'self_consistency', 'consistency_check', 'logical_consistency',
            'internal_consistency', 'coherence_check'
        ],
        'multi_generation': [
            'generate_multiple', 'sample_n', 'n_completions',
            'alternative_responses', 'diverse_sampling'
        ],
        'cross_validation': [
            'cross_validate', 'cross_check', 'verify_consistency',
            'compare_outputs', 'validate_agreement'
        ],
        'contradiction_detection': [
            'contradiction', 'inconsistency', 'conflict_detection',
            'logical_error', 'mutual_exclusion'
        ],
        'temporal_consistency': [
            'temporal_consistency', 'timeline_check', 'chronological',
            'sequence_validation', 'temporal_logic'
        ]
    }

    # Grounding and context awareness patterns
    GROUNDING_PATTERNS = {
        'context_retrieval': [
            'retrieve_context', 'get_context', 'context_retrieval',
            'relevant_context', 'contextual_information'
        ],
        'context_injection': [
            'inject_context', 'add_context', 'prepend_context',
            'context_augmentation', 'enrich_prompt'
        ],
        'context_validation': [
            'validate_context', 'check_relevance', 'context_relevance',
            'pertinence_check', 'context_quality'
        ],
        'grounding_constraints': [
            'ground_to_context', 'context_bound', 'constrain_to_docs',
            'limit_to_context', 'context_only'
        ],
        'knowledge_grounding': [
            'ground_truth', 'knowledge_base', 'factual_base',
            'reference_corpus', 'authoritative_source'
        ]
    }

    def calculate_score(self, parsed_data: Dict[str, Any]) -> CategoryScore:
        """
        Calculate hallucination mitigation score with framework detection

        Args:
            parsed_data: Aggregated parsed data from all files

        Returns:
            CategoryScore with overall and subscategory scores
        """
        imports = parsed_data.get('imports', [])
        functions = parsed_data.get('functions', [])
        source_lines = parsed_data.get('source_lines', [])
        source_code = '\n'.join(source_lines)

        # Detect frameworks
        detected_frameworks = self._detect_frameworks(parsed_data)
        framework_features = {
            fw: self._get_framework_features(parsed_data, fw)
            for fw in detected_frameworks
        }

        # Calculate subcategory scores (legacy - now evidence-based, return int only)
        fact_check_score = self._score_factual_consistency(parsed_data)
        validation_score = self._score_output_validation(parsed_data)
        feedback_score = self._score_user_feedback(parsed_data)

        # Legacy controls (no longer returned by methods)
        fact_check_controls = []
        validation_controls = []
        feedback_controls = []

        # Calculate new comprehensive subscores
        rag_integration_score = self._score_rag_integration(parsed_data)
        citation_tracking_score = self._score_citation_tracking(parsed_data)
        confidence_scoring_score = self._score_confidence_scoring(parsed_data)
        fact_checking_score = self._score_fact_checking(parsed_data)
        consistency_checks_score = self._score_consistency_checks(parsed_data)
        grounding_score = self._score_grounding(parsed_data)

        # Calculate weighted overall score with new subscores
        overall_score = self._weighted_average(
            scores=[
                rag_integration_score,      # Most critical for hallucination prevention
                grounding_score,             # Critical for context-based responses
                citation_tracking_score,     # Important for attribution
                fact_checking_score,         # Important for verification
                consistency_checks_score,    # Important for reliability
                confidence_scoring_score,    # Good practice
                fact_check_score,            # Legacy
                validation_score,            # Legacy
                feedback_score               # Legacy
            ],
            weights=[
                0.25,  # rag_integration - highest priority
                0.20,  # grounding - critical for context
                0.15,  # citation_tracking - source attribution
                0.15,  # fact_checking - verification
                0.10,  # consistency_checks - reliability
                0.08,  # confidence_scoring - uncertainty quantification
                0.03,  # factual_consistency (legacy)
                0.02,  # output_validation (legacy)
                0.02   # user_feedback (legacy)
            ]
        )

        # Combine all detected controls
        detected_controls = fact_check_controls + validation_controls + feedback_controls

        # Calculate confidence (boost for framework detection)
        base_confidence = 0.7 + (len(detected_frameworks) * 0.05)
        total_controls = 12  # 4 fact + 5 validation + 3 feedback controls
        confidence = self._calculate_confidence(
            detection_count=len(detected_controls),
            total_possible=total_controls,
            base_confidence=min(base_confidence, 0.95)
        )

        # Generate framework insights
        framework_insights = {}
        if detected_frameworks:
            for framework in detected_frameworks:
                framework_insights[framework] = self._get_framework_insights(
                    framework,
                    framework_features.get(framework, {}),
                    fact_check_score,
                    validation_score,
                    feedback_score
                )

        return CategoryScore(
            category_id=self.category_id,
            category_name=self.category_name,
            score=overall_score,
            confidence=confidence,
            subscores={
                'factual_consistency': fact_check_score,
                'output_validation': validation_score,
                'user_feedback': feedback_score,
                # New comprehensive subscores
                'rag_integration': rag_integration_score,
                'citation_tracking': citation_tracking_score,
                'confidence_scoring': confidence_scoring_score,
                'fact_checking': fact_checking_score,
                'consistency_checks': consistency_checks_score,
                'grounding': grounding_score
            },
            detected_controls=detected_controls,
            gaps=self._identify_gaps(detected_controls),
            evidence={
                'has_rag': fact_check_score > 0,
                'has_validation': validation_score > 0,
                'has_feedback': feedback_score > 0,
                'detected_frameworks': detected_frameworks,
                'framework_insights': framework_insights,
                # New subscore flags
                'rag_integration_score': rag_integration_score,
                'citation_tracking_score': citation_tracking_score,
                'confidence_scoring_score': confidence_scoring_score,
                'fact_checking_score': fact_checking_score,
                'consistency_checks_score': consistency_checks_score,
                'grounding_score': grounding_score
            }
        )

    def _score_factual_consistency(self, parsed_data: Dict[str, Any]) -> int:
        """
        Score factual consistency checking (0-100) - Evidence-Based

        Combines evidence from RAG, citations, and fact checking.
        Factual consistency ensures outputs are grounded in truth.

        Composite score from:
        - RAG integration (35 points)
        - Citation tracking (35 points)
        - Fact checking (30 points)
        """
        # Factual consistency is composite - leverage other scored methods
        # This avoids duplicate pattern matching and reuses evidence

        # Component 1: RAG integration (grounding in documents)
        rag_score = self._score_rag_integration(parsed_data)
        has_rag = rag_score >= 85  # Has vector DB or framework

        # Component 2: Citation tracking (source attribution)
        citation_score = self._score_citation_tracking(parsed_data)
        has_citations = citation_score >= 75  # Has source tracking

        # Component 3: Fact checking (external verification)
        fact_score = self._score_fact_checking(parsed_data)
        has_fact_checking = fact_score >= 60  # Has verification

        # Additive scoring
        score = 0
        if has_rag:
            score += 35  # Grounding in retrieved documents
        if has_citations:
            score += 35  # Source attribution
        if has_fact_checking:
            score += 30  # External verification

        return min(100, score)

    def _score_output_validation(self, parsed_data: Dict[str, Any]) -> int:
        """
        Score output validation (0-100) - Evidence-Based

        Uses EvidenceCollector to detect output validation libraries.
        Output validation ensures LLM responses meet expected formats.

        Scoring based on validation sophistication:
        - Pydantic/Marshmallow schema validation: 100
        - JSON Schema validation: 75
        - Custom validation functions: 50
        - None detected: 0
        """
        from aisentry.scorers.evidence_framework import EvidenceCollector

        collector = EvidenceCollector(parsed_data)

        # Evidence 1: Pydantic validation
        pydantic_evidence = collector.collect_library_evidence(
            control_name='pydantic_output',
            module_names=['pydantic'],
            class_names=['BaseModel', 'Field'],
            function_names=['parse_obj', 'validate']
        )

        # Evidence 2: Marshmallow validation
        marshmallow_evidence = collector.collect_library_evidence(
            control_name='marshmallow_output',
            module_names=['marshmallow'],
            class_names=['Schema'],
            function_names=['load', 'validate']
        )

        # Evidence 3: JSON Schema
        jsonschema_evidence = collector.collect_library_evidence(
            control_name='jsonschema_output',
            module_names=['jsonschema'],
            class_names=['Draft7Validator'],
            function_names=['validate']
        )

        has_pydantic = pydantic_evidence.is_confident()
        has_marshmallow = marshmallow_evidence.is_confident()
        has_jsonschema = jsonschema_evidence.is_confident()

        # Evidence 4: Custom validation functions
        functions = parsed_data.get('functions', [])
        function_names = [f['name'].lower() for f in functions]
        validation_patterns = [
            'validate_output', 'check_output', 'verify_output',
            'validate_response', 'check_response'
        ]
        has_custom_validation = any(
            any(pattern in func for pattern in validation_patterns)
            for func in function_names
        )

        # Scoring logic
        if has_pydantic or has_marshmallow:
            return 100  # Schema validation
        elif has_jsonschema:
            return 75  # JSON Schema
        elif has_custom_validation:
            return 50  # Custom validation
        else:
            return 0

    def _score_user_feedback(self, parsed_data: Dict[str, Any]) -> int:
        """
        Score user feedback and correction mechanisms (0-100) - Evidence-Based

        Uses AST-based function detection for feedback systems.
        User feedback helps identify and correct hallucinations.

        Scoring based on feedback mechanisms:
        - Feedback + Review + Correction: 100
        - Feedback + Review: 75
        - Feedback only: 50
        - None detected: 0
        """
        # User feedback is primarily about feedback collection functions
        functions = parsed_data.get('functions', [])
        function_names = [f['name'].lower() for f in functions]

        # Feedback collection functions
        feedback_patterns = [
            'collect_feedback', 'submit_feedback', 'user_feedback',
            'report_issue', 'flag_response'
        ]
        has_feedback = any(
            any(pattern in func for pattern in feedback_patterns)
            for func in function_names
        )

        # Human review functions
        review_patterns = [
            'human_review', 'manual_review', 'reviewer_queue',
            'require_review', 'escalate_review'
        ]
        has_review = any(
            any(pattern in func for pattern in review_patterns)
            for func in function_names
        )

        # Correction mechanism functions
        correction_patterns = [
            'correct_response', 'update_response', 'fix_hallucination',
            'override_response', 'edit_output'
        ]
        has_correction = any(
            any(pattern in func for pattern in correction_patterns)
            for func in function_names
        )

        # Scoring logic
        if has_feedback and has_review and has_correction:
            return 100
        elif has_feedback and has_review:
            return 75
        elif has_feedback:
            return 50
        else:
            return 0

    def _score_rag_integration(self, parsed_data: Dict[str, Any]) -> int:
        """
        Score RAG integration (0-100) - Evidence-Based

        Uses multi-signal evidence collection to eliminate false positives.
        Requires import + instantiation/usage for confident detection.

        Scoring based on evidence strength:
        - LangChain RAG chains (STRONG): 100
        - LlamaIndex (STRONG): 100
        - Vector DB with retrieval (MEDIUM): 85
        - Basic vector store (WEAK): 60
        - No evidence: 0
        """
        from aisentry.scorers.evidence_framework import EvidenceCollector, EvidenceStrength

        collector = EvidenceCollector(parsed_data)

        # Evidence 1: LangChain RAG chains
        langchain_rag_evidence = collector.collect_library_evidence(
            control_name='langchain_rag',
            module_names=['langchain'],
            class_names=['RetrievalQA', 'ConversationalRetrievalChain'],
            function_names=['from_chain_type', 'invoke', 'run']
        )

        # Evidence 2: LlamaIndex
        llamaindex_evidence = collector.collect_library_evidence(
            control_name='llamaindex',
            module_names=['llama_index'],
            class_names=['VectorStoreIndex', 'StorageContext'],
            function_names=['from_documents', 'as_query_engine']
        )

        # Evidence 3: ChromaDB
        chroma_evidence = collector.collect_library_evidence(
            control_name='chromadb',
            module_names=['chromadb'],
            class_names=['Client', 'Collection'],
            function_names=['query', 'add']
        )

        # Evidence 4: Pinecone
        pinecone_evidence = collector.collect_library_evidence(
            control_name='pinecone',
            module_names=['pinecone'],
            class_names=['Index'],
            function_names=['query', 'upsert']
        )

        # Evidence 5: Weaviate
        weaviate_evidence = collector.collect_library_evidence(
            control_name='weaviate',
            module_names=['weaviate'],
            class_names=['Client'],
            function_names=['query']
        )

        # Evidence 6: Qdrant
        qdrant_evidence = collector.collect_library_evidence(
            control_name='qdrant',
            module_names=['qdrant_client'],
            class_names=['QdrantClient'],
            function_names=['search', 'query']
        )

        # Evaluate evidence strength
        has_langchain_rag = langchain_rag_evidence.is_confident()
        has_llamaindex = llamaindex_evidence.is_confident()
        has_chroma = chroma_evidence.strength >= EvidenceStrength.MEDIUM
        has_pinecone = pinecone_evidence.strength >= EvidenceStrength.MEDIUM
        has_weaviate = weaviate_evidence.strength >= EvidenceStrength.MEDIUM
        has_qdrant = qdrant_evidence.strength >= EvidenceStrength.MEDIUM

        # Score based on strongest evidence
        if has_langchain_rag or has_llamaindex:
            return 100
        elif has_chroma or has_pinecone or has_weaviate or has_qdrant:
            return 85
        else:
            # Check for basic retrieval patterns (very weak evidence)
            retrieval_patterns = ['retrieve', 'search', 'query']
            functions = parsed_data.get('function_calls', [])
            has_retrieval = any(any(pattern in func.lower() for pattern in retrieval_patterns)
                              for func in functions)
            return 60 if has_retrieval else 0

    def _score_citation_tracking(self, parsed_data: Dict[str, Any]) -> int:
        """
        Score citation tracking (0-100) - Evidence-Based

        Uses AST-based detection for metadata and citation tracking.
        Checks for 'metadata', 'source', 'citation' in function calls and parameters.

        Scoring based on source attribution:
        - Full citation tracking (metadata + source + citation): 100
        - Source IDs (source + metadata): 75
        - Metadata only: 50
        - None detected: 0
        """
        # AST-based detection: Check function calls for metadata/source/citation
        function_calls = parsed_data.get('function_calls', [])
        structured_calls = parsed_data.get('structured_calls', [])

        # Convert to lowercase strings for pattern matching
        all_calls_str = ' '.join([str(call).lower() for call in function_calls + structured_calls])

        # Check for metadata tracking
        metadata_patterns = ['metadata', 'meta', 'document_metadata', 'doc_metadata']
        has_metadata = any(pattern in all_calls_str for pattern in metadata_patterns)

        # Check for source tracking
        source_patterns = ['source', 'source_id', 'source_document', 'document_source', 'retrieve_source']
        has_source = any(pattern in all_calls_str for pattern in source_patterns)

        # Check for citation tracking
        citation_patterns = ['citation', 'cite', 'reference', 'attribution', 'provenance']
        has_citation = any(pattern in all_calls_str for pattern in citation_patterns)

        # Also check function definitions for citation-related methods
        functions = parsed_data.get('functions', [])
        function_names = [f['name'].lower() for f in functions]
        citation_function_patterns = [
            'add_citation', 'track_source', 'get_citation', 'format_citation',
            'add_source', 'get_source', 'track_metadata'
        ]
        has_citation_function = any(
            any(pattern in func for pattern in citation_function_patterns)
            for func in function_names
        )

        # Scoring logic
        if has_metadata and has_source and (has_citation or has_citation_function):
            return 100
        elif has_source and has_metadata:
            return 75
        elif has_metadata or has_source:
            return 50
        else:
            return 0

    def _score_confidence_scoring(self, parsed_data: Dict[str, Any]) -> int:
        """
        Score confidence scoring (0-100) - Evidence-Based

        Uses AST-based detection for temperature, logprobs, and confidence parameters.
        Checks function calls for confidence/probability patterns.

        Scoring based on uncertainty quantification:
        - Calibration + temperature scaling: 100
        - Confidence scores extracted (logprobs): 75
        - Temperature only: 50
        - None detected: 0
        """
        # AST-based detection: Check function calls for confidence parameters
        function_calls = parsed_data.get('function_calls', [])
        structured_calls = parsed_data.get('structured_calls', [])

        # Convert to lowercase strings for pattern matching
        all_calls_str = ' '.join([str(call).lower() for call in function_calls + structured_calls])

        # Check for temperature parameter
        temperature_patterns = ['temperature', 'temp=', 'temperature=']
        has_temperature = any(pattern in all_calls_str for pattern in temperature_patterns)

        # Check for logprobs/probability extraction
        logprobs_patterns = ['logprobs', 'log_probs', 'logprobs=', 'log_probability']
        has_logprobs = any(pattern in all_calls_str for pattern in logprobs_patterns)

        # Check for confidence scoring
        confidence_patterns = ['confidence', 'confidence_score', 'score_confidence', 'probability']
        has_confidence = any(pattern in all_calls_str for pattern in confidence_patterns)

        # Check for calibration functions
        functions = parsed_data.get('functions', [])
        function_names = [f['name'].lower() for f in functions]
        calibration_patterns = [
            'calibrate', 'temperature_scale', 'platt_scaling', 'isotonic_regression',
            'calibrate_confidence', 'scale_temperature'
        ]
        has_calibration = any(
            any(pattern in func for pattern in calibration_patterns)
            for func in function_names
        )

        # Scoring logic
        if has_calibration and has_temperature:
            return 100
        elif has_logprobs or (has_confidence and has_temperature):
            return 75
        elif has_temperature:
            return 50
        else:
            return 0

    def _score_fact_checking(self, parsed_data: Dict[str, Any]) -> int:
        """
        Score fact checking (0-100) - Evidence-Based

        Uses EvidenceCollector to detect fact verification mechanisms.
        Requires import + instantiation/usage for confident detection.

        Scoring based on verification mechanisms:
        - External APIs (web search/knowledge bases): 100
        - Database verification: 75
        - Custom fact checking functions: 60
        - None detected: 0
        """
        from aisentry.scorers.evidence_framework import EvidenceCollector

        collector = EvidenceCollector(parsed_data)

        # Evidence 1: Web search APIs (SerpAPI, Google Search)
        serpapi_evidence = collector.collect_library_evidence(
            control_name='serpapi',
            module_names=['serpapi'],
            class_names=['GoogleSearch', 'Client'],
            function_names=['search', 'get_dict']
        )

        googlesearch_evidence = collector.collect_library_evidence(
            control_name='googlesearch',
            module_names=['googlesearch', 'google'],
            class_names=[''],
            function_names=['search']
        )

        # Evidence 2: Knowledge base APIs (Wikipedia, Wikidata)
        wikipedia_evidence = collector.collect_library_evidence(
            control_name='wikipedia',
            module_names=['wikipedia'],
            class_names=[''],
            function_names=['search', 'page', 'summary']
        )

        # Evidence 3: Database verification (SQLAlchemy, psycopg2)
        sqlalchemy_evidence = collector.collect_library_evidence(
            control_name='sqlalchemy',
            module_names=['sqlalchemy'],
            class_names=['Engine', 'Session'],
            function_names=['execute', 'query']
        )

        has_web_search = (serpapi_evidence.is_confident() or
                         googlesearch_evidence.is_confident())
        has_knowledge_base = wikipedia_evidence.is_confident()
        has_db_verification = sqlalchemy_evidence.is_confident()

        # Evidence 4: Custom fact checking functions (AST-based)
        functions = parsed_data.get('functions', [])
        function_names = [f['name'].lower() for f in functions]
        fact_check_patterns = [
            'verify_fact', 'check_fact', 'fact_check', 'validate_claim',
            'verify_claim', 'check_accuracy'
        ]
        has_custom_fact_check = any(
            any(pattern in func for pattern in fact_check_patterns)
            for func in function_names
        )

        # Scoring logic
        if has_web_search or has_knowledge_base:
            return 100
        elif has_db_verification:
            return 75
        elif has_custom_fact_check:
            return 60
        else:
            return 0

    def _score_consistency_checks(self, parsed_data: Dict[str, Any]) -> int:
        """
        Score consistency checks (0-100) - Evidence-Based

        Uses AST-based function detection for consistency checking.
        Consistency checks detect contradictions in LLM outputs.

        Scoring based on consistency mechanisms:
        - Multiple consistency check types: 100
        - Single consistency check: 60
        - None detected: 0
        """
        # Consistency checks are primarily custom functions
        functions = parsed_data.get('functions', [])
        function_names = [f['name'].lower() for f in functions]

        # Self-consistency functions
        self_consistency_patterns = [
            'self_consistency', 'check_consistency', 'consistency_check',
            'multiple_generation', 'multi_gen'
        ]
        has_self_consistency = any(
            any(pattern in func for pattern in self_consistency_patterns)
            for func in function_names
        )

        # Contradiction detection functions
        contradiction_patterns = [
            'detect_contradiction', 'check_contradiction', 'find_inconsistency',
            'contradiction_detector'
        ]
        has_contradiction = any(
            any(pattern in func for pattern in contradiction_patterns)
            for func in function_names
        )

        # Cross-validation functions
        cross_val_patterns = [
            'cross_validate', 'cross_validation', 'validate_against',
            'compare_sources'
        ]
        has_cross_val = any(
            any(pattern in func for pattern in cross_val_patterns)
            for func in function_names
        )

        # Count consistency mechanisms
        count = sum([has_self_consistency, has_contradiction, has_cross_val])

        # Scoring logic
        if count >= 2:
            return 100  # Multiple consistency mechanisms
        elif count == 1:
            return 60  # Single consistency mechanism
        else:
            return 0  # No consistency checks

    def _score_grounding(self, parsed_data: Dict[str, Any]) -> int:
        """
        Score grounding mechanisms (0-100) - Evidence-Based

        Grounding is primarily achieved through RAG integration.
        This is a composite score leveraging RAG evidence.

        Scoring:
        - RAG integration score directly translates to grounding score
        """
        # Grounding is essentially RAG - reuse that evidence
        rag_score = self._score_rag_integration(parsed_data)
        return rag_score

    def _identify_gaps(self, detected_controls: List[str]) -> List[str]:
        """Identify missing hallucination mitigation controls"""
        gaps = []

        # Define all possible controls
        all_controls = {
            "Source verification",
            "Citation tracking / RAG",
            "Grounding mechanisms",
            "Cross-validation",
            "Hallucination detection library",
            "Schema validation",
            "Constraint checking",
            "Format validation",
            "Consistency checks",
            "Confidence scoring",
            "User feedback collection",
            "Human review process",
            "Response correction",
            "User override"
        }

        # Find missing controls
        detected_set = set(detected_controls)
        missing = all_controls - detected_set

        if missing:
            gaps.append(f"Missing controls: {', '.join(sorted(missing)[:5])}")
            if len(missing) > 5:
                gaps.append(f"Plus {len(missing) - 5} more controls need implementation")

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
        """Detect which RAG features of a framework are being used"""
        all_text = ' '.join(parsed_data.get('source_lines', [])).lower()
        features = {}

        if framework == 'langchain':
            patterns = self.LANGCHAIN_PATTERNS
            features = {
                'rag_chains': any(p.lower() in all_text for p in patterns['rag_chains']),
                'vector_stores': any(p.lower() in all_text for p in patterns['vector_stores']),
                'source_attribution': any(p.lower() in all_text for p in patterns['source_attribution']),
                'output_parsers': any(p.lower() in all_text for p in patterns['output_parsers']),
                'validation': any(p.lower() in all_text for p in patterns['validation'])
            }
        elif framework == 'llamaindex':
            patterns = self.LLAMAINDEX_PATTERNS
            features = {
                'query_engines': any(p.lower() in all_text for p in patterns['query_engines']),
                'response_synthesis': any(p.lower() in all_text for p in patterns['response_synthesis']),
                'retrievers': any(p.lower() in all_text for p in patterns['retrievers']),
                'citation': any(p.lower() in all_text for p in patterns['citation']),
                'evaluation': any(p.lower() in all_text for p in patterns['evaluation'])
            }
        elif framework == 'haystack':
            patterns = self.HAYSTACK_PATTERNS
            features = {
                'rag_pipelines': any(p.lower() in all_text for p in patterns['rag_pipelines']),
                'retrievers': any(p.lower() in all_text for p in patterns['retrievers']),
                'answer_generation': any(p.lower() in all_text for p in patterns['answer_generation']),
                'document_stores': any(p.lower() in all_text for p in patterns['document_stores']),
                'validation': any(p.lower() in all_text for p in patterns['validation'])
            }

        return features

    def _get_framework_insights(
        self,
        framework: str,
        features: Dict[str, bool],
        fact_check_score: int,
        validation_score: int,
        feedback_score: int
    ) -> Dict[str, Any]:
        """Generate hallucination mitigation insights for detected framework"""
        recommendations = []
        best_practices = []

        if framework == 'langchain':
            if features.get('rag_chains'):
                best_practices.append("Using RAG chains (RetrievalQA) for grounded responses")
            if features.get('source_attribution'):
                best_practices.append("Implementing source attribution with return_source_documents")
            if features.get('output_parsers'):
                best_practices.append("Using output parsers for structured validation")

            if not features.get('source_attribution'):
                recommendations.append("Enable return_source_documents=True in RetrievalQA for citation tracking")
            if not features.get('output_parsers'):
                recommendations.append("Add PydanticOutputParser or StructuredOutputParser for response validation")
            if fact_check_score < 60:
                recommendations.append("Consider using ConversationalRetrievalChain with source tracking")

        elif framework == 'llamaindex':
            if features.get('query_engines'):
                best_practices.append("Using query engines for structured retrieval")
            if features.get('citation'):
                best_practices.append("Implementing citation with source_nodes")
            if features.get('evaluation'):
                best_practices.append("Using LlamaIndex evaluators for response quality")

            if not features.get('citation'):
                recommendations.append("Use CitationQueryEngine or access source_nodes for attribution")
            if not features.get('evaluation'):
                recommendations.append("Add FaithfulnessEvaluator and RelevancyEvaluator for response validation")
            if validation_score < 60:
                recommendations.append("Implement ResponseSynthesizer with CompactAndRefine for better accuracy")

        elif framework == 'haystack':
            if features.get('rag_pipelines'):
                best_practices.append("Using GenerativeQAPipeline for RAG")
            if features.get('retrievers'):
                best_practices.append("Implementing retrieval with EmbeddingRetriever or BM25")

            if not features.get('validation'):
                recommendations.append("Add OutputValidator to validate generated responses")
            if not features.get('rag_pipelines'):
                recommendations.append("Consider using GenerativeQAPipeline for document-grounded generation")
            if fact_check_score < 60:
                recommendations.append("Ensure PromptNode includes source attribution in responses")

        return {
            'detected_features': features,
            'security_recommendations': recommendations,
            'best_practices': best_practices
        }
