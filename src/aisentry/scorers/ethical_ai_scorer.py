"""
Category 5: Ethical AI & Bias Detection Scorer

Scores the project's ethical AI practices and bias mitigation for:
- Bias Testing & Monitoring (demographic, social, cultural bias detection)
- Fairness Metrics (quantitative fairness measurement)
- Model Explainability (decision transparency, interpretability)
- Diverse Training Data (representation, inclusivity)
- Harmful Content Filtering (toxicity, hate speech, offensive content)
- Transparency & Disclosure (AI disclosure, user awareness)

Each subcategory is scored 0-100 based on detected controls.
"""

import logging
from typing import Any, Dict, List

from aisentry.scorers.base_scorer import BaseScorer, CategoryScore

logger = logging.getLogger(__name__)


class EthicalAIScorer(BaseScorer):
    """
    Score Category 5: Ethical AI & Bias Detection

    Evaluates:
    - 5.1 Bias Testing & Monitoring (25%)
    - 5.2 Fairness Metrics (20%)
    - 5.3 Model Explainability (20%)
    - 5.4 Harmful Content Filtering (15%)
    - 5.5 Diverse Training Data (10%)
    - 5.6 Transparency & Disclosure (7%)
    - 5.7 Legacy Bias Detection (2%)
    - 5.8 Legacy Fairness (1%)

    Framework-aware scoring for bias detection, fairness, and explainability tools.
    """

    category_id = "5_ethical_ai"
    category_name = "Ethical AI & Bias Detection"

    # ============================================================================
    # Comprehensive Bias Testing & Monitoring Patterns (25%)
    # ============================================================================
    COMPREHENSIVE_BIAS_TESTING_PATTERNS = {
        'bias_testing_frameworks': [
            'fairlearn', 'Fairlearn', 'FairlearnTester',
            'aif360', 'AIF360', 'IBM AIF360', 'AIFairness360',
            'what-if-tool', 'WhatIfTool', 'witwidget',
            'bias_testing', 'BiasTest', 'BiasMonitor'
        ],
        'demographic_bias': [
            'demographic_parity', 'DemographicParity', 'demographic_bias',
            'group_fairness', 'GroupFairness', 'protected_attributes',
            'sensitive_features', 'demographic_features', 'race_bias',
            'gender_bias', 'age_bias', 'ethnicity_bias'
        ],
        'social_bias': [
            'social_bias', 'SocialBias', 'stereotype_detection',
            'StereotypeDetection', 'cultural_bias', 'CulturalBias',
            'implicit_bias', 'ImplicitBias', 'social_fairness'
        ],
        'continuous_monitoring': [
            'bias_monitor', 'BiasMonitor', 'continuous_bias_check',
            'real_time_bias', 'bias_dashboard', 'BiasDashboard',
            'bias_alert', 'BiasAlert', 'monitor_bias', 'track_bias'
        ],
        'ml_bias_detection': [
            'bias_classifier', 'BiasClassifier', 'bias_model',
            'detect_bias', 'BiasDetector', 'bias_score',
            'bias_probability', 'bias_prediction'
        ]
    }

    # ============================================================================
    # Comprehensive Fairness Metrics Patterns (20%)
    # ============================================================================
    COMPREHENSIVE_FAIRNESS_METRICS_PATTERNS = {
        'statistical_parity': [
            'statistical_parity', 'StatisticalParity', 'demographic_parity',
            'DemographicParity', 'independence', 'group_fairness'
        ],
        'equalized_odds': [
            'equalized_odds', 'EqualizedOdds', 'equal_opportunity',
            'EqualOpportunity', 'separation', 'true_positive_parity',
            'false_positive_parity'
        ],
        'disparate_impact': [
            'disparate_impact', 'DisparateImpact', 'adverse_impact',
            'AdverseImpact', 'impact_ratio', '80_percent_rule',
            'four_fifths_rule'
        ],
        'calibration_metrics': [
            'calibration', 'Calibration', 'calibration_by_group',
            'predictive_parity', 'PredictiveParity', 'sufficiency'
        ],
        'fairness_metrics_computation': [
            'MetricFrame', 'fairness_metrics', 'compute_fairness',
            'FairnessMetrics', 'bias_metrics', 'BiasMetrics',
            'selection_rate', 'SelectionRate', 'confusion_matrix_by_group'
        ],
        'threshold_optimization': [
            'ThresholdOptimizer', 'threshold_optimizer', 'optimize_threshold',
            'fair_threshold', 'calibrated_threshold'
        ]
    }

    # ============================================================================
    # Comprehensive Model Explainability Patterns (20%)
    # ============================================================================
    COMPREHENSIVE_EXPLAINABILITY_PATTERNS = {
        'shap': [
            'shap', 'SHAP', 'shap_values', 'TreeExplainer',
            'KernelExplainer', 'DeepExplainer', 'GradientExplainer',
            'LinearExplainer', 'shap.Explainer', 'shap.summary_plot',
            'shap.force_plot', 'shap.waterfall_plot'
        ],
        'lime': [
            'lime', 'LIME', 'LimeTextExplainer', 'LimeTabularExplainer',
            'LimeImageExplainer', 'lime_explainer', 'explain_instance'
        ],
        'eli5': [
            'eli5', 'ELI5', 'eli5.explain_weights', 'eli5.explain_prediction',
            'eli5.show_weights', 'eli5.show_prediction'
        ],
        'integrated_gradients': [
            'IntegratedGradients', 'integrated_gradients', 'captum',
            'Captum', 'LayerIntegratedGradients', 'NeuronIntegratedGradients',
            'ig_attribution', 'gradient_based_attribution'
        ],
        'attention_visualization': [
            'attention_weights', 'AttentionWeights', 'visualize_attention',
            'attention_map', 'AttentionMap', 'attention_scores',
            'self_attention_viz', 'BertViz', 'bertviz'
        ],
        'feature_importance': [
            'feature_importance', 'FeatureImportance', 'feature_importances_',
            'permutation_importance', 'PermutationImportance',
            'get_feature_importance', 'explain_features'
        ],
        'counterfactual_explanations': [
            'counterfactual', 'Counterfactual', 'DiCE', 'dice_ml',
            'generate_counterfactuals', 'CounterfactualExplanations',
            'what_if_analysis'
        ]
    }

    # ============================================================================
    # Comprehensive Harmful Content Filtering Patterns (15%)
    # ============================================================================
    COMPREHENSIVE_HARMFUL_CONTENT_PATTERNS = {
        'toxicity_detection': [
            'Detoxify', 'detoxify', 'ToxicityClassifier',
            'perspective_api', 'PerspectiveAPI', 'toxicity_score',
            'toxic_classifier', 'ToxicBERT', 'toxicbert',
            'is_toxic', 'detect_toxicity', 'toxicity_filter'
        ],
        'hate_speech_detection': [
            'hate_speech', 'HateSpeech', 'HateSpeechClassifier',
            'hate_detector', 'HateDetector', 'detect_hate',
            'hate_filter', 'HateFilter', 'offensive_language'
        ],
        'profanity_filtering': [
            'profanity', 'Profanity', 'profanity_check',
            'better_profanity', 'ProfanityFilter', 'profanity_filter',
            'censor', 'censorship', 'bad_words', 'word_blacklist'
        ],
        'openai_moderation': [
            'openai.Moderation', 'moderation', 'ModerationChain',
            'openai_moderation', 'content_moderation', 'ContentModeration',
            'moderation_api', 'moderate_content'
        ],
        'guardrails_moderation': [
            'guardrails', 'Guardrails', 'Guard', 'guardrails_ai',
            'ValidLength', 'ToxicLanguage', 'ProfanityFree',
            'guard.validate', 'content_safety'
        ],
        'custom_content_filters': [
            'ContentFilter', 'content_filter', 'SafetyFilter',
            'safety_filter', 'harmful_content_check', 'content_policy',
            'ContentPolicy', 'safety_classifier'
        ]
    }

    # ============================================================================
    # Comprehensive Diverse Training Data Patterns (10%)
    # ============================================================================
    COMPREHENSIVE_DIVERSE_TRAINING_PATTERNS = {
        'data_diversity_checks': [
            'diversity_check', 'DiversityCheck', 'data_diversity',
            'DataDiversity', 'demographic_representation', 'representation_analysis',
            'diversity_metrics', 'DiversityMetrics'
        ],
        'balanced_sampling': [
            'balanced_sampling', 'BalancedSampling', 'stratified_sampling',
            'StratifiedSampling', 'oversample', 'undersample',
            'SMOTE', 'RandomOverSampler', 'RandomUnderSampler',
            'imblearn', 'imbalanced_learn'
        ],
        'augmentation_diversity': [
            'augmentation', 'Augmentation', 'data_augmentation',
            'DataAugmentation', 'augment_minority', 'synthetic_data',
            'SyntheticData', 'backtranslation', 'paraphrase'
        ],
        'inclusive_datasets': [
            'inclusive_dataset', 'InclusiveDataset', 'diverse_corpus',
            'DiverseCorpus', 'multilingual', 'Multilingual',
            'cross_cultural', 'CrossCultural', 'representative_data'
        ],
        'bias_mitigation_preprocessing': [
            'Reweighing', 'reweighing', 'LFR', 'lfr',
            'OptimPreproc', 'optim_preproc', 'DisparateImpactRemover',
            'disparate_impact_remover', 'bias_mitigation'
        ]
    }

    # ============================================================================
    # Comprehensive Transparency & Disclosure Patterns (7%)
    # ============================================================================
    COMPREHENSIVE_TRANSPARENCY_PATTERNS = {
        'ai_disclosure': [
            'ai_disclosure', 'AIDisclosure', 'ai_notice',
            'AINotice', 'bot_disclosure', 'BotDisclosure',
            'is_ai', 'powered_by_ai', 'ai_generated'
        ],
        'model_cards': [
            'model_card', 'ModelCard', 'model_documentation',
            'ModelDocumentation', 'model_info', 'ModelInfo',
            'model_metadata', 'ModelMetadata'
        ],
        'capability_disclosure': [
            'capability_disclosure', 'CapabilityDisclosure', 'limitations',
            'Limitations', 'model_limitations', 'known_limitations',
            'capability_notice', 'disclosure_message'
        ],
        'user_consent_ai': [
            'ai_consent', 'AIConsent', 'user_consent_ai',
            'UserConsentAI', 'agree_to_ai', 'ai_terms',
            'consent_to_ai_processing'
        ],
        'transparency_logging': [
            'transparency_log', 'TransparencyLog', 'disclosure_log',
            'DisclosureLog', 'ai_interaction_log', 'track_ai_usage',
            'ai_audit_trail'
        ]
    }

    # ============================================================================
    # Legacy Patterns (3% total)
    # ============================================================================
    LEGACY_BIAS_PATTERNS = {
        'basic_bias': [
            'bias', 'Bias', 'fairness', 'Fairness',
            'discriminate', 'discrimination'
        ]
    }

    LEGACY_FAIRNESS_PATTERNS = {
        'basic_fairness': [
            'fair', 'Fair', 'equal', 'Equal',
            'equity', 'Equity'
        ]
    }

    def calculate_score(self, parsed_data: Dict[str, Any]) -> CategoryScore:
        """
        Calculate overall Ethical AI score with weighted subscores

        Comprehensive subscores (97%):
        - Bias Testing & Monitoring: 25%
        - Fairness Metrics: 20%
        - Model Explainability: 20%
        - Harmful Content Filtering: 15%
        - Diverse Training Data: 10%
        - Transparency & Disclosure: 7%

        Legacy subscores (3%):
        - Legacy Bias Detection: 2%
        - Legacy Fairness: 1%
        """
        # Calculate all subscores
        bias_testing_score = self._score_bias_testing_comprehensive(parsed_data)
        fairness_metrics_score = self._score_fairness_metrics_comprehensive(parsed_data)
        explainability_score = self._score_explainability_comprehensive(parsed_data)
        harmful_content_score = self._score_harmful_content_comprehensive(parsed_data)
        diverse_training_score = self._score_diverse_training_comprehensive(parsed_data)
        transparency_score = self._score_transparency_comprehensive(parsed_data)

        # Legacy subscores
        legacy_bias_score = self._score_legacy_bias(parsed_data)
        legacy_fairness_score = self._score_legacy_fairness(parsed_data)

        # Weighted average (prioritizing comprehensive subscores)
        overall_score = self._weighted_average(
            scores=[
                bias_testing_score,      # 25%
                fairness_metrics_score,  # 20%
                explainability_score,    # 20%
                harmful_content_score,   # 15%
                diverse_training_score,  # 10%
                transparency_score,      # 7%
                legacy_bias_score,       # 2%
                legacy_fairness_score    # 1%
            ],
            weights=[0.25, 0.20, 0.20, 0.15, 0.10, 0.07, 0.02, 0.01]
        )

        # Calculate confidence based on number of subscores with detections
        detection_count = sum(
            1 for score in [bias_testing_score, fairness_metrics_score, explainability_score,
                          harmful_content_score, diverse_training_score, transparency_score]
            if score > 0
        )
        confidence = self._calculate_confidence(detection_count, 6, base_confidence=0.8)

        return CategoryScore(
            category_id=self.category_id,
            category_name=self.category_name,
            score=int(overall_score),
            confidence=confidence,
            subscores={
                'bias_testing': bias_testing_score,
                'fairness_metrics': fairness_metrics_score,
                'explainability': explainability_score,
                'harmful_content_filtering': harmful_content_score,
                'diverse_training': diverse_training_score,
                'transparency': transparency_score,
                'legacy_bias_detection': legacy_bias_score,
                'legacy_fairness': legacy_fairness_score
            }
        )

    # ============================================================================
    # Comprehensive Scoring Methods
    # ============================================================================

    def _score_bias_testing_comprehensive(self, parsed_data: Dict[str, Any]) -> int:
        """
        Score comprehensive bias testing & monitoring - Evidence-Based

        Uses multi-signal evidence collection to eliminate false positives.
        Requires import + instantiation/usage for confident detection.

        Scoring based on evidence strength:
        - Fairlearn or AIF360 (STRONG): 100
        - Custom bias metrics (MEDIUM): 70
        - Basic demographic checks (WEAK): 50
        - No evidence: 0
        """
        from aisentry.scorers.evidence_framework import EvidenceCollector

        collector = EvidenceCollector(parsed_data)

        # Evidence 1: Fairlearn (Microsoft's fairness toolkit)
        fairlearn_evidence = collector.collect_library_evidence(
            control_name='fairlearn',
            module_names=['fairlearn'],
            class_names=['MetricFrame', 'ThresholdOptimizer', 'DemographicParity'],
            function_names=['']
        )

        # Evidence 2: AIF360 (IBM's AI Fairness 360)
        aif360_evidence = collector.collect_library_evidence(
            control_name='aif360',
            module_names=['aif360'],
            class_names=['BinaryLabelDataset', 'Reweighing', 'DisparateImpactRemover'],
            function_names=['']
        )

        # Evidence 3: What-If Tool
        whatif_evidence = collector.collect_library_evidence(
            control_name='whatif',
            module_names=['what-if-tool', 'witwidget'],
            class_names=['WitWidget'],
            function_names=['']
        )

        # Evaluate evidence strength
        has_fairlearn = fairlearn_evidence.is_confident()
        has_aif360 = aif360_evidence.is_confident()
        has_whatif = whatif_evidence.is_confident()

        # Score based on strongest evidence
        if has_fairlearn or has_aif360:
            return 100
        elif has_whatif:
            return 85
        else:
            # Check for custom bias testing functions
            bias_patterns = ['test_bias', 'check_fairness', 'demographic_parity', 'equal_opportunity']
            functions = parsed_data.get('function_calls', [])
            has_custom_bias = any(any(pattern in func.lower() for pattern in bias_patterns)
                                for func in functions)

            # Check for basic demographic checks
            demographic_patterns = ['gender', 'race', 'age', 'protected_attribute']
            has_demographic = any(any(pattern in func.lower() for pattern in demographic_patterns)
                                for func in functions)

            if has_custom_bias:
                return 70
            elif has_demographic:
                return 50
            else:
                return 0

    def _score_fairness_metrics_comprehensive(self, parsed_data: Dict[str, Any]) -> int:
        """
        Score comprehensive fairness metrics implementation - Evidence-Based

        Uses EvidenceCollector to detect fairness metric libraries.
        Fairness metrics measure model equity across demographic groups.

        Scoring tiers:
        - 100: Fairlearn MetricFrame (comprehensive metrics)
        - 85: AIF360 metrics
        - 70: Custom fairness metric functions
        - 0: None detected
        """
        from aisentry.scorers.evidence_framework import EvidenceCollector

        collector = EvidenceCollector(parsed_data)

        # Evidence 1: Fairlearn MetricFrame (comprehensive fairness metrics)
        fairlearn_metrics_evidence = collector.collect_library_evidence(
            control_name='fairlearn_metrics',
            module_names=['fairlearn'],
            class_names=['MetricFrame'],
            function_names=['']
        )

        # Evidence 2: AIF360 metrics
        aif360_metrics_evidence = collector.collect_library_evidence(
            control_name='aif360_metrics',
            module_names=['aif360'],
            class_names=['BinaryLabelDatasetMetric', 'ClassificationMetric'],
            function_names=['']
        )

        has_fairlearn_metrics = fairlearn_metrics_evidence.is_confident()
        has_aif360_metrics = aif360_metrics_evidence.is_confident()

        # Evidence 3: Custom fairness metric functions (AST-based)
        function_defs = parsed_data.get('function_defs', [])
        function_names = [f.lower() for f in function_defs]

        fairness_metric_patterns = [
            'statistical_parity', 'equalized_odds', 'disparate_impact',
            'demographic_parity', 'equal_opportunity', 'fairness_metric',
            'calculate_fairness', 'measure_fairness'
        ]
        has_custom_metrics = any(
            any(pattern in func for pattern in fairness_metric_patterns)
            for func in function_names
        )

        # Scoring logic
        if has_fairlearn_metrics:
            return 100  # Best: Comprehensive MetricFrame
        elif has_aif360_metrics:
            return 85  # Good: AIF360 metrics
        elif has_custom_metrics:
            return 70  # Custom fairness metrics
        else:
            return 0  # No fairness metrics detected

    def _score_explainability_comprehensive(self, parsed_data: Dict[str, Any]) -> int:
        """
        Score comprehensive model explainability - Evidence-Based

        Uses EvidenceCollector to detect explainability libraries like SHAP, LIME, ELI5, Captum.
        Requires import + instantiation/usage for confident detection.

        Scoring tiers:
        - 100: SHAP + LIME (both with confident evidence)
        - 85: SHAP or LIME (with confident evidence)
        - 70: ELI5 or Captum (integrated gradients)
        - 50: Feature importance patterns detected
        - 0: None detected
        """
        from aisentry.scorers.evidence_framework import EvidenceCollector

        collector = EvidenceCollector(parsed_data)

        # Evidence 1: SHAP (most popular explainability library)
        shap_evidence = collector.collect_library_evidence(
            control_name='shap',
            module_names=['shap'],
            class_names=['Explainer', 'TreeExplainer', 'KernelExplainer', 'DeepExplainer'],
            function_names=['shap_values', 'explain']
        )

        # Evidence 2: LIME (Local Interpretable Model-agnostic Explanations)
        lime_evidence = collector.collect_library_evidence(
            control_name='lime',
            module_names=['lime'],
            class_names=['LimeTextExplainer', 'LimeTabularExplainer', 'LimeImageExplainer'],
            function_names=['explain_instance']
        )

        # Evidence 3: ELI5 (Explain Like I'm 5)
        eli5_evidence = collector.collect_library_evidence(
            control_name='eli5',
            module_names=['eli5'],
            class_names=[''],
            function_names=['explain_weights', 'explain_prediction']
        )

        # Evidence 4: Captum (PyTorch interpretability)
        captum_evidence = collector.collect_library_evidence(
            control_name='captum',
            module_names=['captum'],
            class_names=['IntegratedGradients', 'LayerIntegratedGradients'],
            function_names=['attribute']
        )

        has_shap = shap_evidence.is_confident()
        has_lime = lime_evidence.is_confident()
        has_eli5 = eli5_evidence.is_confident()
        has_captum = captum_evidence.is_confident()

        # Evidence 5: Feature importance patterns (AST-based)
        function_defs = parsed_data.get('function_defs', [])
        function_names = [f.lower() for f in function_defs]
        feature_importance_patterns = [
            'feature_importance', 'get_feature_importance', 'plot_importance',
            'calculate_importance', 'feature_weights'
        ]
        has_feature_importance = any(
            any(pattern in func for pattern in feature_importance_patterns)
            for func in function_names
        )

        # Scoring logic
        if has_shap and has_lime:
            return 100
        elif has_shap or has_lime:
            return 85
        elif has_eli5 or has_captum:
            return 70
        elif has_feature_importance:
            return 50
        else:
            return 0

    def _score_harmful_content_comprehensive(self, parsed_data: Dict[str, Any]) -> int:
        """
        Score comprehensive harmful content filtering - Evidence-Based

        Uses multi-signal evidence collection to eliminate false positives.
        Requires import + instantiation/usage for confident detection.

        Scoring based on evidence strength:
        - Commercial APIs (OpenAI/Azure/Perspective, STRONG): 100
        - Detoxify (open-source, STRONG): 85
        - Guardrails AI (STRONG): 80
        - Custom ML toxicity (MEDIUM): 70
        - Basic profanity filter (WEAK): 40
        - No evidence: 0
        """
        from aisentry.scorers.evidence_framework import EvidenceCollector, EvidenceStrength

        collector = EvidenceCollector(parsed_data)

        # Evidence 1: OpenAI Moderation API
        openai_mod_evidence = collector.collect_library_evidence(
            control_name='openai_moderation',
            module_names=['openai'],
            class_names=['Moderation'],
            function_names=['create']
        )

        # Evidence 2: Azure Content Safety
        azure_safety_evidence = collector.collect_library_evidence(
            control_name='azure_content_safety',
            module_names=['azure.ai.contentsafety'],
            class_names=['ContentSafetyClient'],
            function_names=['analyze_text']
        )

        # Evidence 3: Perspective API
        perspective_evidence = collector.collect_library_evidence(
            control_name='perspective',
            module_names=['perspective'],
            class_names=['PerspectiveAPI'],
            function_names=['analyze']
        )

        # Evidence 4: Detoxify (open-source toxicity classifier)
        detoxify_evidence = collector.collect_library_evidence(
            control_name='detoxify',
            module_names=['detoxify'],
            class_names=['Detoxify'],
            function_names=['predict']
        )

        # Evidence 5: Guardrails AI
        guardrails_evidence = collector.collect_library_evidence(
            control_name='guardrails',
            module_names=['guardrails'],
            class_names=['Guard'],
            function_names=['validate']
        )

        # Evidence 6: Custom ML toxicity detector
        ml_toxicity_evidence = collector.collect_library_evidence(
            control_name='ml_toxicity',
            module_names=['transformers', 'tensorflow', 'torch'],
            class_names=['pipeline', 'AutoModelForSequenceClassification'],
            function_names=['predict', 'classify']
        )

        # Evaluate evidence strength
        has_openai_mod = openai_mod_evidence.is_confident()
        has_azure_safety = azure_safety_evidence.is_confident()
        has_perspective = perspective_evidence.is_confident()
        has_detoxify = detoxify_evidence.is_confident()
        has_guardrails = guardrails_evidence.is_confident()
        has_ml_toxicity = ml_toxicity_evidence.strength >= EvidenceStrength.MEDIUM

        # Score based on strongest evidence
        if has_openai_mod or has_azure_safety or has_perspective:
            return 100
        elif has_detoxify:
            return 85
        elif has_guardrails:
            return 80
        elif has_ml_toxicity:
            return 70
        else:
            # Check for basic profanity filter (very weak evidence)
            profanity_patterns = ['profanity', 'bad_words', 'filter_text']
            functions = parsed_data.get('function_calls', [])
            has_profanity = any(any(pattern in func.lower() for pattern in profanity_patterns)
                              for func in functions)
            return 40 if has_profanity else 0

    def _score_diverse_training_comprehensive(self, parsed_data: Dict[str, Any]) -> int:
        """
        Score comprehensive diverse training data practices - Evidence-Based

        Uses AST-based function detection for data diversity practices.
        Diverse training data helps reduce bias in AI models.

        Scoring tiers:
        - 100: Diversity checks + balanced sampling + augmentation
        - 75: Balanced sampling + augmentation
        - 60: Balanced sampling or diversity checks
        - 0: None detected
        """
        # Data diversity is primarily about data preparation functions
        function_defs = parsed_data.get('function_defs', [])
        function_names = [f.lower() for f in function_defs]

        # Diversity check functions
        diversity_patterns = [
            'check_diversity', 'diversity_analysis', 'measure_diversity',
            'demographic_distribution', 'data_balance'
        ]
        has_diversity_checks = any(
            any(pattern in func for pattern in diversity_patterns)
            for func in function_names
        )

        # Balanced sampling functions
        sampling_patterns = [
            'balanced_sampling', 'stratified_sample', 'oversample', 'undersample',
            'smote', 'balance_dataset', 'rebalance'
        ]
        has_balanced_sampling = any(
            any(pattern in func for pattern in sampling_patterns)
            for func in function_names
        )

        # Data augmentation functions
        augmentation_patterns = [
            'augment', 'data_augmentation', 'synthetic_data', 'generate_samples',
            'augment_dataset'
        ]
        has_augmentation = any(
            any(pattern in func for pattern in augmentation_patterns)
            for func in function_names
        )

        # Scoring logic
        if has_diversity_checks and has_balanced_sampling and has_augmentation:
            return 100
        elif has_balanced_sampling and has_augmentation:
            return 75
        elif has_balanced_sampling or has_diversity_checks:
            return 60
        else:
            return 0

    def _score_transparency_comprehensive(self, parsed_data: Dict[str, Any]) -> int:
        """
        Score comprehensive transparency & disclosure - Evidence-Based

        Uses AST-based detection for transparency practices.
        Transparency helps users understand AI capabilities and limitations.

        Scoring tiers:
        - 100: Model cards + disclosure + logging
        - 75: Model cards + disclosure
        - 60: Disclosure only
        - 0: None detected
        """
        # Transparency is primarily about disclosure and documentation
        function_defs = parsed_data.get('function_defs', [])
        function_names = [f.lower() for f in function_defs]

        # AI disclosure functions
        disclosure_patterns = [
            'ai_disclosure', 'disclose_ai', 'ai_notice', 'show_ai_notice',
            'ai_generated_content', 'synthetic_content_warning'
        ]
        has_disclosure = any(
            any(pattern in func for pattern in disclosure_patterns)
            for func in function_names
        )

        # Model card functions (documentation)
        model_card_patterns = [
            'model_card', 'generate_model_card', 'model_documentation',
            'model_metadata', 'model_info'
        ]
        has_model_cards = any(
            any(pattern in func for pattern in model_card_patterns)
            for func in function_names
        )

        # Transparency logging functions
        logging_patterns = [
            'log_prediction', 'log_inference', 'audit_log', 'transparency_log',
            'track_usage'
        ]
        has_logging = any(
            any(pattern in func for pattern in logging_patterns)
            for func in function_names
        )

        # Scoring logic
        if has_model_cards and has_disclosure and has_logging:
            return 100
        elif has_model_cards and has_disclosure:
            return 75
        elif has_disclosure:
            return 60
        else:
            return 0

    # ============================================================================
    # Legacy Scoring Methods
    # ============================================================================

    def _score_legacy_bias(self, parsed_data: Dict[str, Any]) -> int:
        """
        Score legacy bias (legacy subscore - 2% weight)

        Deprecated: Use comprehensive subscore instead.
        Returns 0 as this is superseded by:
        - bias_testing_comprehensive
        """
        return 0

    def _score_legacy_fairness(self, parsed_data: Dict[str, Any]) -> int:
        """
        Score legacy fairness (legacy subscore - 1% weight)

        Deprecated: Use comprehensive subscore instead.
        Returns 0 as this is superseded by:
        - fairness_metrics_comprehensive
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
