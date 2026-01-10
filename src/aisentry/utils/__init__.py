"""Utility modules for aisentry."""

from .ast_utils import (
    LLM_API_METHODS,
    LLM_SINK_KEYWORDS,
    extract_dict_content_names,
    find_assignments_in_scope,
    find_call_at_line,
    get_call_name,
    get_full_call_name,
    is_llm_api_call,
    is_llm_sink_keyword,
    is_passthrough_call,
    is_prompt_template_usage,
    is_sanitization_call,
    names_in_expr,
    names_in_fstring,
    resolve_single_hop,
)
from .entropy import (
    EntropyBaseline,
    calculate_conditional_entropy,
    calculate_perplexity,
    calculate_text_entropy,
    calculate_token_entropy,
    is_high_entropy_string,
)
from .markov_chain import MarkovAnalysisResult, MarkovChainAnalyzer
from .scoring import (
    RISK_LEVELS,
    calculate_confidence_weighted_score,
    calculate_overall_score,
    get_risk_level,
    get_severity_counts,
)
from .statistical import (
    EWMA,
    AnomalyDetector,
    CircularBuffer,
    calculate_mean,
    calculate_percentile,
    calculate_std,
    calculate_z_score,
    detect_outliers_zscore,
)

__all__ = [
    # Scoring
    "calculate_overall_score",
    "get_risk_level",
    "get_severity_counts",
    "calculate_confidence_weighted_score",
    "RISK_LEVELS",
    # Markov Chain
    "MarkovChainAnalyzer",
    "MarkovAnalysisResult",
    # Entropy
    "calculate_text_entropy",
    "calculate_token_entropy",
    "calculate_conditional_entropy",
    "calculate_perplexity",
    "is_high_entropy_string",
    "EntropyBaseline",
    # Statistical
    "calculate_mean",
    "calculate_std",
    "calculate_z_score",
    "calculate_percentile",
    "detect_outliers_zscore",
    "CircularBuffer",
    "EWMA",
    "AnomalyDetector",
    # AST Utilities
    "names_in_expr",
    "names_in_fstring",
    "is_sanitization_call",
    "is_prompt_template_usage",
    "get_call_name",
    "get_full_call_name",
    "find_assignments_in_scope",
    "resolve_single_hop",
    "extract_dict_content_names",
    "is_passthrough_call",
    "find_call_at_line",
    "is_llm_sink_keyword",
    "is_llm_api_call",
    "LLM_SINK_KEYWORDS",
    "LLM_API_METHODS",
]
