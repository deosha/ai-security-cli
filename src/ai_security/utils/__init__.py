"""Utility modules for AI Security CLI"""

from .scoring import (
    calculate_overall_score,
    get_risk_level,
    get_severity_counts,
    calculate_confidence_weighted_score,
    RISK_LEVELS,
)
from .markov_chain import MarkovChainAnalyzer, MarkovAnalysisResult
from .entropy import (
    calculate_text_entropy,
    calculate_token_entropy,
    calculate_conditional_entropy,
    calculate_perplexity,
    is_high_entropy_string,
    EntropyBaseline,
)
from .statistical import (
    calculate_mean,
    calculate_std,
    calculate_z_score,
    calculate_percentile,
    detect_outliers_zscore,
    CircularBuffer,
    EWMA,
    AnomalyDetector,
)
from .ast_utils import (
    names_in_expr,
    names_in_fstring,
    is_sanitization_call,
    is_prompt_template_usage,
    get_call_name,
    get_full_call_name,
    find_assignments_in_scope,
    resolve_single_hop,
    extract_dict_content_names,
    is_passthrough_call,
    find_call_at_line,
    is_llm_sink_keyword,
    is_llm_api_call,
    LLM_SINK_KEYWORDS,
    LLM_API_METHODS,
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
