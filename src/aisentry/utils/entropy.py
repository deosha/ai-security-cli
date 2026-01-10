"""
Entropy and Information Theory Utilities

Provides functions for calculating entropy, information gain,
and other information-theoretic measures for security analysis.
"""

import math
from collections import Counter
from typing import Dict, List


def calculate_text_entropy(text: str) -> float:
    """
    Calculate Shannon entropy of text.

    Higher entropy indicates more randomness/unpredictability.
    Normal text typically has entropy around 4.0-4.5 bits.
    API keys/secrets often have higher entropy (5.0+).

    Args:
        text: Input text

    Returns:
        Entropy in bits (0-8 range for ASCII)
    """
    if not text:
        return 0.0

    # Count character frequencies
    freq = Counter(text)
    length = len(text)

    # Calculate entropy
    entropy = 0.0
    for count in freq.values():
        p = count / length
        entropy -= p * math.log2(p)

    return entropy


def calculate_token_entropy(tokens: List[str]) -> float:
    """
    Calculate entropy of token sequence.

    Args:
        tokens: List of tokens

    Returns:
        Entropy in bits
    """
    if not tokens:
        return 0.0

    freq = Counter(tokens)
    length = len(tokens)

    entropy = 0.0
    for count in freq.values():
        p = count / length
        entropy -= p * math.log2(p)

    return entropy


def calculate_conditional_entropy(
    sequence: List[str], context_length: int = 1
) -> float:
    """
    Calculate conditional entropy H(X|X_{-n}).

    Measures how unpredictable the next token is given the context.
    Lower values indicate more predictable sequences.

    Args:
        sequence: Token sequence
        context_length: Number of previous tokens to consider

    Returns:
        Conditional entropy in bits
    """
    if len(sequence) <= context_length:
        return 0.0

    # Count context-token pairs
    context_counts: Dict[str, Counter] = {}
    total_contexts: Counter = Counter()

    for i in range(context_length, len(sequence)):
        context = tuple(sequence[i - context_length : i])
        token = sequence[i]

        context_key = " ".join(context)
        if context_key not in context_counts:
            context_counts[context_key] = Counter()

        context_counts[context_key][token] += 1
        total_contexts[context_key] += 1

    # Calculate conditional entropy
    total = sum(total_contexts.values())
    conditional_entropy = 0.0

    for context, token_counts in context_counts.items():
        context_prob = total_contexts[context] / total
        context_total = sum(token_counts.values())

        context_entropy = 0.0
        for count in token_counts.values():
            p = count / context_total
            if p > 0:
                context_entropy -= p * math.log2(p)

        conditional_entropy += context_prob * context_entropy

    return conditional_entropy


def calculate_perplexity(log_probs: List[float]) -> float:
    """
    Calculate perplexity from log probabilities.

    Lower perplexity indicates text is more "expected" by the model.
    Human text typically has perplexity 20-100.
    Very low perplexity (<10) may indicate generated text.

    Args:
        log_probs: List of log probabilities (base 2)

    Returns:
        Perplexity value
    """
    if not log_probs:
        return float("inf")

    avg_log_prob = sum(log_probs) / len(log_probs)
    return math.pow(2, -avg_log_prob)


def calculate_cross_entropy(
    p_dist: Dict[str, float], q_dist: Dict[str, float]
) -> float:
    """
    Calculate cross-entropy H(P, Q).

    Measures how well distribution Q predicts samples from P.
    Used for comparing model predictions to actual distributions.

    Args:
        p_dist: True probability distribution
        q_dist: Model probability distribution

    Returns:
        Cross-entropy value
    """
    cross_entropy = 0.0

    for token, p in p_dist.items():
        q = q_dist.get(token, 1e-10)  # Small value to avoid log(0)
        if p > 0:
            cross_entropy -= p * math.log2(q)

    return cross_entropy


def calculate_kl_divergence(
    p_dist: Dict[str, float], q_dist: Dict[str, float]
) -> float:
    """
    Calculate Kullback-Leibler divergence D_KL(P || Q).

    Measures how different distribution Q is from P.
    Higher values indicate greater difference.

    Args:
        p_dist: True probability distribution
        q_dist: Model probability distribution

    Returns:
        KL divergence value
    """
    kl_div = 0.0

    for token, p in p_dist.items():
        q = q_dist.get(token, 1e-10)
        if p > 0:
            kl_div += p * math.log2(p / q)

    return kl_div


def is_high_entropy_string(text: str, threshold: float = 4.5) -> bool:
    """
    Check if string has suspiciously high entropy.

    High entropy strings may be API keys, secrets, or encrypted data.

    Args:
        text: Input text
        threshold: Entropy threshold (default 4.5)

    Returns:
        True if entropy exceeds threshold
    """
    return calculate_text_entropy(text) > threshold


def estimate_information_gain(
    baseline_entropy: float, test_entropy: float
) -> float:
    """
    Estimate information gain from entropy change.

    Positive values indicate the test sample is more predictable.
    Negative values indicate more randomness/surprisal.

    Args:
        baseline_entropy: Entropy of baseline/reference
        test_entropy: Entropy of test sample

    Returns:
        Information gain (positive = more predictable)
    """
    return baseline_entropy - test_entropy


def calculate_normalized_entropy(text: str) -> float:
    """
    Calculate entropy normalized to 0-1 range.

    Args:
        text: Input text

    Returns:
        Normalized entropy (0 = deterministic, 1 = maximum randomness)
    """
    if not text:
        return 0.0

    entropy = calculate_text_entropy(text)
    unique_chars = len(set(text))

    if unique_chars <= 1:
        return 0.0

    max_entropy = math.log2(unique_chars)
    return entropy / max_entropy if max_entropy > 0 else 0.0


class EntropyBaseline:
    """
    Maintains entropy baseline statistics for anomaly detection.

    Tracks mean and standard deviation of entropy values
    to detect anomalous responses.
    """

    def __init__(self):
        self.values: List[float] = []
        self.mean: float = 0.0
        self.std: float = 0.0

    def add_sample(self, text: str) -> None:
        """Add a sample to the baseline."""
        entropy = calculate_text_entropy(text)
        self.values.append(entropy)
        self._update_stats()

    def _update_stats(self) -> None:
        """Update mean and std."""
        if not self.values:
            return

        self.mean = sum(self.values) / len(self.values)

        if len(self.values) > 1:
            variance = sum((v - self.mean) ** 2 for v in self.values) / len(self.values)
            self.std = math.sqrt(variance)

    def is_anomaly(self, text: str, z_threshold: float = 2.0) -> bool:
        """
        Check if text entropy is anomalous compared to baseline.

        Args:
            text: Text to check
            z_threshold: Z-score threshold for anomaly

        Returns:
            True if anomalous
        """
        if len(self.values) < 5 or self.std == 0:
            return False

        entropy = calculate_text_entropy(text)
        z_score = abs(entropy - self.mean) / self.std
        return z_score > z_threshold

    def get_z_score(self, text: str) -> float:
        """Get Z-score for text entropy."""
        if len(self.values) < 2 or self.std == 0:
            return 0.0

        entropy = calculate_text_entropy(text)
        return (entropy - self.mean) / self.std

    def get_stats(self) -> Dict[str, float]:
        """Get baseline statistics."""
        return {
            "mean": self.mean,
            "std": self.std,
            "samples": len(self.values),
        }
