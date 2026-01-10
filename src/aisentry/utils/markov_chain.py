"""
Markov Chain Analyzer

Advanced text generation pattern analysis using Markov chains.
Detects predictability, anomalies, and generation patterns in LLM outputs.
Ported from genai-security JavaScript implementation.
"""

import math
import re
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Dict, List, Set


@dataclass
class MarkovAnalysisResult:
    """Results from Markov chain analysis."""

    predictability: float = 0.0
    entropy: float = 0.0
    perplexity: float = float("inf")
    likelihood: float = 0.0
    surprisal_avg: float = 0.0
    surprisal_max: float = 0.0
    anomalies: List[Dict[str, Any]] = field(default_factory=list)
    recurring_patterns: List[Dict[str, Any]] = field(default_factory=list)
    is_likely_generated: bool = False
    generation_confidence: float = 0.0
    generation_indicators: List[str] = field(default_factory=list)
    risk_score: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "predictability": round(self.predictability, 4),
            "entropy": round(self.entropy, 4),
            "perplexity": round(self.perplexity, 4) if self.perplexity != float("inf") else None,
            "likelihood": round(self.likelihood, 4),
            "surprisal": {
                "average": round(self.surprisal_avg, 4),
                "max": round(self.surprisal_max, 4),
            },
            "anomalies_count": len(self.anomalies),
            "recurring_patterns_count": len(self.recurring_patterns),
            "is_likely_generated": self.is_likely_generated,
            "generation_confidence": round(self.generation_confidence, 4),
            "generation_indicators": self.generation_indicators,
            "risk_score": round(self.risk_score, 2),
        }


class MarkovChainAnalyzer:
    """
    Markov Chain Analyzer for detecting LLM response patterns.

    Uses n-gram analysis to build transition matrices and detect
    anomalies, predictability patterns, and generated text signatures.
    """

    def __init__(
        self,
        order: int = 2,
        max_order: int = 5,
        adaptive_order: bool = True,
        min_sample_size: int = 50,
        smoothing: str = "laplace",
        smoothing_parameter: float = 1.0,
        predictability_threshold: float = 0.7,
        anomaly_threshold: float = 0.05,
        entropy_threshold: float = 2.0,
        use_backoff: bool = True,
    ):
        """
        Initialize Markov Chain Analyzer.

        Args:
            order: N-gram size (2 = bigram, 3 = trigram)
            max_order: Maximum order for variable-order chains
            adaptive_order: Automatically adjust order based on data
            min_sample_size: Minimum tokens for analysis
            smoothing: Smoothing method ('laplace', 'kneser-ney')
            smoothing_parameter: Smoothing parameter (alpha for Laplace)
            predictability_threshold: Threshold for high predictability
            anomaly_threshold: Threshold for anomaly detection
            entropy_threshold: Threshold for low entropy detection
            use_backoff: Use backoff for unseen sequences
        """
        self.order = order
        self.max_order = max_order
        self.adaptive_order = adaptive_order
        self.min_sample_size = min_sample_size
        self.smoothing = smoothing
        self.smoothing_parameter = smoothing_parameter
        self.predictability_threshold = predictability_threshold
        self.anomaly_threshold = anomaly_threshold
        self.entropy_threshold = entropy_threshold
        self.use_backoff = use_backoff

        # Initialize components
        self._reset()

    def _reset(self) -> None:
        """Reset analyzer state."""
        self.transition_matrix: Dict[str, Dict[str, float]] = defaultdict(
            lambda: defaultdict(float)
        )
        self.variable_order_chains: Dict[int, Dict[str, Dict[str, float]]] = {
            i: defaultdict(lambda: defaultdict(float))
            for i in range(1, self.max_order + 1)
        }
        self.vocabulary: Set[str] = set()
        self.corpus: List[str] = []
        self.total_transitions = 0

    def tokenize(self, text: str) -> List[str]:
        """
        Tokenize text into words.

        Args:
            text: Input text

        Returns:
            List of tokens
        """
        # Simple tokenization - lowercase and split on whitespace/punctuation
        text = text.lower()
        text = re.sub(r"[^\w\s]", " ", text)
        tokens = [t for t in text.split() if t]
        return tokens

    def build_chain(self, text: str) -> Dict[str, Any]:
        """
        Build Markov chain from text.

        Args:
            text: Input text to build chain from

        Returns:
            Build statistics
        """
        tokens = self.tokenize(text)

        if len(tokens) < self.min_sample_size:
            pass  # Still proceed but with limited data

        # Add to corpus and vocabulary
        self.corpus.extend(tokens)
        self.vocabulary.update(tokens)

        # Build chains of different orders
        if self.adaptive_order:
            for order in range(1, min(self.max_order + 1, len(tokens))):
                self._build_order_n_chain(tokens, order)
        else:
            self._build_order_n_chain(tokens, self.order)

        # Apply smoothing
        self._apply_smoothing()

        return {
            "states": len(self.transition_matrix),
            "transitions": self.total_transitions,
            "vocabulary_size": len(self.vocabulary),
        }

    def _build_order_n_chain(self, tokens: List[str], order: int) -> None:
        """Build n-order chain."""
        chain = (
            self.transition_matrix
            if order == self.order
            else self.variable_order_chains[order]
        )

        # Count transitions
        counts: Dict[str, Dict[str, int]] = defaultdict(lambda: defaultdict(int))

        for i in range(len(tokens) - order):
            state = " ".join(tokens[i : i + order])
            next_token = tokens[i + order]
            counts[state][next_token] += 1
            self.total_transitions += 1

        # Normalize to probabilities
        for state, transitions in counts.items():
            total = sum(transitions.values())
            for next_token, count in transitions.items():
                chain[state][next_token] = count / total

    def _apply_smoothing(self) -> None:
        """Apply smoothing to transition probabilities."""
        if self.smoothing == "laplace":
            self._apply_laplace_smoothing()
        elif self.smoothing == "kneser-ney":
            self._apply_kneser_ney_smoothing()

    def _apply_laplace_smoothing(self) -> None:
        """Apply Laplace (add-alpha) smoothing."""
        alpha = self.smoothing_parameter
        vocab_size = len(self.vocabulary)

        if vocab_size == 0:
            return

        for state, transitions in self.transition_matrix.items():
            total = sum(transitions.values())
            for token in transitions:
                smoothed_prob = (transitions[token] * total + alpha) / (
                    total + alpha * vocab_size
                )
                transitions[token] = smoothed_prob

    def _apply_kneser_ney_smoothing(self) -> None:
        """Apply simplified Kneser-Ney smoothing."""
        discount = 0.75
        vocab_size = len(self.vocabulary)

        if vocab_size == 0:
            return

        for state, transitions in self.transition_matrix.items():
            total = sum(transitions.values())
            unique_followers = len(transitions)

            for token in transitions:
                discounted_prob = max(transitions[token] - discount / total, 0)
                redistributed_mass = (discount * unique_followers) / (
                    total * vocab_size
                )
                transitions[token] = discounted_prob + redistributed_mass

    def analyze(self, text: str) -> MarkovAnalysisResult:
        """
        Analyze text using Markov chain.

        Args:
            text: Text to analyze

        Returns:
            Analysis results
        """
        tokens = self.tokenize(text)
        result = MarkovAnalysisResult()

        if len(tokens) <= self.order:
            return result

        # Calculate metrics
        result.predictability = self._calculate_predictability(tokens)
        result.entropy = self._calculate_entropy(tokens)
        result.perplexity = self._calculate_perplexity(tokens)
        result.likelihood = self._calculate_likelihood(tokens)

        # Calculate surprisal
        surprisal_data = self._calculate_surprisal(tokens)
        result.surprisal_avg = surprisal_data["average"]
        result.surprisal_max = surprisal_data["max"]
        result.anomalies = surprisal_data["anomalies"]

        # Find patterns
        result.recurring_patterns = self._find_recurring_patterns(tokens)

        # Analyze generation likelihood
        gen_analysis = self._analyze_generation_likelihood(tokens, result)
        result.is_likely_generated = gen_analysis["is_likely_generated"]
        result.generation_confidence = gen_analysis["confidence"]
        result.generation_indicators = gen_analysis["indicators"]

        # Calculate risk score
        result.risk_score = self._calculate_risk_score(result)

        return result

    def _calculate_predictability(self, tokens: List[str]) -> float:
        """Calculate predictability of text."""
        if len(tokens) <= self.order:
            return 0.0

        predictable_transitions = 0
        total_transitions = 0

        for i in range(len(tokens) - self.order):
            state = " ".join(tokens[i : i + self.order])
            actual_next = tokens[i + self.order]

            if state in self.transition_matrix:
                transitions = self.transition_matrix[state]

                # Get most probable next token
                if transitions:
                    predicted_next = max(transitions, key=transitions.get)
                    max_prob = transitions[predicted_next]

                    if (
                        predicted_next == actual_next
                        and max_prob > self.predictability_threshold
                    ):
                        predictable_transitions += 1

                total_transitions += 1

        return predictable_transitions / total_transitions if total_transitions > 0 else 0.0

    def _calculate_entropy(self, tokens: List[str]) -> float:
        """Calculate average entropy of transitions."""
        entropies = []

        for i in range(len(tokens) - self.order):
            state = " ".join(tokens[i : i + self.order])

            if state in self.transition_matrix:
                transitions = self.transition_matrix[state]
                entropy = 0.0

                for prob in transitions.values():
                    if prob > 0:
                        entropy -= prob * math.log2(prob)

                entropies.append(entropy)

        return sum(entropies) / len(entropies) if entropies else 0.0

    def _calculate_perplexity(self, tokens: List[str]) -> float:
        """Calculate perplexity of text."""
        log_probs = []

        for i in range(len(tokens) - self.order):
            state = " ".join(tokens[i : i + self.order])
            next_token = tokens[i + self.order]

            prob = self._get_transition_probability(state, next_token)

            if prob > 0:
                log_probs.append(math.log2(prob))

        if not log_probs:
            return float("inf")

        avg_log_prob = sum(log_probs) / len(log_probs)
        return math.pow(2, -avg_log_prob)

    def _calculate_likelihood(self, tokens: List[str]) -> float:
        """Calculate likelihood of sequence."""
        if len(tokens) <= self.order:
            return 0.0

        log_likelihood = 0.0
        valid_transitions = 0

        for i in range(len(tokens) - self.order):
            state = " ".join(tokens[i : i + self.order])
            next_token = tokens[i + self.order]

            prob = self._get_transition_probability(state, next_token)

            if prob > 0:
                log_likelihood += math.log(prob)
                valid_transitions += 1

        return (
            math.exp(log_likelihood / valid_transitions)
            if valid_transitions > 0
            else 0.0
        )

    def _calculate_surprisal(self, tokens: List[str]) -> Dict[str, Any]:
        """Calculate surprisal metrics."""
        surprisals = []

        for i in range(len(tokens) - self.order):
            state = " ".join(tokens[i : i + self.order])
            next_token = tokens[i + self.order]

            prob = self._get_transition_probability(state, next_token)

            if prob > 0:
                surprisal = -math.log2(prob)
                surprisals.append(
                    {
                        "position": i + self.order,
                        "token": next_token,
                        "surprisal": surprisal,
                        "is_anomaly": surprisal > 10,
                    }
                )

        if not surprisals:
            return {"average": 0.0, "max": 0.0, "anomalies": []}

        avg_surprisal = sum(s["surprisal"] for s in surprisals) / len(surprisals)
        max_surprisal = max(s["surprisal"] for s in surprisals)
        anomalies = [s for s in surprisals if s["is_anomaly"]]

        return {"average": avg_surprisal, "max": max_surprisal, "anomalies": anomalies}

    def _get_transition_probability(self, state: str, next_token: str) -> float:
        """Get transition probability with backoff."""
        # Try exact match
        if state in self.transition_matrix:
            transitions = self.transition_matrix[state]
            if next_token in transitions:
                return transitions[next_token]

        # Use backoff if enabled
        if self.use_backoff:
            prob = self._calculate_backoff_probability(state, next_token)
            if prob > 0:
                return prob

        # Return smoothing probability
        return self._get_smoothing_probability()

    def _calculate_backoff_probability(self, state: str, next_token: str) -> float:
        """Calculate backoff probability for unseen transitions."""
        tokens = state.split()

        # Try progressively shorter contexts
        for order in range(len(tokens) - 1, 0, -1):
            shorter_state = " ".join(tokens[-order:])

            if order in self.variable_order_chains:
                chain = self.variable_order_chains[order]
                if shorter_state in chain:
                    transitions = chain[shorter_state]
                    if next_token in transitions:
                        # Apply backoff weight
                        backoff_weight = pow(0.4, len(tokens) - order)
                        return transitions[next_token] * backoff_weight

        return 0.0

    def _get_smoothing_probability(self) -> float:
        """Get smoothing probability for unseen transitions."""
        alpha = self.smoothing_parameter
        vocab_size = len(self.vocabulary)
        if vocab_size == 0:
            return 0.0
        return alpha / (vocab_size + alpha * vocab_size)

    def _find_recurring_patterns(self, tokens: List[str]) -> List[Dict[str, Any]]:
        """Find recurring patterns in text."""
        patterns = []
        window_size = min(10, len(tokens) // 3)

        for length in range(3, window_size + 1):
            seen: Dict[str, int] = {}

            for i in range(len(tokens) - length + 1):
                pattern = " ".join(tokens[i : i + length])

                if pattern in seen:
                    last_pos = seen[pattern]
                    if i - last_pos > length:  # Non-overlapping
                        patterns.append(
                            {
                                "pattern": pattern,
                                "positions": [last_pos, i],
                                "length": length,
                                "distance": i - last_pos,
                            }
                        )

                seen[pattern] = i

        return patterns

    def _analyze_generation_likelihood(
        self, tokens: List[str], metrics: MarkovAnalysisResult
    ) -> Dict[str, Any]:
        """Analyze likelihood that text is generated."""
        indicators = []
        confidence = 0.0

        # Low entropy indicates generated text
        if metrics.entropy < 2:
            indicators.append("low_entropy")
            confidence += 0.3

        # High predictability indicates generated text
        if metrics.predictability > 0.7:
            indicators.append("high_predictability")
            confidence += 0.3

        # Low perplexity indicates generated text
        if metrics.perplexity < 10:
            indicators.append("low_perplexity")
            confidence += 0.2

        # Regular surprisal patterns
        if metrics.surprisal_avg < 3 and len(metrics.anomalies) == 0:
            indicators.append("regular_surprisal")
            confidence += 0.2

        # Repetitive patterns
        unique_ratio = len(set(tokens)) / len(tokens) if tokens else 0
        if unique_ratio < 0.6:
            indicators.append("repetitive")
            confidence += 0.2

        return {
            "is_likely_generated": confidence > 0.5,
            "confidence": min(confidence, 1.0),
            "indicators": indicators,
        }

    def _calculate_risk_score(self, analysis: MarkovAnalysisResult) -> float:
        """Calculate risk score from analysis."""
        score = 0.0

        # High predictability indicates potential vulnerability
        if analysis.predictability > 0.8:
            score += 30

        # Low entropy indicates generated or manipulated text
        if analysis.entropy < 2:
            score += 25

        # Anomalous sequences indicate potential attack
        if len(analysis.anomalies) > 5:
            score += 20

        # Generated pattern detection
        if analysis.is_likely_generated:
            score += analysis.generation_confidence * 25

        return min(score, 100)

    def get_statistics(self) -> Dict[str, Any]:
        """Get chain statistics."""
        return {
            "total_transitions": self.total_transitions,
            "unique_states": len(self.transition_matrix),
            "vocabulary_size": len(self.vocabulary),
            "corpus_size": len(self.corpus),
            "order": self.order,
        }

    def reset(self) -> None:
        """Reset the analyzer."""
        self._reset()
