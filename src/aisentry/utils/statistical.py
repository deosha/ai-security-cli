"""
Statistical Analysis Utilities

Provides statistical functions for security analysis including
Z-score calculation, anomaly detection, and confidence intervals.
"""

import math
from collections import deque
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple


def calculate_mean(values: List[float]) -> float:
    """Calculate arithmetic mean."""
    if not values:
        return 0.0
    return sum(values) / len(values)


def calculate_std(values: List[float], mean: Optional[float] = None) -> float:
    """Calculate standard deviation."""
    if len(values) < 2:
        return 0.0

    if mean is None:
        mean = calculate_mean(values)

    variance = sum((v - mean) ** 2 for v in values) / len(values)
    return math.sqrt(variance)


def calculate_z_score(value: float, mean: float, std: float) -> float:
    """
    Calculate Z-score for a value.

    Args:
        value: Value to calculate Z-score for
        mean: Population mean
        std: Population standard deviation

    Returns:
        Z-score (number of standard deviations from mean)
    """
    if std == 0:
        return 0.0
    return (value - mean) / std


def calculate_percentile(values: List[float], percentile: float) -> float:
    """
    Calculate percentile value.

    Args:
        values: List of values
        percentile: Percentile to calculate (0-100)

    Returns:
        Value at given percentile
    """
    if not values:
        return 0.0

    sorted_values = sorted(values)
    index = (percentile / 100) * (len(sorted_values) - 1)
    lower = int(index)
    upper = min(lower + 1, len(sorted_values) - 1)
    weight = index - lower

    return sorted_values[lower] * (1 - weight) + sorted_values[upper] * weight


def calculate_iqr(values: List[float]) -> Tuple[float, float, float]:
    """
    Calculate interquartile range.

    Args:
        values: List of values

    Returns:
        Tuple of (Q1, median, Q3)
    """
    q1 = calculate_percentile(values, 25)
    median = calculate_percentile(values, 50)
    q3 = calculate_percentile(values, 75)
    return q1, median, q3


def detect_outliers_zscore(
    values: List[float], threshold: float = 3.0
) -> List[Tuple[int, float, float]]:
    """
    Detect outliers using Z-score method.

    Args:
        values: List of values
        threshold: Z-score threshold for outlier detection

    Returns:
        List of (index, value, z_score) for outliers
    """
    if len(values) < 3:
        return []

    mean = calculate_mean(values)
    std = calculate_std(values, mean)

    if std == 0:
        return []

    outliers = []
    for i, value in enumerate(values):
        z = calculate_z_score(value, mean, std)
        if abs(z) > threshold:
            outliers.append((i, value, z))

    return outliers


def detect_outliers_iqr(
    values: List[float], k: float = 1.5
) -> List[Tuple[int, float]]:
    """
    Detect outliers using IQR method.

    Args:
        values: List of values
        k: IQR multiplier (1.5 = outlier, 3.0 = extreme outlier)

    Returns:
        List of (index, value) for outliers
    """
    if len(values) < 4:
        return []

    q1, _, q3 = calculate_iqr(values)
    iqr = q3 - q1
    lower_bound = q1 - k * iqr
    upper_bound = q3 + k * iqr

    outliers = []
    for i, value in enumerate(values):
        if value < lower_bound or value > upper_bound:
            outliers.append((i, value))

    return outliers


def calculate_confidence_interval(
    values: List[float], confidence: float = 0.95
) -> Tuple[float, float]:
    """
    Calculate confidence interval.

    Args:
        values: List of values
        confidence: Confidence level (0-1)

    Returns:
        Tuple of (lower_bound, upper_bound)
    """
    if len(values) < 2:
        mean = calculate_mean(values) if values else 0.0
        return mean, mean

    mean = calculate_mean(values)
    std = calculate_std(values, mean)
    n = len(values)

    # Z-score for confidence level (approximate)
    z_scores = {0.90: 1.645, 0.95: 1.96, 0.99: 2.576}
    z = z_scores.get(confidence, 1.96)

    margin = z * (std / math.sqrt(n))
    return mean - margin, mean + margin


def calculate_cosine_similarity(vec1: List[float], vec2: List[float]) -> float:
    """
    Calculate cosine similarity between two vectors.

    Args:
        vec1: First vector
        vec2: Second vector

    Returns:
        Cosine similarity (-1 to 1)
    """
    if len(vec1) != len(vec2) or not vec1:
        return 0.0

    dot_product = sum(a * b for a, b in zip(vec1, vec2))
    norm1 = math.sqrt(sum(a * a for a in vec1))
    norm2 = math.sqrt(sum(b * b for b in vec2))

    if norm1 == 0 or norm2 == 0:
        return 0.0

    return dot_product / (norm1 * norm2)


def calculate_cohens_d(
    group1: List[float], group2: List[float]
) -> float:
    """
    Calculate Cohen's d effect size.

    Measures the standardized difference between two means.
    Small: 0.2, Medium: 0.5, Large: 0.8

    Args:
        group1: First group values
        group2: Second group values

    Returns:
        Cohen's d effect size
    """
    if not group1 or not group2:
        return 0.0

    mean1 = calculate_mean(group1)
    mean2 = calculate_mean(group2)

    std1 = calculate_std(group1, mean1)
    std2 = calculate_std(group2, mean2)

    # Pooled standard deviation
    n1, n2 = len(group1), len(group2)
    pooled_std = math.sqrt(
        ((n1 - 1) * std1**2 + (n2 - 1) * std2**2) / (n1 + n2 - 2)
    )

    if pooled_std == 0:
        return 0.0

    return (mean1 - mean2) / pooled_std


@dataclass
class CircularBuffer:
    """
    Memory-efficient circular buffer for streaming statistics.

    Maintains a fixed-size window of recent values.
    """

    max_size: int = 100
    values: deque = field(default_factory=deque)

    def __post_init__(self):
        self.values = deque(maxlen=self.max_size)

    def add(self, value: float) -> None:
        """Add a value to the buffer."""
        self.values.append(value)

    def get_mean(self) -> float:
        """Get current mean."""
        return calculate_mean(list(self.values))

    def get_std(self) -> float:
        """Get current standard deviation."""
        return calculate_std(list(self.values))

    def get_values(self) -> List[float]:
        """Get all values in buffer."""
        return list(self.values)

    def is_full(self) -> bool:
        """Check if buffer is at capacity."""
        return len(self.values) >= self.max_size

    def clear(self) -> None:
        """Clear the buffer."""
        self.values.clear()


@dataclass
class EWMA:
    """
    Exponentially Weighted Moving Average.

    Gives more weight to recent observations.
    Used for detecting behavioral drift in LLM responses.
    """

    alpha: float = 0.3  # Smoothing factor (0-1)
    value: float = 0.0
    initialized: bool = False

    def update(self, observation: float) -> float:
        """
        Update EWMA with new observation.

        Args:
            observation: New observation value

        Returns:
            Updated EWMA value
        """
        if not self.initialized:
            self.value = observation
            self.initialized = True
        else:
            self.value = self.alpha * observation + (1 - self.alpha) * self.value

        return self.value

    def get_value(self) -> float:
        """Get current EWMA value."""
        return self.value

    def reset(self) -> None:
        """Reset EWMA."""
        self.value = 0.0
        self.initialized = False


class AnomalyDetector:
    """
    Statistical anomaly detector for LLM response analysis.

    Combines multiple methods (Z-score, EWMA, percentile) for
    robust anomaly detection.
    """

    def __init__(
        self,
        window_size: int = 100,
        z_threshold: float = 3.0,
        ewma_alpha: float = 0.3,
        percentile_threshold: float = 95,
    ):
        self.buffer = CircularBuffer(max_size=window_size)
        self.ewma = EWMA(alpha=ewma_alpha)
        self.z_threshold = z_threshold
        self.percentile_threshold = percentile_threshold

    def add_observation(self, value: float) -> Dict[str, Any]:
        """
        Add observation and check for anomaly.

        Args:
            value: Observation value

        Returns:
            Dict with anomaly detection results
        """
        self.buffer.add(value)
        ewma_value = self.ewma.update(value)

        result = {
            "value": value,
            "ewma": ewma_value,
            "is_anomaly": False,
            "anomaly_type": None,
            "z_score": 0.0,
            "percentile": 0.0,
        }

        if not self.buffer.is_full():
            return result

        values = self.buffer.get_values()
        mean = self.buffer.get_mean()
        std = self.buffer.get_std()

        # Z-score check
        if std > 0:
            z_score = calculate_z_score(value, mean, std)
            result["z_score"] = z_score

            if abs(z_score) > self.z_threshold:
                result["is_anomaly"] = True
                result["anomaly_type"] = "z_score"

        # Percentile check
        sorted_values = sorted(values)
        rank = sum(1 for v in sorted_values if v <= value)
        percentile = (rank / len(sorted_values)) * 100
        result["percentile"] = percentile

        if percentile > self.percentile_threshold or percentile < (100 - self.percentile_threshold):
            result["is_anomaly"] = True
            result["anomaly_type"] = result.get("anomaly_type") or "percentile"

        return result

    def get_baseline_stats(self) -> Dict[str, float]:
        """Get current baseline statistics."""
        values = self.buffer.get_values()
        return {
            "mean": self.buffer.get_mean(),
            "std": self.buffer.get_std(),
            "ewma": self.ewma.get_value(),
            "samples": len(values),
            "min": min(values) if values else 0.0,
            "max": max(values) if values else 0.0,
        }

    def reset(self) -> None:
        """Reset the detector."""
        self.buffer.clear()
        self.ewma.reset()
