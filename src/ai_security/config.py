"""
Configuration management for AI Security CLI

Supports configuration from multiple sources with precedence:
CLI flags > Environment variables > .ai-security.yaml > Built-in defaults

Environment variables:
- AISEC_MODE: recall|strict
- AISEC_DEDUP: exact|off
- AISEC_EXCLUDE_DIRS: comma-separated paths
- AISEC_THRESHOLD_LLM01 through AISEC_THRESHOLD_LLM10: per-category thresholds
"""

import os
import yaml
from pathlib import Path
from typing import Dict, Any, Optional, List
from dataclasses import dataclass, field
import logging

logger = logging.getLogger(__name__)


# Built-in defaults (recall-friendly)
DEFAULT_CONFIG = {
    'mode': 'recall',
    'dedup': 'exact',
    'exclude_dirs': [],
    'thresholds': {
        'LLM01': 0.70,
        'LLM02': 0.70,
        'LLM03': 0.70,
        'LLM04': 0.70,
        'LLM05': 0.70,
        'LLM06': 0.70,
        'LLM07': 0.70,
        'LLM08': 0.70,
        'LLM09': 0.70,
        'LLM10': 0.70,
    },
    'global_threshold': 0.70,
}

# Strict mode adjustments (+0.05 to thresholds)
STRICT_MODE_THRESHOLD_BUMP = 0.05


@dataclass
class ScanConfig:
    """Configuration for scanning operations."""

    mode: str = 'recall'  # 'recall' or 'strict'
    dedup: str = 'exact'  # 'exact' or 'off'
    exclude_dirs: List[str] = field(default_factory=list)
    thresholds: Dict[str, float] = field(default_factory=dict)
    global_threshold: float = 0.70
    exclude_tests: bool = False  # If True, skip test files entirely
    demote_tests: bool = True  # If True, reduce confidence for test file findings
    test_confidence_penalty: float = 0.25  # Confidence reduction for test files

    def __post_init__(self):
        # Apply defaults for any missing thresholds
        for cat in ['LLM01', 'LLM02', 'LLM03', 'LLM04', 'LLM05',
                    'LLM06', 'LLM07', 'LLM08', 'LLM09', 'LLM10']:
            if cat not in self.thresholds:
                self.thresholds[cat] = self.global_threshold

        # Apply strict mode bump if needed
        if self.mode == 'strict':
            for cat in self.thresholds:
                self.thresholds[cat] = min(1.0, self.thresholds[cat] + STRICT_MODE_THRESHOLD_BUMP)

    def get_threshold(self, category: str) -> float:
        """Get threshold for a specific category."""
        # Normalize category (e.g., "LLM01: Prompt Injection" -> "LLM01")
        cat_id = category.split(':')[0].strip().upper()
        return self.thresholds.get(cat_id, self.global_threshold)


def find_config_file(start_path: Optional[Path] = None) -> Optional[Path]:
    """
    Find .ai-security.yaml in current directory or parents.

    Args:
        start_path: Starting directory (defaults to cwd)

    Returns:
        Path to config file, or None if not found
    """
    if start_path is None:
        start_path = Path.cwd()

    current = start_path.resolve()

    # Search up to root
    while current != current.parent:
        config_file = current / '.ai-security.yaml'
        if config_file.exists():
            return config_file

        # Also check for .ai-security.yml
        config_file = current / '.ai-security.yml'
        if config_file.exists():
            return config_file

        current = current.parent

    return None


def load_yaml_config(config_path: Path) -> Dict[str, Any]:
    """
    Load configuration from YAML file.

    Args:
        config_path: Path to .ai-security.yaml

    Returns:
        Configuration dictionary
    """
    try:
        with open(config_path, 'r') as f:
            config = yaml.safe_load(f) or {}
        logger.debug(f"Loaded config from {config_path}")
        return config
    except yaml.YAMLError as e:
        logger.warning(f"Error parsing {config_path}: {e}")
        return {}
    except IOError as e:
        logger.warning(f"Error reading {config_path}: {e}")
        return {}


def load_env_config() -> Dict[str, Any]:
    """
    Load configuration from environment variables.

    Returns:
        Configuration dictionary from env vars
    """
    config: Dict[str, Any] = {}

    # Mode
    if mode := os.environ.get('AISEC_MODE'):
        if mode.lower() in ('recall', 'strict'):
            config['mode'] = mode.lower()

    # Dedup
    if dedup := os.environ.get('AISEC_DEDUP'):
        if dedup.lower() in ('exact', 'off'):
            config['dedup'] = dedup.lower()

    # Exclude dirs
    if exclude_dirs := os.environ.get('AISEC_EXCLUDE_DIRS'):
        config['exclude_dirs'] = [d.strip() for d in exclude_dirs.split(',') if d.strip()]

    # Per-category thresholds
    thresholds = {}
    for i in range(1, 11):
        cat = f'LLM{i:02d}'
        env_var = f'AISEC_THRESHOLD_{cat}'
        if threshold := os.environ.get(env_var):
            try:
                thresholds[cat] = float(threshold)
            except ValueError:
                logger.warning(f"Invalid threshold in {env_var}: {threshold}")

    if thresholds:
        config['thresholds'] = thresholds

    # Global threshold
    if global_thresh := os.environ.get('AISEC_THRESHOLD'):
        try:
            config['global_threshold'] = float(global_thresh)
        except ValueError:
            logger.warning(f"Invalid global threshold: {global_thresh}")

    return config


def merge_configs(*configs: Dict[str, Any]) -> Dict[str, Any]:
    """
    Merge multiple config dicts with later ones taking precedence.

    Special handling for 'thresholds' dict (merge, don't replace).

    Args:
        *configs: Configuration dictionaries in order of increasing precedence

    Returns:
        Merged configuration
    """
    result = {}

    for config in configs:
        if not config:
            continue

        for key, value in config.items():
            if key == 'thresholds' and key in result and isinstance(value, dict):
                # Merge thresholds dicts
                result['thresholds'] = {**result.get('thresholds', {}), **value}
            elif value is not None:
                result[key] = value

    return result


def load_config(
    cli_options: Optional[Dict[str, Any]] = None,
    config_path: Optional[Path] = None,
    scan_path: Optional[Path] = None
) -> ScanConfig:
    """
    Load configuration with full precedence chain.

    Precedence: CLI flags > env vars > .ai-security.yaml > defaults

    Args:
        cli_options: Options from CLI flags
        config_path: Explicit path to config file (overrides auto-discovery)
        scan_path: Path being scanned (used for config file discovery)

    Returns:
        ScanConfig with merged settings
    """
    # Start with defaults
    config = dict(DEFAULT_CONFIG)

    # Load from YAML file (auto-discover or explicit)
    if config_path:
        yaml_config = load_yaml_config(config_path)
    else:
        found_config = find_config_file(scan_path)
        yaml_config = load_yaml_config(found_config) if found_config else {}

    # Load from environment
    env_config = load_env_config()

    # Merge with precedence: defaults < yaml < env < cli
    merged = merge_configs(
        config,
        yaml_config,
        env_config,
        cli_options or {}
    )

    # Create ScanConfig from merged dict
    return ScanConfig(
        mode=merged.get('mode', 'recall'),
        dedup=merged.get('dedup', 'exact'),
        exclude_dirs=merged.get('exclude_dirs', []),
        thresholds=merged.get('thresholds', {}),
        global_threshold=merged.get('global_threshold', 0.70),
        exclude_tests=merged.get('exclude_tests', False),
        demote_tests=merged.get('demote_tests', True),
        test_confidence_penalty=merged.get('test_confidence_penalty', 0.25),
    )
