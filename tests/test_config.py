"""
Unit tests for aisentry configuration module.
"""

import os
import tempfile
from pathlib import Path


from aisentry.config import (
    ScanConfig,
    find_config_file,
    load_config,
    load_env_config,
    load_yaml_config,
    merge_configs,
)


class TestScanConfig:
    """Test ScanConfig dataclass."""

    def test_default_values(self):
        """Test default configuration values."""
        config = ScanConfig()
        assert config.mode == 'recall'
        assert config.dedup == 'exact'
        assert config.exclude_dirs == []
        assert config.global_threshold == 0.70
        assert config.exclude_tests is False
        assert config.demote_tests is True
        assert config.test_confidence_penalty == 0.25

    def test_default_thresholds_applied(self):
        """Test that default thresholds are applied for all categories."""
        config = ScanConfig()
        for i in range(1, 11):
            cat = f'LLM{i:02d}'
            assert cat in config.thresholds
            assert config.thresholds[cat] == 0.70

    def test_strict_mode_threshold_bump(self):
        """Test that strict mode increases thresholds by 0.05."""
        config = ScanConfig(mode='strict')
        for i in range(1, 11):
            cat = f'LLM{i:02d}'
            assert config.thresholds[cat] == 0.75  # 0.70 + 0.05

    def test_strict_mode_threshold_cap(self):
        """Test that thresholds are capped at 1.0 in strict mode."""
        config = ScanConfig(mode='strict', thresholds={'LLM01': 0.98})
        assert config.thresholds['LLM01'] == 1.0  # 0.98 + 0.05 = 1.03, capped to 1.0

    def test_custom_thresholds_preserved(self):
        """Test that custom thresholds are preserved."""
        config = ScanConfig(thresholds={'LLM01': 0.5, 'LLM02': 0.9})
        assert config.thresholds['LLM01'] == 0.5
        assert config.thresholds['LLM02'] == 0.9
        # Others should get default
        assert config.thresholds['LLM03'] == 0.70

    def test_get_threshold_simple(self):
        """Test get_threshold with simple category ID."""
        config = ScanConfig(thresholds={'LLM01': 0.8})
        assert config.get_threshold('LLM01') == 0.8

    def test_get_threshold_with_name(self):
        """Test get_threshold with full category name."""
        config = ScanConfig(thresholds={'LLM01': 0.8})
        assert config.get_threshold('LLM01: Prompt Injection') == 0.8

    def test_get_threshold_case_insensitive(self):
        """Test get_threshold is case insensitive."""
        config = ScanConfig(thresholds={'LLM01': 0.8})
        assert config.get_threshold('llm01') == 0.8

    def test_get_threshold_fallback(self):
        """Test get_threshold returns global threshold for unknown category."""
        config = ScanConfig(global_threshold=0.6)
        assert config.get_threshold('LLM99') == 0.6


class TestFindConfigFile:
    """Test find_config_file function."""

    def test_find_aisentry_yaml(self):
        """Test finding .aisentry.yaml in directory."""
        with tempfile.TemporaryDirectory() as tmpdir:
            config_file = Path(tmpdir) / '.aisentry.yaml'
            config_file.write_text('mode: strict')

            found = find_config_file(Path(tmpdir))
            assert found.resolve() == config_file.resolve()

    def test_find_aisentry_yml(self):
        """Test finding .aisentry.yml in directory."""
        with tempfile.TemporaryDirectory() as tmpdir:
            config_file = Path(tmpdir) / '.aisentry.yml'
            config_file.write_text('mode: strict')

            found = find_config_file(Path(tmpdir))
            assert found.resolve() == config_file.resolve()

    def test_find_legacy_config(self):
        """Test finding legacy .ai-security.yaml."""
        with tempfile.TemporaryDirectory() as tmpdir:
            config_file = Path(tmpdir) / '.ai-security.yaml'
            config_file.write_text('mode: strict')

            found = find_config_file(Path(tmpdir))
            assert found.resolve() == config_file.resolve()

    def test_prefer_new_over_legacy(self):
        """Test that .aisentry.yaml is preferred over legacy config."""
        with tempfile.TemporaryDirectory() as tmpdir:
            new_config = Path(tmpdir) / '.aisentry.yaml'
            new_config.write_text('mode: recall')
            legacy_config = Path(tmpdir) / '.ai-security.yaml'
            legacy_config.write_text('mode: strict')

            found = find_config_file(Path(tmpdir))
            assert found.resolve() == new_config.resolve()

    def test_find_in_parent(self):
        """Test finding config in parent directory."""
        with tempfile.TemporaryDirectory() as tmpdir:
            config_file = Path(tmpdir) / '.aisentry.yaml'
            config_file.write_text('mode: strict')

            subdir = Path(tmpdir) / 'subdir'
            subdir.mkdir()

            found = find_config_file(subdir)
            assert found.resolve() == config_file.resolve()

    def test_not_found(self):
        """Test returning None when no config file found."""
        with tempfile.TemporaryDirectory() as tmpdir:
            found = find_config_file(Path(tmpdir))
            assert found is None


class TestLoadYamlConfig:
    """Test load_yaml_config function."""

    def test_load_valid_yaml(self):
        """Test loading valid YAML config."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            f.write('mode: strict\ndedup: "off"\n')
            f.flush()

            config = load_yaml_config(Path(f.name))
            assert config['mode'] == 'strict'
            assert config['dedup'] == 'off'

            os.unlink(f.name)

    def test_load_yaml_with_thresholds(self):
        """Test loading YAML with thresholds."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            f.write('thresholds:\n  LLM01: 0.8\n  LLM02: 0.9\n')
            f.flush()

            config = load_yaml_config(Path(f.name))
            assert config['thresholds']['LLM01'] == 0.8
            assert config['thresholds']['LLM02'] == 0.9

            os.unlink(f.name)

    def test_load_empty_yaml(self):
        """Test loading empty YAML file."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            f.write('')
            f.flush()

            config = load_yaml_config(Path(f.name))
            assert config == {}

            os.unlink(f.name)

    def test_load_invalid_yaml(self):
        """Test loading invalid YAML returns empty dict."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            f.write('invalid: yaml: content: [')
            f.flush()

            config = load_yaml_config(Path(f.name))
            assert config == {}

            os.unlink(f.name)

    def test_load_nonexistent_file(self):
        """Test loading nonexistent file returns empty dict."""
        config = load_yaml_config(Path('/nonexistent/file.yaml'))
        assert config == {}


class TestLoadEnvConfig:
    """Test load_env_config function."""

    def test_load_mode_from_env(self):
        """Test loading mode from environment."""
        os.environ['AISEC_MODE'] = 'strict'
        try:
            config = load_env_config()
            assert config['mode'] == 'strict'
        finally:
            del os.environ['AISEC_MODE']

    def test_load_dedup_from_env(self):
        """Test loading dedup from environment."""
        os.environ['AISEC_DEDUP'] = 'off'
        try:
            config = load_env_config()
            assert config['dedup'] == 'off'
        finally:
            del os.environ['AISEC_DEDUP']

    def test_load_exclude_dirs_from_env(self):
        """Test loading exclude_dirs from environment."""
        os.environ['AISEC_EXCLUDE_DIRS'] = 'node_modules,venv,.git'
        try:
            config = load_env_config()
            assert config['exclude_dirs'] == ['node_modules', 'venv', '.git']
        finally:
            del os.environ['AISEC_EXCLUDE_DIRS']

    def test_load_threshold_from_env(self):
        """Test loading per-category threshold from environment."""
        os.environ['AISEC_THRESHOLD_LLM01'] = '0.85'
        try:
            config = load_env_config()
            assert config['thresholds']['LLM01'] == 0.85
        finally:
            del os.environ['AISEC_THRESHOLD_LLM01']

    def test_load_global_threshold_from_env(self):
        """Test loading global threshold from environment."""
        os.environ['AISEC_THRESHOLD'] = '0.6'
        try:
            config = load_env_config()
            assert config['global_threshold'] == 0.6
        finally:
            del os.environ['AISEC_THRESHOLD']

    def test_invalid_mode_ignored(self):
        """Test that invalid mode is ignored."""
        os.environ['AISEC_MODE'] = 'invalid'
        try:
            config = load_env_config()
            assert 'mode' not in config
        finally:
            del os.environ['AISEC_MODE']

    def test_invalid_threshold_ignored(self):
        """Test that invalid threshold is ignored."""
        os.environ['AISEC_THRESHOLD_LLM01'] = 'not_a_number'
        try:
            config = load_env_config()
            assert 'thresholds' not in config or 'LLM01' not in config.get('thresholds', {})
        finally:
            del os.environ['AISEC_THRESHOLD_LLM01']

    def test_empty_env(self):
        """Test loading with no env vars set."""
        # Clear any test env vars
        for key in list(os.environ.keys()):
            if key.startswith('AISEC_'):
                del os.environ[key]

        config = load_env_config()
        assert config == {}


class TestMergeConfigs:
    """Test merge_configs function."""

    def test_merge_empty_configs(self):
        """Test merging empty configs."""
        result = merge_configs({}, {}, {})
        assert result == {}

    def test_merge_single_config(self):
        """Test merging single config."""
        result = merge_configs({'mode': 'strict'})
        assert result == {'mode': 'strict'}

    def test_later_takes_precedence(self):
        """Test that later configs take precedence."""
        result = merge_configs(
            {'mode': 'recall'},
            {'mode': 'strict'}
        )
        assert result['mode'] == 'strict'

    def test_merge_thresholds(self):
        """Test that thresholds are merged, not replaced."""
        result = merge_configs(
            {'thresholds': {'LLM01': 0.7, 'LLM02': 0.7}},
            {'thresholds': {'LLM01': 0.8}}
        )
        assert result['thresholds']['LLM01'] == 0.8
        assert result['thresholds']['LLM02'] == 0.7

    def test_skip_none_values(self):
        """Test that None values are skipped."""
        result = merge_configs(
            {'mode': 'recall'},
            {'mode': None}
        )
        assert result['mode'] == 'recall'

    def test_skip_empty_configs(self):
        """Test that empty configs are skipped."""
        result = merge_configs(
            {'mode': 'recall'},
            None,
            {},
            {'dedup': 'off'}
        )
        assert result == {'mode': 'recall', 'dedup': 'off'}


class TestLoadConfig:
    """Test load_config function."""

    def test_load_defaults(self):
        """Test loading default configuration."""
        config = load_config()
        assert config.mode == 'recall'
        assert config.dedup == 'exact'

    def test_cli_overrides_defaults(self):
        """Test that CLI options override defaults."""
        config = load_config(cli_options={'mode': 'strict'})
        assert config.mode == 'strict'

    def test_cli_overrides_env(self):
        """Test that CLI options override environment."""
        os.environ['AISEC_MODE'] = 'recall'
        try:
            config = load_config(cli_options={'mode': 'strict'})
            assert config.mode == 'strict'
        finally:
            del os.environ['AISEC_MODE']

    def test_load_from_yaml_file(self):
        """Test loading from explicit YAML file."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            f.write('mode: strict\nexclude_dirs:\n  - node_modules\n')
            f.flush()

            config = load_config(config_path=Path(f.name))
            assert config.mode == 'strict'
            assert 'node_modules' in config.exclude_dirs

            os.unlink(f.name)

    def test_auto_discover_config(self):
        """Test auto-discovering config file."""
        with tempfile.TemporaryDirectory() as tmpdir:
            config_file = Path(tmpdir) / '.aisentry.yaml'
            config_file.write_text('mode: strict')

            config = load_config(scan_path=Path(tmpdir))
            assert config.mode == 'strict'

    def test_full_precedence_chain(self):
        """Test full precedence: CLI > env > yaml > defaults."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            f.write('mode: strict\ndedup: off\n')
            f.flush()

            os.environ['AISEC_DEDUP'] = 'exact'
            try:
                config = load_config(
                    config_path=Path(f.name),
                    cli_options={'global_threshold': 0.5}
                )
                # mode from yaml (not overridden)
                assert config.mode == 'strict'
                # dedup from env (overrides yaml)
                assert config.dedup == 'exact'
                # global_threshold from CLI
                assert config.global_threshold == 0.5
            finally:
                del os.environ['AISEC_DEDUP']
                os.unlink(f.name)
