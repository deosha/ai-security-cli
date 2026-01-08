"""
Config Analyzer for detecting configuration patterns.
"""

import json
import os
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Set
from dataclasses import dataclass

try:
    import yaml
    HAS_YAML = True
except ImportError:
    HAS_YAML = False


@dataclass
class ConfigMatch:
    """Result of a config pattern match."""
    file_path: str
    key: str
    value: Any
    line_number: Optional[int] = None
    file_type: str = "unknown"


class ConfigAnalyzer:
    """
    Analyzes configuration files for security settings.
    """

    CONFIG_PATTERNS = [
        "*.yaml", "*.yml", "*.json", "*.toml",
        "*.env", ".env*", "*.ini", "*.cfg",
        "config.*", "settings.*",
    ]

    def __init__(self):
        self._configs: Dict[str, Dict[str, Any]] = {}
        self._matches: List[ConfigMatch] = []
        self._env_vars: Dict[str, str] = {}

    def analyze_directory(self, directory: Path) -> int:
        """Analyze all config files in directory."""
        count = 0

        for pattern in self.CONFIG_PATTERNS:
            for config_file in directory.rglob(pattern):
                if self._analyze_file(config_file):
                    count += 1

        # Also check for specific files
        specific_files = [
            "pyproject.toml", "setup.cfg", "setup.py",
            "docker-compose.yaml", "docker-compose.yml",
            "Dockerfile", ".dockerignore",
            "requirements.txt", "requirements-dev.txt",
            ".pre-commit-config.yaml",
            ".github/workflows/*.yaml", ".github/workflows/*.yml",
            ".gitlab-ci.yml", "Jenkinsfile",
            "terraform.tfvars", "*.tf",
        ]

        for pattern in specific_files:
            for config_file in directory.rglob(pattern):
                if self._analyze_file(config_file):
                    count += 1

        return count

    def _analyze_file(self, file_path: Path) -> bool:
        """Analyze a single config file."""
        try:
            suffix = file_path.suffix.lower()
            name = file_path.name.lower()

            if suffix in [".yaml", ".yml"]:
                return self._parse_yaml(file_path)
            elif suffix == ".json":
                return self._parse_json(file_path)
            elif suffix == ".env" or name.startswith(".env"):
                return self._parse_env(file_path)
            elif suffix == ".toml":
                return self._parse_toml(file_path)
            elif suffix in [".ini", ".cfg"]:
                return self._parse_ini(file_path)
            elif name == "dockerfile":
                return self._parse_dockerfile(file_path)
            elif name == "requirements.txt" or name.startswith("requirements"):
                return self._parse_requirements(file_path)
            else:
                # Try to detect format from content
                return self._parse_generic(file_path)
        except Exception:
            return False

    def _parse_yaml(self, file_path: Path) -> bool:
        """Parse YAML file."""
        if not HAS_YAML:
            return False
        try:
            content = file_path.read_text(encoding="utf-8", errors="ignore")
            data = yaml.safe_load(content)
            if data:
                self._configs[str(file_path)] = data
                self._extract_keys(data, str(file_path), "yaml")
            return True
        except Exception:
            return False

    def _parse_json(self, file_path: Path) -> bool:
        """Parse JSON file."""
        try:
            content = file_path.read_text(encoding="utf-8", errors="ignore")
            data = json.loads(content)
            if data:
                self._configs[str(file_path)] = data
                self._extract_keys(data, str(file_path), "json")
            return True
        except Exception:
            return False

    def _parse_env(self, file_path: Path) -> bool:
        """Parse .env file."""
        try:
            content = file_path.read_text(encoding="utf-8", errors="ignore")
            for line_num, line in enumerate(content.splitlines(), 1):
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    key, _, value = line.partition("=")
                    key = key.strip()
                    value = value.strip().strip("\"'")
                    self._env_vars[key] = value
                    self._matches.append(ConfigMatch(
                        file_path=str(file_path),
                        key=key,
                        value=value,
                        line_number=line_num,
                        file_type="env",
                    ))
            return True
        except Exception:
            return False

    def _parse_toml(self, file_path: Path) -> bool:
        """Parse TOML file."""
        try:
            import tomllib
            content = file_path.read_bytes()
            data = tomllib.loads(content.decode("utf-8"))
            if data:
                self._configs[str(file_path)] = data
                self._extract_keys(data, str(file_path), "toml")
            return True
        except ImportError:
            # Python < 3.11, try tomli
            try:
                import tomli
                content = file_path.read_bytes()
                data = tomli.loads(content.decode("utf-8"))
                if data:
                    self._configs[str(file_path)] = data
                    self._extract_keys(data, str(file_path), "toml")
                return True
            except ImportError:
                return False
        except Exception:
            return False

    def _parse_ini(self, file_path: Path) -> bool:
        """Parse INI/CFG file."""
        try:
            import configparser
            config = configparser.ConfigParser()
            config.read(str(file_path))
            data = {s: dict(config[s]) for s in config.sections()}
            if data:
                self._configs[str(file_path)] = data
                self._extract_keys(data, str(file_path), "ini")
            return True
        except Exception:
            return False

    def _parse_dockerfile(self, file_path: Path) -> bool:
        """Parse Dockerfile for security settings."""
        try:
            content = file_path.read_text(encoding="utf-8", errors="ignore")
            data = {"dockerfile": True, "instructions": []}

            for line_num, line in enumerate(content.splitlines(), 1):
                line = line.strip()
                if line and not line.startswith("#"):
                    parts = line.split(None, 1)
                    if parts:
                        instruction = parts[0].upper()
                        args = parts[1] if len(parts) > 1 else ""
                        data["instructions"].append({
                            "instruction": instruction,
                            "args": args,
                            "line": line_num,
                        })
                        self._matches.append(ConfigMatch(
                            file_path=str(file_path),
                            key=instruction,
                            value=args,
                            line_number=line_num,
                            file_type="dockerfile",
                        ))

            self._configs[str(file_path)] = data
            return True
        except Exception:
            return False

    def _parse_requirements(self, file_path: Path) -> bool:
        """Parse requirements.txt file."""
        try:
            content = file_path.read_text(encoding="utf-8", errors="ignore")
            data = {"packages": []}

            for line_num, line in enumerate(content.splitlines(), 1):
                line = line.strip()
                if line and not line.startswith("#") and not line.startswith("-"):
                    # Parse package name
                    match = re.match(r"^([a-zA-Z0-9_-]+)", line)
                    if match:
                        pkg_name = match.group(1)
                        data["packages"].append(pkg_name)
                        self._matches.append(ConfigMatch(
                            file_path=str(file_path),
                            key=pkg_name,
                            value=line,
                            line_number=line_num,
                            file_type="requirements",
                        ))

            self._configs[str(file_path)] = data
            return True
        except Exception:
            return False

    def _parse_generic(self, file_path: Path) -> bool:
        """Try to parse file as key-value pairs."""
        try:
            content = file_path.read_text(encoding="utf-8", errors="ignore")
            # Check if it looks like YAML
            if ":" in content and not content.startswith("{"):
                return self._parse_yaml(file_path)
            # Check if it looks like JSON
            if content.strip().startswith("{") or content.strip().startswith("["):
                return self._parse_json(file_path)
            return False
        except Exception:
            return False

    def _extract_keys(
        self,
        data: Any,
        file_path: str,
        file_type: str,
        prefix: str = ""
    ) -> None:
        """Recursively extract keys from nested config."""
        if isinstance(data, dict):
            for key, value in data.items():
                full_key = f"{prefix}.{key}" if prefix else key
                self._matches.append(ConfigMatch(
                    file_path=file_path,
                    key=full_key,
                    value=value if not isinstance(value, (dict, list)) else type(value).__name__,
                    file_type=file_type,
                ))
                self._extract_keys(value, file_path, file_type, full_key)
        elif isinstance(data, list):
            for i, item in enumerate(data):
                self._extract_keys(item, file_path, file_type, f"{prefix}[{i}]")

    def find_key(self, pattern: str, regex: bool = False) -> List[ConfigMatch]:
        """Find config keys matching pattern."""
        results = []
        if regex:
            compiled = re.compile(pattern, re.IGNORECASE)
            for match in self._matches:
                if compiled.search(match.key):
                    results.append(match)
        else:
            pattern_lower = pattern.lower()
            for match in self._matches:
                if pattern_lower in match.key.lower():
                    results.append(match)
        return results

    def find_value(self, pattern: str, regex: bool = False) -> List[ConfigMatch]:
        """Find config values matching pattern."""
        results = []
        if regex:
            compiled = re.compile(pattern, re.IGNORECASE)
            for match in self._matches:
                value_str = str(match.value)
                if compiled.search(value_str):
                    results.append(match)
        else:
            pattern_lower = pattern.lower()
            for match in self._matches:
                if pattern_lower in str(match.value).lower():
                    results.append(match)
        return results

    def has_key(self, key: str) -> bool:
        """Check if a config key exists."""
        key_lower = key.lower()
        return any(key_lower in m.key.lower() for m in self._matches)

    def has_env_var(self, var_name: str) -> bool:
        """Check if an environment variable is defined."""
        return var_name in self._env_vars

    def get_env_var(self, var_name: str) -> Optional[str]:
        """Get environment variable value."""
        return self._env_vars.get(var_name)

    def has_package(self, package_name: str) -> bool:
        """Check if a package is in requirements."""
        pkg_lower = package_name.lower()
        for match in self._matches:
            if match.file_type == "requirements" and pkg_lower in match.key.lower():
                return True
        return False

    def get_all_packages(self) -> Set[str]:
        """Get all packages from requirements files."""
        return {
            m.key for m in self._matches
            if m.file_type == "requirements"
        }

    def get_all_env_vars(self) -> Dict[str, str]:
        """Get all environment variables."""
        return dict(self._env_vars)

    def clear(self) -> None:
        """Clear all cached data."""
        self._configs.clear()
        self._matches.clear()
        self._env_vars.clear()
