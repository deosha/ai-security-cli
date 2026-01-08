"""
Dependency Analyzer for detecting security-related packages.
"""

import re
from pathlib import Path
from typing import Dict, List, Optional, Set
from dataclasses import dataclass


@dataclass
class DependencyMatch:
    """Result of a dependency detection."""
    package_name: str
    version: Optional[str]
    file_path: str
    category: str  # security, monitoring, ml, etc.
    description: str


class DependencyAnalyzer:
    """
    Analyzes project dependencies for security-related packages.
    """

    # Security-related packages by category
    SECURITY_PACKAGES = {
        # Input sanitization
        "sanitization": {
            "bleach": "HTML sanitization library",
            "html-sanitizer": "HTML sanitization",
            "markupsafe": "Safe string handling",
            "defusedxml": "Safe XML parsing",
        },
        # Rate limiting
        "rate_limiting": {
            "ratelimit": "Rate limiting decorator",
            "fastapi-limiter": "FastAPI rate limiting",
            "flask-limiter": "Flask rate limiting",
            "django-ratelimit": "Django rate limiting",
            "slowapi": "Starlette/FastAPI rate limiting",
        },
        # Authentication
        "authentication": {
            "pyjwt": "JWT authentication",
            "python-jose": "JWT/JWS/JWE implementation",
            "authlib": "OAuth/OpenID Connect",
            "oauthlib": "OAuth implementation",
            "passlib": "Password hashing",
            "bcrypt": "Password hashing",
            "argon2-cffi": "Argon2 password hashing",
        },
        # PII detection
        "pii_detection": {
            "presidio-analyzer": "Microsoft PII detection",
            "presidio-anonymizer": "PII anonymization",
            "scrubadub": "PII scrubbing",
            "pii-codex": "PII detection",
            "spacy": "NLP with NER for PII",
            "flair": "NLP with NER",
        },
        # Validation
        "validation": {
            "pydantic": "Data validation",
            "marshmallow": "Object serialization/validation",
            "cerberus": "Data validation",
            "voluptuous": "Data validation",
            "jsonschema": "JSON schema validation",
        },
        # Encryption
        "encryption": {
            "cryptography": "Cryptographic primitives",
            "pycryptodome": "Cryptographic library",
            "nacl": "Networking and cryptography",
            "fernet": "Symmetric encryption",
        },
        # Logging/Monitoring
        "logging": {
            "structlog": "Structured logging",
            "loguru": "Modern logging",
            "python-json-logger": "JSON logging",
            "sentry-sdk": "Error tracking",
            "opentelemetry-sdk": "Observability",
            "prometheus-client": "Metrics",
            "datadog": "Monitoring",
        },
        # Security scanning
        "security_scanning": {
            "bandit": "Security linter",
            "safety": "Dependency vulnerability scanner",
            "pip-audit": "Dependency auditing",
            "semgrep": "Code analysis",
            "detect-secrets": "Secret detection",
            "trufflehog": "Secret scanning",
        },
        # ML security
        "ml_security": {
            "adversarial-robustness-toolbox": "ML security",
            "cleverhans": "Adversarial examples",
            "foolbox": "Adversarial attacks",
            "textattack": "NLP adversarial attacks",
        },
        # Model versioning
        "model_versioning": {
            "mlflow": "ML lifecycle management",
            "dvc": "Data version control",
            "wandb": "ML experiment tracking",
            "neptune": "ML experiment tracking",
            "comet-ml": "ML experiment tracking",
        },
        # Drift detection
        "drift_detection": {
            "evidently": "ML model monitoring",
            "alibi-detect": "Drift detection",
            "deepchecks": "ML testing",
            "whylogs": "Data logging/monitoring",
            "nannyml": "Post-deployment monitoring",
        },
        # Explainability
        "explainability": {
            "shap": "Model explanations",
            "lime": "Model interpretability",
            "alibi": "Model explanations",
            "captum": "PyTorch interpretability",
            "interpret": "Model interpretability",
        },
        # Bias detection
        "bias_detection": {
            "fairlearn": "Fairness assessment",
            "aequitas": "Bias auditing",
            "aif360": "AI Fairness 360",
            "responsibleai": "Responsible AI toolkit",
        },
    }

    # CI/CD security tools
    CI_SECURITY_TOOLS = {
        "pre-commit": "Git hooks framework",
        "tox": "Test automation",
        "nox": "Test automation",
        "pytest-cov": "Test coverage",
        "coverage": "Code coverage",
    }

    def __init__(self):
        self._dependencies: Dict[str, DependencyMatch] = {}
        self._dev_dependencies: Dict[str, DependencyMatch] = {}
        self._all_packages: Set[str] = set()

    def analyze_directory(self, directory: Path) -> int:
        """Analyze all dependency files in directory."""
        count = 0

        # Requirements files
        for req_file in directory.rglob("requirements*.txt"):
            if self._analyze_requirements(req_file):
                count += 1

        # pyproject.toml
        pyproject = directory / "pyproject.toml"
        if pyproject.exists() and self._analyze_pyproject(pyproject):
            count += 1

        # setup.py
        setup_py = directory / "setup.py"
        if setup_py.exists() and self._analyze_setup_py(setup_py):
            count += 1

        # Pipfile
        pipfile = directory / "Pipfile"
        if pipfile.exists() and self._analyze_pipfile(pipfile):
            count += 1

        # poetry.lock, Pipfile.lock for actual installed versions
        for lock_file in ["poetry.lock", "Pipfile.lock"]:
            lock_path = directory / lock_file
            if lock_path.exists():
                self._analyze_lock_file(lock_path)
                count += 1

        return count

    def _analyze_requirements(self, file_path: Path) -> bool:
        """Parse requirements.txt file."""
        try:
            content = file_path.read_text(encoding="utf-8", errors="ignore")
            is_dev = "dev" in file_path.name.lower() or "test" in file_path.name.lower()

            for line in content.splitlines():
                line = line.strip()
                if not line or line.startswith("#") or line.startswith("-"):
                    continue

                # Parse package name and version
                match = re.match(r"^([a-zA-Z0-9_-]+)(?:\[.*\])?([<>=!~]+.*)?$", line)
                if match:
                    pkg_name = match.group(1).lower()
                    version = match.group(2) if match.group(2) else None

                    self._all_packages.add(pkg_name)
                    category, description = self._categorize_package(pkg_name)

                    if category:
                        dep_match = DependencyMatch(
                            package_name=pkg_name,
                            version=version,
                            file_path=str(file_path),
                            category=category,
                            description=description,
                        )
                        if is_dev:
                            self._dev_dependencies[pkg_name] = dep_match
                        else:
                            self._dependencies[pkg_name] = dep_match

            return True
        except Exception:
            return False

    def _analyze_pyproject(self, file_path: Path) -> bool:
        """Parse pyproject.toml file."""
        try:
            try:
                import tomllib
                content = file_path.read_bytes()
                data = tomllib.loads(content.decode("utf-8"))
            except ImportError:
                try:
                    import tomli
                    content = file_path.read_bytes()
                    data = tomli.loads(content.decode("utf-8"))
                except ImportError:
                    return False

            # Poetry dependencies
            if "tool" in data and "poetry" in data["tool"]:
                poetry = data["tool"]["poetry"]
                if "dependencies" in poetry:
                    self._process_deps(poetry["dependencies"], str(file_path), False)
                if "dev-dependencies" in poetry:
                    self._process_deps(poetry["dev-dependencies"], str(file_path), True)
                if "group" in poetry:
                    for group in poetry["group"].values():
                        if "dependencies" in group:
                            self._process_deps(group["dependencies"], str(file_path), True)

            # PEP 621 dependencies
            if "project" in data:
                project = data["project"]
                if "dependencies" in project:
                    for dep in project["dependencies"]:
                        self._parse_pep508(dep, str(file_path), False)
                if "optional-dependencies" in project:
                    for deps in project["optional-dependencies"].values():
                        for dep in deps:
                            self._parse_pep508(dep, str(file_path), True)

            return True
        except Exception:
            return False

    def _analyze_setup_py(self, file_path: Path) -> bool:
        """Parse setup.py for dependencies."""
        try:
            content = file_path.read_text(encoding="utf-8", errors="ignore")

            # Find install_requires
            install_match = re.search(
                r"install_requires\s*=\s*\[(.*?)\]",
                content, re.DOTALL
            )
            if install_match:
                deps_str = install_match.group(1)
                for dep in re.findall(r"['\"]([^'\"]+)['\"]", deps_str):
                    self._parse_pep508(dep, str(file_path), False)

            # Find extras_require
            extras_match = re.search(
                r"extras_require\s*=\s*\{(.*?)\}",
                content, re.DOTALL
            )
            if extras_match:
                for dep in re.findall(r"['\"]([^'\"]+)['\"]", extras_match.group(1)):
                    if not dep.endswith(":"):  # Skip dict keys
                        self._parse_pep508(dep, str(file_path), True)

            return True
        except Exception:
            return False

    def _analyze_pipfile(self, file_path: Path) -> bool:
        """Parse Pipfile."""
        try:
            try:
                import tomllib
                content = file_path.read_bytes()
                data = tomllib.loads(content.decode("utf-8"))
            except ImportError:
                try:
                    import tomli
                    content = file_path.read_bytes()
                    data = tomli.loads(content.decode("utf-8"))
                except ImportError:
                    return False

            if "packages" in data:
                self._process_deps(data["packages"], str(file_path), False)
            if "dev-packages" in data:
                self._process_deps(data["dev-packages"], str(file_path), True)

            return True
        except Exception:
            return False

    def _analyze_lock_file(self, file_path: Path) -> bool:
        """Parse lock files for actual versions."""
        # Just mark that we have lock files for now
        return True

    def _process_deps(
        self,
        deps: Dict,
        file_path: str,
        is_dev: bool
    ) -> None:
        """Process dependency dictionary."""
        for pkg_name, version_info in deps.items():
            if pkg_name.lower() == "python":
                continue

            pkg_name = pkg_name.lower()
            self._all_packages.add(pkg_name)

            version = None
            if isinstance(version_info, str):
                version = version_info
            elif isinstance(version_info, dict) and "version" in version_info:
                version = version_info["version"]

            category, description = self._categorize_package(pkg_name)
            if category:
                dep_match = DependencyMatch(
                    package_name=pkg_name,
                    version=version,
                    file_path=file_path,
                    category=category,
                    description=description,
                )
                if is_dev:
                    self._dev_dependencies[pkg_name] = dep_match
                else:
                    self._dependencies[pkg_name] = dep_match

    def _parse_pep508(self, dep_str: str, file_path: str, is_dev: bool) -> None:
        """Parse PEP 508 dependency string."""
        match = re.match(r"^([a-zA-Z0-9_-]+)", dep_str)
        if match:
            pkg_name = match.group(1).lower()
            self._all_packages.add(pkg_name)

            version_match = re.search(r"([<>=!~]+[\d.]+)", dep_str)
            version = version_match.group(1) if version_match else None

            category, description = self._categorize_package(pkg_name)
            if category:
                dep_match = DependencyMatch(
                    package_name=pkg_name,
                    version=version,
                    file_path=file_path,
                    category=category,
                    description=description,
                )
                if is_dev:
                    self._dev_dependencies[pkg_name] = dep_match
                else:
                    self._dependencies[pkg_name] = dep_match

    def _categorize_package(self, pkg_name: str) -> tuple[Optional[str], str]:
        """Categorize a package by security function."""
        pkg_lower = pkg_name.lower().replace("-", "_").replace("_", "-")

        for category, packages in self.SECURITY_PACKAGES.items():
            for pkg, description in packages.items():
                if pkg_lower == pkg.lower().replace("_", "-"):
                    return category, description

        for pkg, description in self.CI_SECURITY_TOOLS.items():
            if pkg_lower == pkg.lower().replace("_", "-"):
                return "ci_security", description

        return None, ""

    def has_package(self, package_name: str) -> bool:
        """Check if a package is installed."""
        pkg_lower = package_name.lower()
        return pkg_lower in self._all_packages

    def has_category(self, category: str) -> bool:
        """Check if any package from a category is installed."""
        return any(
            d.category == category
            for d in list(self._dependencies.values()) + list(self._dev_dependencies.values())
        )

    def get_packages_by_category(self, category: str) -> List[DependencyMatch]:
        """Get all packages in a category."""
        return [
            d for d in list(self._dependencies.values()) + list(self._dev_dependencies.values())
            if d.category == category
        ]

    def get_all_security_packages(self) -> List[DependencyMatch]:
        """Get all detected security-related packages."""
        return list(self._dependencies.values()) + list(self._dev_dependencies.values())

    def get_all_packages(self) -> Set[str]:
        """Get all package names."""
        return self._all_packages

    def clear(self) -> None:
        """Clear all cached data."""
        self._dependencies.clear()
        self._dev_dependencies.clear()
        self._all_packages.clear()
