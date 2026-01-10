"""Base provider class for LLM API connections"""

import asyncio
import logging
import os
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


@dataclass
class LLMResponse:
    """Standardized response from any LLM provider."""

    content: str
    tokens_used: int = 0
    model: str = ""
    latency_ms: float = 0.0
    raw_response: Dict[str, Any] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "content": self.content,
            "tokens_used": self.tokens_used,
            "model": self.model,
            "latency_ms": round(self.latency_ms, 2),
            "metadata": self.metadata,
        }


class ProviderError(Exception):
    """Base exception for provider errors."""

    pass


class AuthenticationError(ProviderError):
    """Raised when API authentication fails."""

    pass


class RateLimitError(ProviderError):
    """Raised when rate limit is exceeded."""

    pass


class BaseProvider(ABC):
    """
    Abstract base class for LLM providers.

    All providers must implement query() and get_available_models().
    API keys are read from environment variables only for security.
    """

    provider_name: str = "base"
    requires_api_key: bool = True
    env_var_name: str = "API_KEY"

    def __init__(
        self,
        model: Optional[str] = None,
        endpoint: Optional[str] = None,
        timeout: int = 30,
        max_retries: int = 3,
        **kwargs,
    ):
        """
        Initialize provider.

        Args:
            model: Model name to use (uses default if not specified)
            endpoint: Custom endpoint URL (for custom providers)
            timeout: Request timeout in seconds
            max_retries: Maximum retry attempts for failed requests
            **kwargs: Additional provider-specific configuration
        """
        self.api_key = self._get_api_key_from_env()
        self.model = model or self.get_default_model()
        self.endpoint = endpoint
        self.timeout = timeout
        self.max_retries = max_retries
        self.config = kwargs

        # Statistics tracking
        self.stats = {
            "total_queries": 0,
            "successful_queries": 0,
            "failed_queries": 0,
            "total_tokens": 0,
            "total_latency_ms": 0.0,
        }

        self._validate_config()

    def _get_api_key_from_env(self) -> Optional[str]:
        """Get API key from environment variable."""
        return os.environ.get(self.env_var_name)

    def _validate_config(self) -> None:
        """Validate provider configuration."""
        if self.requires_api_key and not self.api_key:
            raise AuthenticationError(
                f"API key not found. Set the {self.env_var_name} environment variable."
            )

    async def query(self, prompt: str, **kwargs) -> LLMResponse:
        """
        Send a query to the LLM and get response.

        Args:
            prompt: The prompt to send
            **kwargs: Additional parameters (temperature, max_tokens, etc.)

        Returns:
            LLMResponse with content and metadata
        """
        start_time = time.time()
        self.stats["total_queries"] += 1

        last_error = None
        for attempt in range(self.max_retries):
            try:
                response = await self._execute_query(prompt, **kwargs)
                latency_ms = (time.time() - start_time) * 1000

                response.latency_ms = latency_ms
                response.model = self.model

                # Update stats
                self.stats["successful_queries"] += 1
                self.stats["total_tokens"] += response.tokens_used
                self.stats["total_latency_ms"] += latency_ms

                return response

            except RateLimitError as e:
                last_error = e
                wait_time = 2 ** attempt  # Exponential backoff
                logger.warning(
                    f"Rate limited on attempt {attempt + 1}, waiting {wait_time}s"
                )
                await asyncio.sleep(wait_time)

            except Exception as e:
                last_error = e
                if attempt < self.max_retries - 1:
                    logger.warning(f"Query failed on attempt {attempt + 1}: {e}")
                    await asyncio.sleep(1)

        self.stats["failed_queries"] += 1
        raise ProviderError(f"Query failed after {self.max_retries} attempts: {last_error}")

    @abstractmethod
    async def _execute_query(self, prompt: str, **kwargs) -> LLMResponse:
        """
        Execute the actual API query.

        Override in subclass with provider-specific implementation.

        Args:
            prompt: The prompt to send
            **kwargs: Additional parameters

        Returns:
            LLMResponse with content
        """
        raise NotImplementedError("Subclass must implement _execute_query()")

    async def query_batch(
        self, prompts: List[str], parallelism: int = 5, **kwargs
    ) -> List[LLMResponse]:
        """
        Send multiple queries with controlled parallelism.

        Args:
            prompts: List of prompts to send
            parallelism: Maximum concurrent requests
            **kwargs: Additional parameters for each query

        Returns:
            List of LLMResponse objects
        """
        semaphore = asyncio.Semaphore(parallelism)

        async def limited_query(prompt: str) -> LLMResponse:
            async with semaphore:
                return await self.query(prompt, **kwargs)

        tasks = [limited_query(prompt) for prompt in prompts]
        return await asyncio.gather(*tasks, return_exceptions=True)

    @abstractmethod
    def get_available_models(self) -> List[str]:
        """Return list of available models for this provider."""
        raise NotImplementedError("Subclass must implement get_available_models()")

    def get_default_model(self) -> str:
        """Return default model for this provider."""
        models = self.get_available_models()
        return models[0] if models else ""

    async def test_connection(self) -> Dict[str, Any]:
        """
        Test connection to the provider.

        Returns:
            Dict with connection status and details
        """
        try:
            start_time = time.time()
            response = await self.query("Hello, respond with 'OK' only.")
            latency = (time.time() - start_time) * 1000

            return {
                "success": True,
                "provider": self.provider_name,
                "model": self.model,
                "latency_ms": round(latency, 2),
                "response_preview": response.content[:100],
            }
        except Exception as e:
            return {
                "success": False,
                "provider": self.provider_name,
                "model": self.model,
                "error": str(e),
            }

    def get_stats(self) -> Dict[str, Any]:
        """Get provider usage statistics."""
        avg_latency = (
            self.stats["total_latency_ms"] / self.stats["successful_queries"]
            if self.stats["successful_queries"] > 0
            else 0
        )
        return {
            **self.stats,
            "average_latency_ms": round(avg_latency, 2),
            "success_rate": (
                self.stats["successful_queries"] / self.stats["total_queries"]
                if self.stats["total_queries"] > 0
                else 0
            ),
        }

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}(model={self.model})"
