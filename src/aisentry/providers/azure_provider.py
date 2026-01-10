"""Azure OpenAI provider implementation"""

import logging
import os
from typing import List, Optional

from .base_provider import BaseProvider, LLMResponse, ProviderError, RateLimitError

logger = logging.getLogger(__name__)


class AzureProvider(BaseProvider):
    """
    Azure OpenAI provider.

    Supports Azure-hosted OpenAI models.
    Requires AZURE_OPENAI_API_KEY and AZURE_OPENAI_ENDPOINT environment variables.
    """

    provider_name = "azure"
    requires_api_key = True
    env_var_name = "AZURE_OPENAI_API_KEY"

    def __init__(
        self,
        model: Optional[str] = None,
        deployment_name: Optional[str] = None,
        api_version: str = "2024-02-15-preview",
        temperature: float = 0.7,
        max_tokens: int = 150,
        **kwargs,
    ):
        self.deployment_name = deployment_name or model
        self.api_version = api_version
        self.temperature = temperature
        self.max_tokens = max_tokens
        self._endpoint = os.environ.get("AZURE_OPENAI_ENDPOINT")
        self._client = None
        super().__init__(model=model, **kwargs)

    def _validate_config(self) -> None:
        """Validate Azure OpenAI configuration."""
        super()._validate_config()
        if not self._endpoint:
            raise ProviderError(
                "Azure OpenAI endpoint not found. "
                "Set AZURE_OPENAI_ENDPOINT environment variable."
            )
        if not self.deployment_name:
            raise ProviderError(
                "Azure OpenAI deployment name required. "
                "Pass deployment_name parameter or use model as deployment name."
            )

    def _get_client(self):
        """Lazy initialization of Azure OpenAI client."""
        if self._client is None:
            try:
                from openai import AsyncAzureOpenAI

                self._client = AsyncAzureOpenAI(
                    api_key=self.api_key,
                    api_version=self.api_version,
                    azure_endpoint=self._endpoint,
                )
            except ImportError:
                raise ProviderError(
                    "OpenAI package not installed. Run: pip install openai"
                )
        return self._client

    async def _execute_query(self, prompt: str, **kwargs) -> LLMResponse:
        """Execute query to Azure OpenAI."""
        client = self._get_client()

        temperature = kwargs.get("temperature", self.temperature)
        max_tokens = kwargs.get("max_tokens", self.max_tokens)

        try:
            response = await client.chat.completions.create(
                model=self.deployment_name,
                messages=[{"role": "user", "content": prompt}],
                temperature=temperature,
                max_tokens=max_tokens,
            )

            content = response.choices[0].message.content or ""
            tokens_used = response.usage.total_tokens if response.usage else 0

            return LLMResponse(
                content=content,
                tokens_used=tokens_used,
                model=self.deployment_name,
                raw_response=response.model_dump() if hasattr(response, 'model_dump') else {},
            )

        except Exception as e:
            error_str = str(e).lower()
            if "rate_limit" in error_str or "429" in error_str:
                raise RateLimitError(f"Azure OpenAI rate limit exceeded: {e}")
            raise ProviderError(f"Azure OpenAI error: {e}")

    def get_available_models(self) -> List[str]:
        """Return list of common Azure OpenAI deployment names."""
        return [
            "gpt-4o",
            "gpt-4-turbo",
            "gpt-4",
            "gpt-35-turbo",
        ]
