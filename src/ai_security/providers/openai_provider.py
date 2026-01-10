"""OpenAI provider implementation"""

import logging
from typing import List, Optional

from .base_provider import BaseProvider, LLMResponse, ProviderError, RateLimitError

logger = logging.getLogger(__name__)


class OpenAIProvider(BaseProvider):
    """
    OpenAI API provider.

    Supports GPT-4, GPT-4 Turbo, GPT-3.5 Turbo, and other OpenAI models.
    Requires OPENAI_API_KEY environment variable.
    """

    provider_name = "openai"
    requires_api_key = True
    env_var_name = "OPENAI_API_KEY"

    def __init__(
        self,
        model: Optional[str] = None,
        temperature: float = 0.7,
        max_tokens: int = 150,
        **kwargs,
    ):
        self.temperature = temperature
        self.max_tokens = max_tokens
        self._client = None
        super().__init__(model=model, **kwargs)

    def _get_client(self):
        """Lazy initialization of OpenAI client."""
        if self._client is None:
            try:
                from openai import AsyncOpenAI
                self._client = AsyncOpenAI(api_key=self.api_key)
            except ImportError:
                raise ProviderError(
                    "OpenAI package not installed. Run: pip install openai"
                )
        return self._client

    async def _execute_query(self, prompt: str, **kwargs) -> LLMResponse:
        """Execute query to OpenAI API."""
        client = self._get_client()

        temperature = kwargs.get("temperature", self.temperature)
        max_tokens = kwargs.get("max_tokens", self.max_tokens)

        try:
            response = await client.chat.completions.create(
                model=self.model,
                messages=[{"role": "user", "content": prompt}],
                temperature=temperature,
                max_tokens=max_tokens,
            )

            content = response.choices[0].message.content or ""
            tokens_used = response.usage.total_tokens if response.usage else 0

            return LLMResponse(
                content=content,
                tokens_used=tokens_used,
                model=response.model,
                raw_response=response.model_dump() if hasattr(response, 'model_dump') else {},
            )

        except Exception as e:
            error_str = str(e).lower()
            if "rate_limit" in error_str or "429" in error_str:
                raise RateLimitError(f"OpenAI rate limit exceeded: {e}")
            raise ProviderError(f"OpenAI API error: {e}")

    def get_available_models(self) -> List[str]:
        """Return list of available OpenAI models."""
        return [
            "gpt-4o",
            "gpt-4o-mini",
            "gpt-4-turbo",
            "gpt-4",
            "gpt-3.5-turbo",
        ]
