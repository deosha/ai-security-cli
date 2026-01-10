"""Anthropic provider implementation"""

import logging
from typing import List, Optional

from .base_provider import BaseProvider, LLMResponse, ProviderError, RateLimitError

logger = logging.getLogger(__name__)


class AnthropicProvider(BaseProvider):
    """
    Anthropic API provider.

    Supports Claude 3.5, Claude 3, and other Anthropic models.
    Requires ANTHROPIC_API_KEY environment variable.
    """

    provider_name = "anthropic"
    requires_api_key = True
    env_var_name = "ANTHROPIC_API_KEY"

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
        """Lazy initialization of Anthropic client."""
        if self._client is None:
            try:
                from anthropic import AsyncAnthropic
                self._client = AsyncAnthropic(api_key=self.api_key)
            except ImportError:
                raise ProviderError(
                    "Anthropic package not installed. Run: pip install anthropic"
                )
        return self._client

    async def _execute_query(self, prompt: str, **kwargs) -> LLMResponse:
        """Execute query to Anthropic API."""
        client = self._get_client()

        temperature = kwargs.get("temperature", self.temperature)
        max_tokens = kwargs.get("max_tokens", self.max_tokens)

        try:
            response = await client.messages.create(
                model=self.model,
                max_tokens=max_tokens,
                messages=[{"role": "user", "content": prompt}],
            )

            content = response.content[0].text if response.content else ""
            tokens_used = (
                response.usage.input_tokens + response.usage.output_tokens
                if response.usage
                else 0
            )

            return LLMResponse(
                content=content,
                tokens_used=tokens_used,
                model=response.model,
                raw_response=response.model_dump() if hasattr(response, 'model_dump') else {},
            )

        except Exception as e:
            error_str = str(e).lower()
            if "rate_limit" in error_str or "429" in error_str:
                raise RateLimitError(f"Anthropic rate limit exceeded: {e}")
            raise ProviderError(f"Anthropic API error: {e}")

    def get_available_models(self) -> List[str]:
        """Return list of available Anthropic models."""
        return [
            "claude-3-5-sonnet-20241022",
            "claude-3-5-haiku-20241022",
            "claude-3-opus-20240229",
            "claude-3-sonnet-20240229",
            "claude-3-haiku-20240307",
        ]
