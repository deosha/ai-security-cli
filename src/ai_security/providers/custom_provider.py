"""Custom endpoint provider implementation"""

import logging
from typing import Any, Dict, List, Optional

from .base_provider import BaseProvider, LLMResponse, ProviderError, RateLimitError

logger = logging.getLogger(__name__)


class CustomProvider(BaseProvider):
    """
    Custom endpoint provider for generic LLM APIs.

    Supports any HTTP-based LLM API with configurable request/response formats.
    Optionally uses CUSTOM_API_KEY environment variable.
    """

    provider_name = "custom"
    requires_api_key = False  # Optional
    env_var_name = "CUSTOM_API_KEY"

    def __init__(
        self,
        endpoint: str,
        model: Optional[str] = None,
        request_format: str = "openai",
        response_path: str = "choices.0.message.content",
        headers: Optional[Dict[str, str]] = None,
        temperature: float = 0.7,
        max_tokens: int = 150,
        **kwargs,
    ):
        """
        Initialize custom provider.

        Args:
            endpoint: API endpoint URL (required)
            model: Model name to send in request
            request_format: Request format type: 'openai', 'anthropic', 'simple'
            response_path: Dot-notation path to extract response content
            headers: Additional HTTP headers
            temperature: Temperature parameter
            max_tokens: Max tokens parameter
        """
        if not endpoint:
            raise ProviderError("Custom provider requires 'endpoint' parameter")

        self.request_format = request_format
        self.response_path = response_path
        self.custom_headers = headers or {}
        self.temperature = temperature
        self.max_tokens = max_tokens
        super().__init__(model=model, endpoint=endpoint, **kwargs)

    def _validate_config(self) -> None:
        """Validate custom provider configuration."""
        # API key is optional for custom endpoints
        pass

    async def _execute_query(self, prompt: str, **kwargs) -> LLMResponse:
        """Execute query to custom endpoint."""
        try:
            import httpx
        except ImportError:
            raise ProviderError(
                "httpx package not installed. Run: pip install httpx"
            )

        temperature = kwargs.get("temperature", self.temperature)
        max_tokens = kwargs.get("max_tokens", self.max_tokens)

        # Build request body based on format
        body = self._build_request_body(prompt, temperature, max_tokens)

        # Build headers
        headers = {"Content-Type": "application/json", **self.custom_headers}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"

        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.post(
                    self.endpoint,
                    json=body,
                    headers=headers,
                )
                response.raise_for_status()
                data = response.json()

                # Extract content using response path
                content = self._extract_response(data, self.response_path)

                return LLMResponse(
                    content=content,
                    tokens_used=0,
                    model=self.model or "custom",
                    raw_response=data,
                )

        except httpx.HTTPStatusError as e:
            if e.response.status_code == 429:
                raise RateLimitError(f"Rate limit exceeded: {e}")
            raise ProviderError(f"HTTP error: {e}")
        except Exception as e:
            raise ProviderError(f"Custom endpoint error: {e}")

    def _build_request_body(
        self, prompt: str, temperature: float, max_tokens: int
    ) -> Dict[str, Any]:
        """Build request body based on format type."""
        if self.request_format == "openai":
            body = {
                "messages": [{"role": "user", "content": prompt}],
                "temperature": temperature,
                "max_tokens": max_tokens,
            }
            if self.model:
                body["model"] = self.model
            return body

        elif self.request_format == "anthropic":
            body = {
                "messages": [{"role": "user", "content": prompt}],
                "max_tokens": max_tokens,
            }
            if self.model:
                body["model"] = self.model
            return body

        elif self.request_format == "simple":
            return {"prompt": prompt}

        else:
            # Default to simple format
            return {
                "prompt": prompt,
                "model": self.model,
                "temperature": temperature,
                "max_tokens": max_tokens,
            }

    def _extract_response(self, data: Any, path: str) -> str:
        """Extract response content using dot-notation path."""
        try:
            parts = path.split(".")
            result = data

            for part in parts:
                if isinstance(result, dict):
                    result = result.get(part, "")
                elif isinstance(result, list):
                    index = int(part)
                    result = result[index] if len(result) > index else ""
                else:
                    return str(result)

            return str(result) if result else ""

        except (KeyError, IndexError, ValueError):
            # Fallback: try common response locations
            for key in ["response", "text", "content", "output", "generation"]:
                if isinstance(data, dict) and key in data:
                    return str(data[key])
            return str(data)

    def get_available_models(self) -> List[str]:
        """Return empty list - models depend on custom endpoint."""
        return []
