"""Ollama provider implementation for local LLM inference"""

import logging
from typing import List, Optional

from .base_provider import BaseProvider, LLMResponse, ProviderError

logger = logging.getLogger(__name__)


class OllamaProvider(BaseProvider):
    """
    Ollama provider for local LLM inference.

    Supports Llama, Mistral, CodeLlama, and other models running locally.
    No API key required - connects to local Ollama server.
    """

    provider_name = "ollama"
    requires_api_key = False
    env_var_name = ""  # No API key needed

    DEFAULT_ENDPOINT = "http://localhost:11434"

    def __init__(
        self,
        model: Optional[str] = None,
        endpoint: Optional[str] = None,
        temperature: float = 0.7,
        **kwargs,
    ):
        self.temperature = temperature
        self._endpoint = endpoint or self.DEFAULT_ENDPOINT
        super().__init__(model=model, endpoint=endpoint, **kwargs)

    def _validate_config(self) -> None:
        """Override - no API key validation needed."""
        pass

    async def _execute_query(self, prompt: str, **kwargs) -> LLMResponse:
        """Execute query to Ollama API."""
        try:
            import httpx
        except ImportError:
            raise ProviderError(
                "httpx package not installed. Run: pip install httpx"
            )

        temperature = kwargs.get("temperature", self.temperature)
        url = f"{self._endpoint}/api/generate"

        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.post(
                    url,
                    json={
                        "model": self.model,
                        "prompt": prompt,
                        "stream": False,
                        "options": {"temperature": temperature},
                    },
                )
                response.raise_for_status()
                data = response.json()

                content = data.get("response", "")
                # Ollama doesn't always return token counts
                tokens_used = data.get("eval_count", 0) + data.get("prompt_eval_count", 0)

                return LLMResponse(
                    content=content,
                    tokens_used=tokens_used,
                    model=self.model,
                    raw_response=data,
                )

        except httpx.ConnectError:
            raise ProviderError(
                f"Cannot connect to Ollama at {self._endpoint}. "
                "Make sure Ollama is running: ollama serve"
            )
        except Exception as e:
            raise ProviderError(f"Ollama API error: {e}")

    def get_available_models(self) -> List[str]:
        """Return list of common Ollama models."""
        return [
            "llama2",
            "llama3",
            "mistral",
            "mixtral",
            "codellama",
            "phi",
            "neural-chat",
            "starling-lm",
        ]

    async def list_local_models(self) -> List[str]:
        """List models actually installed locally."""
        try:
            import httpx

            async with httpx.AsyncClient(timeout=10) as client:
                response = await client.get(f"{self._endpoint}/api/tags")
                response.raise_for_status()
                data = response.json()
                return [m["name"] for m in data.get("models", [])]
        except Exception as e:
            logger.warning(f"Could not list Ollama models: {e}")
            return self.get_available_models()
