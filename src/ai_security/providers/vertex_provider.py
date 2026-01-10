"""Google Vertex AI provider implementation"""

import logging
import os
from typing import List, Optional

from .base_provider import BaseProvider, LLMResponse, ProviderError, RateLimitError

logger = logging.getLogger(__name__)


class VertexProvider(BaseProvider):
    """
    Google Vertex AI provider.

    Supports Gemini, PaLM, and other Google AI models.
    Uses GOOGLE_APPLICATION_CREDENTIALS environment variable for authentication.
    """

    provider_name = "vertex"
    requires_api_key = False  # Uses service account credentials
    env_var_name = "GOOGLE_APPLICATION_CREDENTIALS"

    def __init__(
        self,
        model: Optional[str] = None,
        project_id: Optional[str] = None,
        location: str = "us-central1",
        temperature: float = 0.7,
        max_tokens: int = 150,
        **kwargs,
    ):
        self.project_id = project_id or os.environ.get("GOOGLE_CLOUD_PROJECT")
        self.location = location
        self.temperature = temperature
        self.max_tokens = max_tokens
        self._model_client = None
        super().__init__(model=model, **kwargs)

    def _validate_config(self) -> None:
        """Validate Google Cloud credentials."""
        if not self.project_id:
            raise ProviderError(
                "Google Cloud project ID not found. Set GOOGLE_CLOUD_PROJECT "
                "environment variable or pass project_id parameter."
            )

    def _get_client(self):
        """Lazy initialization of Vertex AI client."""
        if self._model_client is None:
            try:
                import vertexai
                from vertexai.generative_models import GenerativeModel

                vertexai.init(project=self.project_id, location=self.location)
                self._model_client = GenerativeModel(self.model)
            except ImportError:
                raise ProviderError(
                    "google-cloud-aiplatform package not installed. "
                    "Run: pip install google-cloud-aiplatform"
                )
        return self._model_client

    async def _execute_query(self, prompt: str, **kwargs) -> LLMResponse:
        """Execute query to Vertex AI."""
        import asyncio

        model = self._get_client()
        temperature = kwargs.get("temperature", self.temperature)
        max_tokens = kwargs.get("max_tokens", self.max_tokens)

        try:
            # Vertex AI SDK is sync, run in executor
            loop = asyncio.get_event_loop()

            def sync_generate():
                from vertexai.generative_models import GenerationConfig

                config = GenerationConfig(
                    temperature=temperature,
                    max_output_tokens=max_tokens,
                )
                response = model.generate_content(prompt, generation_config=config)
                return response

            response = await loop.run_in_executor(None, sync_generate)

            content = response.text if hasattr(response, "text") else ""
            # Token usage not always available
            tokens_used = 0
            if hasattr(response, "usage_metadata"):
                tokens_used = (
                    response.usage_metadata.prompt_token_count
                    + response.usage_metadata.candidates_token_count
                )

            return LLMResponse(
                content=content,
                tokens_used=tokens_used,
                model=self.model,
                raw_response={"text": content},
            )

        except Exception as e:
            error_str = str(e).lower()
            if "quota" in error_str or "rate" in error_str:
                raise RateLimitError(f"Vertex AI rate limit exceeded: {e}")
            raise ProviderError(f"Vertex AI error: {e}")

    def get_available_models(self) -> List[str]:
        """Return list of available Vertex AI models."""
        return [
            "gemini-1.5-pro",
            "gemini-1.5-flash",
            "gemini-1.0-pro",
            "text-bison@002",
            "chat-bison@002",
        ]
