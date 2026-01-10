"""AWS Bedrock provider implementation"""

import json
import logging
from typing import Any, Dict, List, Optional

from .base_provider import BaseProvider, LLMResponse, ProviderError, RateLimitError

logger = logging.getLogger(__name__)


class BedrockProvider(BaseProvider):
    """
    AWS Bedrock provider.

    Supports Claude, Llama, Titan, and other models via AWS Bedrock.
    Uses AWS credentials from environment (AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY)
    or IAM role credentials.
    """

    provider_name = "bedrock"
    requires_api_key = False  # Uses AWS credentials
    env_var_name = "AWS_ACCESS_KEY_ID"

    def __init__(
        self,
        model: Optional[str] = None,
        region: str = "us-east-1",
        temperature: float = 0.7,
        max_tokens: int = 150,
        **kwargs,
    ):
        self.region = region
        self.temperature = temperature
        self.max_tokens = max_tokens
        self._client = None
        super().__init__(model=model, **kwargs)

    def _validate_config(self) -> None:
        """Validate AWS credentials are available."""
        # AWS SDK will handle credential validation
        pass

    def _get_client(self):
        """Lazy initialization of Bedrock client."""
        if self._client is None:
            try:
                import boto3
                self._client = boto3.client(
                    "bedrock-runtime",
                    region_name=self.region,
                )
            except ImportError:
                raise ProviderError(
                    "boto3 package not installed. Run: pip install boto3"
                )
        return self._client

    async def _execute_query(self, prompt: str, **kwargs) -> LLMResponse:
        """Execute query to AWS Bedrock."""
        import asyncio

        client = self._get_client()
        temperature = kwargs.get("temperature", self.temperature)
        max_tokens = kwargs.get("max_tokens", self.max_tokens)

        # Determine request format based on model
        model_id = self.model
        request_body = self._build_request_body(prompt, temperature, max_tokens)

        try:
            # Run sync boto3 call in executor
            loop = asyncio.get_event_loop()
            response = await loop.run_in_executor(
                None,
                lambda: client.invoke_model(
                    modelId=model_id,
                    body=json.dumps(request_body),
                    contentType="application/json",
                    accept="application/json",
                ),
            )

            response_body = json.loads(response["body"].read())
            content, tokens_used = self._parse_response(response_body)

            return LLMResponse(
                content=content,
                tokens_used=tokens_used,
                model=model_id,
                raw_response=response_body,
            )

        except Exception as e:
            error_str = str(e).lower()
            if "throttling" in error_str or "rate" in error_str:
                raise RateLimitError(f"Bedrock rate limit exceeded: {e}")
            raise ProviderError(f"Bedrock API error: {e}")

    def _build_request_body(
        self, prompt: str, temperature: float, max_tokens: int
    ) -> Dict[str, Any]:
        """Build request body based on model type."""
        model_id = self.model.lower()

        if "anthropic" in model_id or "claude" in model_id:
            return {
                "anthropic_version": "bedrock-2023-05-31",
                "max_tokens": max_tokens,
                "messages": [{"role": "user", "content": prompt}],
            }
        elif "meta" in model_id or "llama" in model_id:
            return {
                "prompt": prompt,
                "max_gen_len": max_tokens,
                "temperature": temperature,
            }
        elif "amazon" in model_id or "titan" in model_id:
            return {
                "inputText": prompt,
                "textGenerationConfig": {
                    "maxTokenCount": max_tokens,
                    "temperature": temperature,
                },
            }
        elif "mistral" in model_id:
            return {
                "prompt": f"<s>[INST] {prompt} [/INST]",
                "max_tokens": max_tokens,
                "temperature": temperature,
            }
        else:
            # Default format
            return {
                "prompt": prompt,
                "max_tokens": max_tokens,
                "temperature": temperature,
            }

    def _parse_response(self, response_body: Dict[str, Any]) -> tuple:
        """Parse response based on model type."""
        model_id = self.model.lower()

        if "anthropic" in model_id or "claude" in model_id:
            content = response_body.get("content", [{}])[0].get("text", "")
            usage = response_body.get("usage", {})
            tokens = usage.get("input_tokens", 0) + usage.get("output_tokens", 0)
            return content, tokens
        elif "meta" in model_id or "llama" in model_id:
            content = response_body.get("generation", "")
            tokens = response_body.get("generation_token_count", 0)
            return content, tokens
        elif "amazon" in model_id or "titan" in model_id:
            results = response_body.get("results", [{}])
            content = results[0].get("outputText", "") if results else ""
            tokens = response_body.get("inputTextTokenCount", 0)
            return content, tokens
        elif "mistral" in model_id:
            outputs = response_body.get("outputs", [{}])
            content = outputs[0].get("text", "") if outputs else ""
            return content, 0
        else:
            content = response_body.get("completion", response_body.get("generation", ""))
            return content, 0

    def get_available_models(self) -> List[str]:
        """Return list of available Bedrock models."""
        return [
            "anthropic.claude-3-5-sonnet-20241022-v2:0",
            "anthropic.claude-3-5-haiku-20241022-v1:0",
            "anthropic.claude-3-opus-20240229-v1:0",
            "anthropic.claude-3-sonnet-20240229-v1:0",
            "meta.llama3-70b-instruct-v1:0",
            "meta.llama3-8b-instruct-v1:0",
            "mistral.mixtral-8x7b-instruct-v0:1",
            "amazon.titan-text-express-v1",
        ]
