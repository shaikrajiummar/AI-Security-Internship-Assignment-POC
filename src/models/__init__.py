"""Model Provider factory and exports."""
from src.models.base import BaseModelProvider
from src.models.gemini_provider import GeminiProvider
from src.models.claude_provider import ClaudeProvider
from src.models.mock_provider import MockProvider

def get_model_provider(model_name: str, api_key: str = None) -> BaseModelProvider:
    name_lower = model_name.lower()
    if "claude" in name_lower or "anthropic" in name_lower:
        return ClaudeProvider(model_name=model_name, api_key=api_key)
    elif "gemini" in name_lower or "google" in name_lower:
        return GeminiProvider(model_name=model_name, api_key=api_key)
    else:
        return MockProvider(model_name=model_name)
