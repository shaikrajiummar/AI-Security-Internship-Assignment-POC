"""
Base abstract class for LLM providers.
"""
from abc import ABC, abstractmethod
from typing import Dict, Any, List, Optional

class BaseModelProvider(ABC):
    def __init__(self, model_name: str, api_key: Optional[str] = None):
        self.model_name = model_name
        self.api_key = api_key

    @abstractmethod
    def generate(self, prompt: str, system_prompt: str = "", temperature: float = 0.0) -> str:
        """Generate text response from LLM."""
        pass

    @abstractmethod
    def generate_tool_call(
        self,
        prompt: str,
        system_prompt: str = "",
        available_tools: Optional[List[Dict[str, Any]]] = None,
        temperature: float = 0.0
    ) -> Dict[str, Any]:
        """
        Generate a tool call decision.
        Returns:
            {
                "tool_name": str or None,
                "tool_args": dict,
                "thought": str,
                "raw_response": str
            }
        """
        pass
