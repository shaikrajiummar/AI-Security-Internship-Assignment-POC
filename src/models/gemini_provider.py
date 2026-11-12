"""
Google Gemini Model Provider implementation.
"""
import os
import json
from typing import Dict, Any, List, Optional
from src.models.base import BaseModelProvider
from src.models.mock_provider import MockProvider

class GeminiProvider(BaseModelProvider):
    def __init__(self, model_name: str = "gemini-1.5-flash", api_key: Optional[str] = None):
        super().__init__(model_name=model_name, api_key=api_key or os.getenv("GEMINI_API_KEY") or os.getenv("GOOGLE_API_KEY"))
        self._client = None
        self._fallback_mock = MockProvider(model_name=f"mock-{model_name}", flavor="gemini")
        
        if self.api_key:
            try:
                import google.generativeai as genai
                genai.configure(api_key=self.api_key)
                self._client = genai.GenerativeModel(self.model_name)
            except Exception as e:
                print(f"[GeminiProvider] Warning: Failed to initialize Google GenAI SDK ({e}). Using mock simulation.")
                self._client = None

    def generate(self, prompt: str, system_prompt: str = "", temperature: float = 0.0) -> str:
        if self._client:
            try:
                full_prompt = f"{system_prompt}\n\nUser: {prompt}" if system_prompt else prompt
                response = self._client.generate_content(
                    full_prompt,
                    generation_config={"temperature": temperature}
                )
                return response.text if response.text else ""
            except Exception as e:
                print(f"[GeminiProvider] Live API call failed ({e}). Falling back to mock simulation.")
                return self._fallback_mock.generate(prompt, system_prompt, temperature)
        return self._fallback_mock.generate(prompt, system_prompt, temperature)

    def generate_tool_call(
        self,
        prompt: str,
        system_prompt: str = "",
        available_tools: Optional[List[Dict[str, Any]]] = None,
        temperature: float = 0.0
    ) -> Dict[str, Any]:
        if self._client:
            try:
                # Structured JSON prompt for tool calling
                tools_desc = json.dumps(available_tools or [], indent=2)
                sys_msg = (
                    f"{system_prompt}\n"
                    f"You have access to these tools:\n{tools_desc}\n"
                    "Respond ONLY with a JSON object containing: "
                    '{"thought": "...", "tool_name": "name_or_null", "tool_args": {...}}'
                )
                response = self._client.generate_content(
                    f"{sys_msg}\n\nUser: {prompt}",
                    generation_config={"temperature": temperature}
                )
                text = response.text.strip()
                # Extract JSON block
                if "{" in text and "}" in text:
                    json_str = text[text.find("{"):text.rfind("}") + 1]
                    data = json.loads(json_str)
                    return {
                        "tool_name": data.get("tool_name"),
                        "tool_args": data.get("tool_args", {}),
                        "thought": data.get("thought", ""),
                        "raw_response": text
                    }
            except Exception as e:
                print(f"[GeminiProvider] Live API tool call failed ({e}). Falling back to mock simulation.")
                return self._fallback_mock.generate_tool_call(prompt, system_prompt, available_tools, temperature)

        return self._fallback_mock.generate_tool_call(prompt, system_prompt, available_tools, temperature)
